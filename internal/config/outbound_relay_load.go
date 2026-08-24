package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/meinside/mesh-brokerd/internal/decode"
)

const (
	defaultMinPrecisionBits = 10 // 23.3km: matches the official public server's own filter
	defaultMaxPrecisionBits = 16 // 364m
)

func loadOutboundRelay(raw rawConfig) (OutboundRelay, error) {
	out := OutboundRelay{
		Enabled: raw.OutboundRelay.Enabled,
	}

	// The pre-rename key is rejected rather than ignored. Silently applying
	// the safe default to a config that says "dry_run": false would leave an
	// operator wondering why nothing publishes; silently doing the reverse
	// would publish without being asked.
	if raw.OutboundRelay.DryRunLegacy != nil {
		return out, fmt.Errorf("config: outbound_relay.dry_run has been renamed to dry_run_all_rules, to make clear it suppresses publishing for every rule rather than one feature (docs/outbound-relay.md section 7)")
	}

	// Absent means suppressed. A plain bool could not distinguish absent from
	// false, so omitting the key used to publish for real -- the opposite of
	// the documented default, guarded only by the convention that the sample
	// spelled it out.
	out.DryRunAllRules = true
	if v := raw.OutboundRelay.DryRunAllRules; v != nil {
		out.DryRunAllRules = *v
	}

	if len(raw.OutboundRelay.Targets) == 0 && len(raw.OutboundRelay.Rules) == 0 {
		return out, nil
	}

	seenTargets := map[string]bool{}
	for _, rt := range raw.OutboundRelay.Targets {
		if rt.ID == "" || rt.Address == "" || rt.RootTopic == "" || rt.ChannelName == "" {
			return out, fmt.Errorf("config: outbound_relay.targets[] entries require id, address, root_topic, and channel_name")
		}
		if seenTargets[rt.ID] {
			return out, fmt.Errorf("config: duplicate outbound_relay.targets[].id %q", rt.ID)
		}
		seenTargets[rt.ID] = true

		// The region is part of the root topic by convention (the firmware's
		// own default root is msh/<REGION>), so the shipped sample carries a
		// placeholder instead of any one deployment's region. Publishing to a
		// literal "msh/<REGION>/..." would put traffic on a nonsense topic on
		// shared public infrastructure and nothing downstream would object,
		// so refuse it — but only once the relay is actually enabled, so the
		// sample itself still loads.
		if raw.OutboundRelay.Enabled && strings.ContainsAny(rt.RootTopic, "<>") {
			return out, fmt.Errorf("config: outbound_relay.targets[%q].root_topic %q still contains a placeholder — substitute the real region (e.g. msh/US), see docs/outbound-relay.md", rt.ID, rt.RootTopic)
		}

		var psk []byte
		switch rt.PSK {
		case "default":
			psk = DefaultChannelPSKBytes()
		case "":
			return out, fmt.Errorf("config: outbound_relay.targets[%q].psk is required (only \"default\" is supported in v1)", rt.ID)
		default:
			return out, fmt.Errorf("config: outbound_relay.targets[%q].psk %q is not supported \u2014 v1 only implements \"default\" (a real secret PSK for a second target is not yet designed, and must never be written directly in config.json regardless, docs/security.md section 7)", rt.ID, rt.PSK)
		}

		password := ""
		if rt.PasswordEnv != "" {
			password = os.Getenv(rt.PasswordEnv)
			if password == "" {
				// Fail loudly rather than connecting anonymously: an
				// unauthenticated connection to a broker that requires
				// credentials is rejected, and the rejection looks like a
				// broker-side problem rather than a missing variable.
				return out, fmt.Errorf("config: outbound_relay.targets[%q].password_env %q is not set in the environment", rt.ID, rt.PasswordEnv)
			}
		}

		out.Targets = append(out.Targets, RelayTarget{
			ID:          rt.ID,
			Address:     rt.Address,
			TLSEnabled:  rt.TLSEnabled,
			RootTopic:   rt.RootTopic,
			ChannelName: rt.ChannelName,
			PSK:         psk,
			Username:    rt.Username,
			Password:    password,
		})
	}

	seenRules := map[string]bool{}
	for _, rr := range raw.OutboundRelay.Rules {
		if rr.ID == "" {
			return out, fmt.Errorf("config: outbound_relay.rules[] entries require id")
		}
		if seenRules[rr.ID] {
			return out, fmt.Errorf("config: duplicate outbound_relay.rules[].id %q", rr.ID)
		}
		seenRules[rr.ID] = true

		// Whitelist, not a passthrough. POSITION_APP is the original rule;
		// NODEINFO_APP was added because publishing it is what stops other
		// nodes interrogating ours -- firmware answers an unknown node with
		// its own NodeInfo *and* a request for the unknown node's, and that
		// behaviour is not configurable (meshtastic/firmware#5238, where a
		// setting for it was declined). See docs/outbound-relay.md 10.2.
		switch rr.SourcePortnum {
		case "POSITION_APP", "NODEINFO_APP", "MAP_REPORT_APP":
		default:
			return out, fmt.Errorf("config: outbound_relay.rules[%q].source_portnum %q is not supported -- only \"POSITION_APP\", \"NODEINFO_APP\" and \"MAP_REPORT_APP\" are implemented (docs/outbound-relay.md section 10)", rr.ID, rr.SourcePortnum)
		}
		if !seenTargets[rr.Target] {
			return out, fmt.Errorf("config: outbound_relay.rules[%q].target %q does not match any outbound_relay.targets[].id", rr.ID, rr.Target)
		}

		originScope := rr.OriginScope
		if originScope == "" {
			originScope = OriginScopeChannelMembers
		}
		if originScope != OriginScopeChannelMembers && originScope != OriginScopeOwnBoardsOnly {
			return out, fmt.Errorf("config: outbound_relay.rules[%q].origin_scope %q must be %q or %q", rr.ID, rr.OriginScope, OriginScopeChannelMembers, OriginScopeOwnBoardsOnly)
		}

		identity := rr.Identity
		if identity == "" {
			identity = "real"
		}
		if identity != "real" {
			return out, fmt.Errorf("config: outbound_relay.rules[%q].identity %q is not supported \u2014 v1 only implements \"real\" (docs/outbound-relay.md)", rr.ID, rr.Identity)
		}

		minBits := uint32(defaultMinPrecisionBits)
		if rr.Eligibility.MinPrecisionBits != nil {
			minBits = *rr.Eligibility.MinPrecisionBits
		}
		maxBits := uint32(defaultMaxPrecisionBits)
		if rr.Eligibility.MaxPrecisionBits != nil {
			maxBits = *rr.Eligibility.MaxPrecisionBits
		}
		if minBits > 32 || maxBits > 32 || minBits > maxBits {
			return out, fmt.Errorf("config: outbound_relay.rules[%q].eligibility min/max_precision_bits (%d/%d) must satisfy 0 <= min <= max <= 32", rr.ID, minBits, maxBits)
		}

		out.Rules = append(out.Rules, RelayRule{
			ID:               rr.ID,
			Enabled:          rr.Enabled,
			SourcePortnum:    rr.SourcePortnum,
			TargetID:         rr.Target,
			OriginScope:      originScope,
			Boards:           rr.Boards,
			Identity:         identity,
			MinPrecisionBits: minBits,
			MaxPrecisionBits: maxBits,
		})
	}

	return out, nil
}

// DefaultChannelPSKBytes exposes decode.DefaultChannelPSK as a plain
// []byte slice for RelayTarget.PSK.
func DefaultChannelPSKBytes() []byte {
	psk := decode.DefaultChannelPSK
	return psk[:]
}
