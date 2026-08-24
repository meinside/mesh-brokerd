package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func writeSampleConfigWithRelay(t *testing.T, dir string, relay map[string]any) string {
	t.Helper()
	return writeSampleConfig(t, dir, func(m map[string]any) {
		m["outbound_relay"] = relay
	})
}

func validRelayConfig() map[string]any {
	return map[string]any{
		"enabled":           true,
		"dry_run_all_rules": true,
		"targets": []any{
			map[string]any{
				"id":           "meshtastic-public",
				"address":      "mqtt.meshtastic.org:8883",
				"tls_enabled":  true,
				"root_topic":   "msh/KR",
				"channel_name": "LongFast",
				"psk":          "default",
			},
		},
		"rules": []any{
			map[string]any{
				"id":             "coarse-position",
				"enabled":        true,
				"source_portnum": "POSITION_APP",
				"target":         "meshtastic-public",
				"origin_scope":   "channel_members",
				"boards":         []string{"alpha", "bravo"},
				"identity":       "real",
			},
		},
	}
}

func TestLoad_OutboundRelay_Valid(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	path := writeSampleConfigWithRelay(t, dir, validRelayConfig())

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !cfg.OutboundRelay.Enabled || !cfg.OutboundRelay.DryRunAllRules {
		t.Fatalf("OutboundRelay = %+v, want Enabled=true DryRun=true", cfg.OutboundRelay)
	}
	if len(cfg.OutboundRelay.Targets) != 1 || cfg.OutboundRelay.Targets[0].ID != "meshtastic-public" {
		t.Fatalf("Targets = %+v", cfg.OutboundRelay.Targets)
	}
	if len(cfg.OutboundRelay.Targets[0].PSK) != 16 {
		t.Errorf("resolved \"default\" PSK has %d bytes, want 16", len(cfg.OutboundRelay.Targets[0].PSK))
	}
	if len(cfg.OutboundRelay.Rules) != 1 {
		t.Fatalf("Rules = %+v", cfg.OutboundRelay.Rules)
	}
	rule := cfg.OutboundRelay.Rules[0]
	if rule.OriginScope != OriginScopeChannelMembers {
		t.Errorf("OriginScope = %q, want %q", rule.OriginScope, OriginScopeChannelMembers)
	}
	if rule.MinPrecisionBits != defaultMinPrecisionBits || rule.MaxPrecisionBits != defaultMaxPrecisionBits {
		t.Errorf("precision bits = %d/%d, want defaults %d/%d", rule.MinPrecisionBits, rule.MaxPrecisionBits, defaultMinPrecisionBits, defaultMaxPrecisionBits)
	}
}

func TestLoad_OutboundRelay_AbsentIsFine(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	path := writeSampleConfig(t, dir, nil) // no outbound_relay key at all

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OutboundRelay.Enabled {
		t.Error("OutboundRelay.Enabled should default to false when the key is absent")
	}
}

func TestLoad_OutboundRelay_UnsupportedPSK(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	relay := validRelayConfig()
	relay["targets"].([]any)[0].(map[string]any)["psk"] = "c3VwZXItc2VjcmV0"
	path := writeSampleConfigWithRelay(t, dir, relay)

	if _, err := Load(path); err == nil {
		t.Fatal("Load: want error for a non-\"default\" target psk, got nil")
	}
}

func TestLoad_OutboundRelay_UnknownTargetReference(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	relay := validRelayConfig()
	relay["rules"].([]any)[0].(map[string]any)["target"] = "does-not-exist"
	path := writeSampleConfigWithRelay(t, dir, relay)

	if _, err := Load(path); err == nil {
		t.Fatal("Load: want error for a rule referencing an unknown target, got nil")
	}
}

func TestLoad_OutboundRelay_UnsupportedPortnum(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	relay := validRelayConfig()
	relay["rules"].([]any)[0].(map[string]any)["source_portnum"] = "TEXT_MESSAGE_APP"
	path := writeSampleConfigWithRelay(t, dir, relay)

	if _, err := Load(path); err == nil {
		t.Fatal("Load: want error for a non-POSITION_APP rule (v1 limitation), got nil")
	}
}

func TestLoad_OutboundRelay_BadOriginScope(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	relay := validRelayConfig()
	relay["rules"].([]any)[0].(map[string]any)["origin_scope"] = "everyone"
	path := writeSampleConfigWithRelay(t, dir, relay)

	if _, err := Load(path); err == nil {
		t.Fatal("Load: want error for an invalid origin_scope, got nil")
	}
}

func TestLoad_OutboundRelay_CustomPrecisionRange(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	relay := validRelayConfig()
	relay["rules"].([]any)[0].(map[string]any)["eligibility"] = map[string]any{
		"min_precision_bits": 12,
		"max_precision_bits": 14,
	}
	path := writeSampleConfigWithRelay(t, dir, relay)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rule := cfg.OutboundRelay.Rules[0]
	if rule.MinPrecisionBits != 12 || rule.MaxPrecisionBits != 14 {
		t.Errorf("precision bits = %d/%d, want 12/14", rule.MinPrecisionBits, rule.MaxPrecisionBits)
	}
}

func TestLoad_OutboundRelay_InvalidPrecisionRange(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	relay := validRelayConfig()
	relay["rules"].([]any)[0].(map[string]any)["eligibility"] = map[string]any{
		"min_precision_bits": 20,
		"max_precision_bits": 10,
	}
	path := writeSampleConfigWithRelay(t, dir, relay)

	if _, err := Load(path); err == nil {
		t.Fatal("Load: want error for min > max precision bits, got nil")
	}
}

// sanity check that our test helper actually produces valid JSON with
// the extra outbound_relay key merged in correctly.
func TestValidRelayConfig_IsValidJSON(t *testing.T) {
	if _, err := json.Marshal(validRelayConfig()); err != nil {
		t.Fatalf("validRelayConfig is not marshalable: %v", err)
	}
}

// A relay target must be able to carry credentials.
//
// The official public MQTT server requires them (the firmware's own stock
// defaults are username "meshdev" / password "large4cats",
// docs/firmware-config.md §11A), so a target without credential support
// cannot publish there at all. This gap went unnoticed because dry_run
// never opens a connection: it can only surface on the first real publish.
func TestLoad_OutboundRelay_TargetCredentials(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	t.Setenv("TEST_RELAY_TARGET_PASSWORD", "large4cats")

	relay := validRelayConfig()
	tgt := relay["targets"].([]any)[0].(map[string]any)
	tgt["username"] = "meshdev"
	tgt["password_env"] = "TEST_RELAY_TARGET_PASSWORD"

	cfg, err := Load(writeSampleConfigWithRelay(t, dir, relay))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.OutboundRelay.Targets[0]
	if got.Username != "meshdev" {
		t.Errorf("Username = %q, want \"meshdev\"", got.Username)
	}
	if got.Password != "large4cats" {
		t.Error("Password was not resolved from password_env")
	}
}

// Credentials stay optional: a target needing none must still load.
func TestLoad_OutboundRelay_TargetCredentialsOptional(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)

	cfg, err := Load(writeSampleConfigWithRelay(t, dir, validRelayConfig()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.OutboundRelay.Targets[0]
	if got.Username != "" || got.Password != "" {
		t.Errorf("credentials = %q/%q, want both empty when unconfigured", got.Username, got.Password)
	}
}

// A named-but-unset password env var must fail loudly, like every other
// secret this project resolves by name (docs/security.md §7). Silently
// connecting without a password would look like a broker-side rejection.
func TestLoad_OutboundRelay_TargetPasswordEnvMissing(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)

	relay := validRelayConfig()
	tgt := relay["targets"].([]any)[0].(map[string]any)
	tgt["username"] = "meshdev"
	tgt["password_env"] = "TEST_RELAY_PASSWORD_DEFINITELY_UNSET"

	if _, err := Load(writeSampleConfigWithRelay(t, dir, relay)); err == nil {
		t.Fatal("Load succeeded with an unset password_env, want an error")
	}
}

// An unsubstituted placeholder in root_topic must not reach a live target.
//
// The region is part of the root topic by convention — the firmware's own
// default root is msh/<REGION> — so config.json.sample ships a placeholder
// rather than this deployment's region. Publishing to a literal
// "msh/<REGION>/2/e/..." would put traffic on a nonsense topic on shared
// public infrastructure, and nothing downstream would complain: the broker
// accepts any topic the ACL allows.
//
// Only checked when the relay is enabled, so the shipped sample (enabled:
// false) still loads — the same coupling internal/config's sample smoke test
// depends on.
func TestLoad_OutboundRelay_RejectsPlaceholderRootTopicWhenEnabled(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)

	relay := validRelayConfig()
	relay["enabled"] = true
	relay["targets"].([]any)[0].(map[string]any)["root_topic"] = "msh/<REGION>"

	_, err := Load(writeSampleConfigWithRelay(t, dir, relay))
	if err == nil {
		t.Fatal("Load succeeded with an unsubstituted placeholder root_topic, want an error")
	}
	if !strings.Contains(err.Error(), "root_topic") {
		t.Errorf("error does not name the offending key: %v", err)
	}
}

// The same config with the relay disabled must still load: that is exactly
// the shape config.json.sample ships in.
func TestLoad_OutboundRelay_AllowsPlaceholderRootTopicWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)

	relay := validRelayConfig()
	relay["enabled"] = false
	relay["targets"].([]any)[0].(map[string]any)["root_topic"] = "msh/<REGION>"

	if _, err := Load(writeSampleConfigWithRelay(t, dir, relay)); err != nil {
		t.Fatalf("Load failed for a disabled relay with a placeholder: %v", err)
	}
}

// NODEINFO_APP is a valid rule portnum alongside POSITION_APP.
//
// Relaying it is what stops other people's nodes interrogating ours:
// firmware sends its own NodeInfo *and* requests NodeInfo whenever it hears
// an unknown node (meshtastic/firmware#5238, two packets per sighting), and
// that request cannot be disabled — the feature request for a setting was
// declined. Publishing our NodeInfo makes the node known, so the cycle
// stops (docs/outbound-relay.md §10.2).
func TestLoad_OutboundRelay_AcceptsNodeInfoPortnum(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)

	relay := validRelayConfig()
	relay["rules"].([]any)[0].(map[string]any)["source_portnum"] = "NODEINFO_APP"

	cfg, err := Load(writeSampleConfigWithRelay(t, dir, relay))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.OutboundRelay.Rules[0].SourcePortnum; got != "NODEINFO_APP" {
		t.Errorf("SourcePortnum = %q, want NODEINFO_APP", got)
	}
}

// Precision eligibility is meaningless for NodeInfo, so a NodeInfo rule must
// not inherit position-shaped requirements.
func TestLoad_OutboundRelay_NodeInfoRuleNeedsNoPrecision(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)

	relay := validRelayConfig()
	rule := relay["rules"].([]any)[0].(map[string]any)
	rule["source_portnum"] = "NODEINFO_APP"
	delete(rule, "eligibility")

	if _, err := Load(writeSampleConfigWithRelay(t, dir, relay)); err != nil {
		t.Fatalf("Load failed for a NodeInfo rule without eligibility: %v", err)
	}
}

// Anything else stays rejected: this is a whitelist, not a passthrough.
//
// MAP_REPORT_APP was moved out of this list deliberately, not to make a test
// pass: meshmap.net's own source requires a node to have a LongName before it
// is shown (Node.IsValid), and MAP_REPORT_APP is the only payload that both
// carries a name and reaches brokerd -- a node's NodeInfo *broadcast* goes out
// on the primary channel, which this project never uplinks
// (docs/outbound-relay.md 10.1). TEXT_MESSAGE_APP stays rejected because
// relaying message content was never the point, TELEMETRY_APP because it is
// not needed for the map.
func TestLoad_OutboundRelay_RejectsOtherPortnums(t *testing.T) {
	for _, pn := range []string{"TEXT_MESSAGE_APP", "TELEMETRY_APP", "NEIGHBORINFO_APP", ""} {
		dir := t.TempDir()
		setTestEnv(t)
		relay := validRelayConfig()
		relay["rules"].([]any)[0].(map[string]any)["source_portnum"] = pn
		if _, err := Load(writeSampleConfigWithRelay(t, dir, relay)); err == nil {
			t.Errorf("source_portnum %q was accepted; the whitelist is POSITION_APP, NODEINFO_APP and MAP_REPORT_APP only", pn)
		}
	}
}

// Omitting the publish-suppression key must NOT publish.
//
// The old `dry_run bool` could not tell "absent" from "false", so a config
// that simply lacked the key published to a real external server — the exact
// opposite of the documented default, guarded only by the convention that
// config.json.sample always spelled it out. A safety switch whose safe
// setting depends on remembering to write it is not a safety switch.
func TestLoad_OutboundRelay_MissingDryRunKeyDefaultsToSuppressed(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)

	relay := validRelayConfig()
	delete(relay, "dry_run_all_rules")

	cfg, err := Load(writeSampleConfigWithRelay(t, dir, relay))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.OutboundRelay.DryRunAllRules {
		t.Error("omitting dry_run_all_rules left publishing ENABLED; absent must mean suppressed")
	}
}

func TestLoad_OutboundRelay_ExplicitFalseEnablesPublishing(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)

	relay := validRelayConfig()
	relay["dry_run_all_rules"] = false

	cfg, err := Load(writeSampleConfigWithRelay(t, dir, relay))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OutboundRelay.DryRunAllRules {
		t.Error("an explicit false did not enable publishing")
	}
}

// The old key must fail loudly rather than being ignored: silently falling
// back to the safe default would leave an operator who wrote "dry_run": false
// wondering why nothing publishes, and the reverse mistake would be worse.
func TestLoad_OutboundRelay_RejectsRenamedDryRunKey(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)

	relay := validRelayConfig()
	delete(relay, "dry_run_all_rules")
	relay["dry_run"] = false

	_, err := Load(writeSampleConfigWithRelay(t, dir, relay))
	if err == nil {
		t.Fatal("Load accepted the old dry_run key, want an error")
	}
	if !strings.Contains(err.Error(), "dry_run_all_rules") {
		t.Errorf("error does not name the replacement key: %v", err)
	}
}
