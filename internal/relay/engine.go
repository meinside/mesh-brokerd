// Package relay implements brokerd's selective outbound relay
// (docs/outbound-relay.md, ADR-12): a narrow, publish-only,
// whitelist/rule-based forwarding of specific, already-coarse data
// (v1: POSITION_APP) to an external MQTT target. Disabled by default
// and defaulting to dry_run even when enabled (docs/outbound-relay.md
// section 7) -- nothing here ever touches a real external broker
// unless an operator has explicitly turned both switches on.
package relay

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
)

// Publisher is the minimal outbound MQTT client interface the Engine
// needs. Kept separate from any concrete client library so eligibility
// and packet-construction logic can be tested without a real network
// connection (docs/outbound-relay.md section 7's "never touch
// mqtt.meshtastic.org in tests" spirit).
type Publisher interface {
	Publish(targetID, topic string, payload []byte) error
}

// Engine evaluates decoded packets against the configured rules and
// relays eligible ones (or logs a dry-run line) via Publisher.
type Engine struct {
	cfg        config.OutboundRelay
	targets    map[string]config.RelayTarget
	boardsByID map[string]config.Board
	publisher  Publisher
	log        *slog.Logger

	mu                 sync.Mutex
	dryRunTotal        map[string]int64
	publishedTotal     map[string]int64
	publishFailedTotal map[string]int64
}

// New builds an Engine. publisher may be nil if cfg.DryRunAllRules is always
// true for every enabled rule -- Engine only calls it on the
// non-dry-run path, and never at construction time.
func New(cfg config.OutboundRelay, boards []config.Board, publisher Publisher, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	targets := make(map[string]config.RelayTarget, len(cfg.Targets))
	for _, t := range cfg.Targets {
		targets[t.ID] = t
	}
	boardsByID := make(map[string]config.Board, len(boards))
	for _, b := range boards {
		boardsByID[b.ID] = b
	}
	return &Engine{
		cfg:                cfg,
		targets:            targets,
		boardsByID:         boardsByID,
		publisher:          publisher,
		log:                log,
		dryRunTotal:        make(map[string]int64),
		publishedTotal:     make(map[string]int64),
		publishFailedTotal: make(map[string]int64),
	}
}

// Evaluate checks a successfully decoded packet against every enabled
// rule and relays (or dry-run logs) it for each one it's eligible for.
// sourceBoardID is the board_id that gatewayed this packet
// (raw_frames.board_id) -- the "channel_members" origin_scope's
// eligibility key (docs/outbound-relay.md section 3).
func (e *Engine) Evaluate(res *decode.Result, sourceBoardID string) {
	// Any successfully decoded payload is a candidate; which portnums are
	// actually relayed is each rule's own decision (see eligible). An earlier
	// version gated this whole function on res.Position != nil, which hid the
	// fact that rules never compared their source_portnum against the
	// packet's -- a NODEINFO_APP rule would have relayed positions.
	if !e.cfg.Enabled || len(res.RawPayload) == 0 {
		return
	}

	for _, rule := range e.cfg.Rules {
		if !rule.Enabled {
			continue
		}
		if !e.eligible(rule, res, sourceBoardID) {
			// Not logged as a near-miss, by design (docs/outbound-relay.md
			// section 4): avoids accumulating a log of every board's
			// precise-position or no-fix moments.
			continue
		}
		e.relay(rule, res)
	}
}

// rulePortnum maps a rule's configured source_portnum to its wire value.
// internal/config has already rejected anything off the whitelist.
func rulePortnum(s string) (decode.PortNum, bool) {
	switch s {
	case "POSITION_APP":
		return decode.PortNumPosition, true
	case "NODEINFO_APP":
		return decode.PortNumNodeInfo, true
	case "MAP_REPORT_APP":
		return decode.PortNumMapReport, true
	default:
		return 0, false
	}
}

// eligible implements docs/outbound-relay.md section 4's three-part
// check, in order: lat/lon presence, precision range, origin scope.
func (e *Engine) eligible(rule config.RelayRule, res *decode.Result, sourceBoardID string) bool {
	// A rule only ever applies to its own portnum. Without this a rule
	// configured for one payload type relays another.
	want, ok := rulePortnum(rule.SourcePortnum)
	if !ok || res.Portnum != want {
		return false
	}

	// Payload-specific gates. POSITION_APP has the precision/no-fix checks;
	// NODEINFO_APP has no precision-like concept to range-check
	// (docs/outbound-relay.md 10.2), so origin scope is its only gate --
	// which is the one that matters, since relaying a stranger's NodeInfo
	// would republish someone else's name and hardware.
	if want == decode.PortNumPosition {
		pos := res.Position
		if pos == nil || !pos.HasLatLon {
			return false
		}
		if !pos.HasPrecisionBits || pos.PrecisionBits < rule.MinPrecisionBits || pos.PrecisionBits > rule.MaxPrecisionBits {
			return false
		}
		if isZeroOrigin(pos) {
			return false
		}
	}

	return e.originMatches(rule, res, sourceBoardID)
}

// isZeroOrigin reports whether a position's underlying coordinates were
// zero — a board broadcasting POSITION_APP with no usable fix, seen for real
// after a mis-applied --setlat/--setlon left latitude_i/longitude_i at 0.
//
// It cannot be detected with a plain "is it zero" test, which is why this
// check exists as its own step. Meshtastic truncation masks off the low
// (32-precision) bits and then adds half a cell, so zero does not survive as
// zero: at 13 bits of precision it arrives as 0x00040000 (0.0262°) on both
// axes. HasLatLon is true and the precision range check passes, so without
// this the packet is relayed and a "Null Island" node appears in the Gulf of
// Guinea on public maps — polluting shared community infrastructure, which is
// what this check exists to prevent.
//
// The signature is exact rather than a proximity heuristic: a zero coordinate
// at precision p is precisely 1<<(31-p) on both axes. A genuine position is
// only rejected if it sits at that exact point on *both* axes, which is open
// ocean.
func isZeroOrigin(pos *decode.Position) bool {
	if pos.LatitudeI == 0 && pos.LongitudeI == 0 {
		return true
	}
	if !pos.HasPrecisionBits || pos.PrecisionBits >= 32 {
		return false
	}
	halfCell := int32(1) << (31 - pos.PrecisionBits)
	return pos.LatitudeI == halfCell && pos.LongitudeI == halfCell
}

func (e *Engine) originMatches(rule config.RelayRule, res *decode.Result, sourceBoardID string) bool {
	switch rule.OriginScope {
	case config.OriginScopeOwnBoardsOnly:
		// Eligible only if the packet's actual origin (from_node)
		// matches one of the listed boards' own configured node_id.
		boards := rule.Boards
		if len(boards) == 0 {
			boards = allBoardIDs(e.boardsByID)
		}
		for _, id := range boards {
			b, ok := e.boardsByID[id]
			if ok && b.HasNodeID && b.NodeIDDec == res.FromNode {
				return true
			}
		}
		return false
	default: // config.OriginScopeChannelMembers, and the config loader's own default
		if len(rule.Boards) == 0 {
			return true // "all configured boards" (docs/brokerd-config.md)
		}
		for _, id := range rule.Boards {
			if id == sourceBoardID {
				return true
			}
		}
		return false
	}
}

func allBoardIDs(boards map[string]config.Board) []string {
	ids := make([]string, 0, len(boards))
	for id := range boards {
		ids = append(ids, id)
	}
	return ids
}

// relay constructs, encrypts, and (unless dry_run) publishes the
// outbound packet for one eligible rule (docs/outbound-relay.md
// sections 5-7).
func (e *Engine) relay(rule config.RelayRule, res *decode.Result) {
	target, ok := e.targets[rule.TargetID]
	if !ok {
		e.log.Error("outbound_relay: rule references an unknown target", "rule", rule.ID, "target", rule.TargetID)
		return
	}

	topic, payload, err := BuildPacket(target, res)
	if err != nil {
		e.log.Error("outbound_relay: building packet failed", "rule", rule.ID, "target", target.ID, "error", err)
		return
	}

	if e.cfg.DryRunAllRules {
		e.log.Info("outbound_relay dry_run",
			"rule", rule.ID, "target", target.ID, "topic", topic, "bytes", len(payload))
		e.incr(&e.dryRunTotal, rule.ID)
		return
	}

	if e.publisher == nil {
		e.log.Error("outbound_relay: dry_run is false but no publisher is configured", "rule", rule.ID)
		e.incr(&e.publishFailedTotal, rule.ID)
		return
	}
	if err := e.publisher.Publish(target.ID, topic, payload); err != nil {
		e.log.Error("outbound_relay: publish failed", "rule", rule.ID, "target", target.ID, "error", err)
		e.incr(&e.publishFailedTotal, rule.ID)
		return
	}
	e.log.Info("outbound_relay published",
		"rule", rule.ID, "target", target.ID, "topic", topic, "bytes", len(payload))
	e.incr(&e.publishedTotal, rule.ID)
}

func (e *Engine) incr(counter *map[string]int64, ruleID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	(*counter)[ruleID]++
}

func snapshot(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// DryRunTotal, PublishedTotal, and PublishFailuresTotal expose the
// counters docs/monitoring-api.md section 4 / docs/outbound-relay.md
// section 8 describe, each keyed by rule ID.
func (e *Engine) DryRunTotal() map[string]int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return snapshot(e.dryRunTotal)
}

func (e *Engine) PublishedTotal() map[string]int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return snapshot(e.publishedTotal)
}

func (e *Engine) PublishFailuresTotal() map[string]int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return snapshot(e.publishFailedTotal)
}

// BuildPacket constructs the outbound topic and encrypted
// ServiceEnvelope payload for one eligible (target, decoded position)
// pair (docs/outbound-relay.md section 5-6). Exported so it can be
// unit-tested (and dry-run-logged) without a Publisher at all.
func BuildPacket(target config.RelayTarget, res *decode.Result) (topic string, payload []byte, err error) {
	// Verbatim, not re-encoded: re-encoding from the parsed struct silently
	// dropped every field this decoder does not model -- a Position's time,
	// altitude and location_source among them. A public map decides whether
	// a position is current from its time field, so dropping it produced a
	// packet that decoded cleanly and was still unusable
	// (docs/outbound-relay.md 5).
	data := decode.EncodeData(res.Portnum, res.RawPayload)

	// MeshPacket.channel carries the channel *hash* (name + PSK), which
	// consumers may filter on instead of the topic string
	// (docs/outbound-relay.md section 5). Computed over the target's own
	// channel name and key, not the source channel's.
	channelHash := decode.ChannelHash(target.ChannelName, target.PSK)

	fields := decode.MeshPacketFields{
		From:        res.FromNode,
		To:          res.ToNode,
		ID:          res.PacketID,
		ChannelHash: channelHash,
		RxTime:      res.RxTime,
		HopLimit:    res.HopLimit,
		HopStart:    res.HopStart,
		Priority:    res.Priority,
		RelayNode:   res.RelayNode,
	}

	// Map reports are their own shape on the wire, and matching it is the
	// whole point: they go to <root>/2/map/ and are published as the
	// MeshPacket's *decoded* (plaintext) variant. The firmware never
	// encrypts one, and consumers read GetDecoded() directly for that topic
	// -- an encrypted map report on a /2/e/ topic is a combination that
	// exists nowhere in real traffic, and was ignored
	// (docs/outbound-relay.md 11, docs/firmware-config.md 14).
	if res.Portnum == decode.PortNumMapReport {
		mp := decode.EncodeMeshPacketDecodedFields(fields, data)
		envelope := decode.EncodeServiceEnvelope(mp, target.ChannelName, res.GatewayID)
		return target.RootTopic + "/2/map/", envelope, nil
	}

	nonce := decode.DeriveNonce(res.PacketID, res.FromNode)
	ciphertext, err := decode.CryptCTR(target.PSK, nonce, data)
	if err != nil {
		return "", nil, fmt.Errorf("relay: encrypting outbound packet: %w", err)
	}

	// The optional envelope fields are copied from the source packet, not
	// synthesized: a packet missing hop_limit/hop_start reads as "no hops
	// left" and one missing rx_time gives consumers no observation time,
	// which is why an earlier reduced-field version was accepted by the
	// broker yet ignored by map front-ends (docs/outbound-relay.md 5).
	fields.Encrypted = ciphertext
	mp := decode.EncodeMeshPacket(fields)
	envelope := decode.EncodeServiceEnvelope(mp, target.ChannelName, res.GatewayID)

	topic = fmt.Sprintf("%s/2/e/%s/%s", target.RootTopic, target.ChannelName, res.GatewayID)
	return topic, envelope, nil
}

// RuleInfo is what is configured, as opposed to what has been published. A rule
// that has relayed nothing yet is not the same as no rule at all.
type RuleInfo struct {
	ID      string
	Enabled bool
	DryRun  bool
}

// ConfiguredRules lists every rule in the configuration, enabled or not.
func (e *Engine) ConfiguredRules() []RuleInfo {
	out := make([]RuleInfo, 0, len(e.cfg.Rules))
	for _, r := range e.cfg.Rules {
		out = append(out, RuleInfo{ID: r.ID, Enabled: r.Enabled, DryRun: e.cfg.DryRunAllRules})
	}
	return out
}
