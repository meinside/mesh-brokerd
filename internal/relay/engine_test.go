package relay

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
)

type fakePublisher struct {
	published []publishedMsg
	failNext  bool
}

type publishedMsg struct {
	targetID, topic string
	payload         []byte
}

func (f *fakePublisher) Publish(targetID, topic string, payload []byte) error {
	if f.failNext {
		f.failNext = false
		return errFakePublish
	}
	f.published = append(f.published, publishedMsg{targetID, topic, payload})
	return nil
}

var errFakePublish = fakePublishError{}

type fakePublishError struct{}

func (fakePublishError) Error() string { return "fake publish error" }

func testTarget() config.RelayTarget {
	return config.RelayTarget{
		ID:          "meshtastic-public",
		Address:     "mqtt.meshtastic.org:8883",
		TLSEnabled:  true,
		RootTopic:   "msh/KR",
		ChannelName: "LongFast",
		PSK:         decode.DefaultChannelPSK[:],
	}
}

func testRule(overrides func(*config.RelayRule)) config.RelayRule {
	r := config.RelayRule{
		ID:               "coarse-position",
		Enabled:          true,
		SourcePortnum:    "POSITION_APP",
		TargetID:         "meshtastic-public",
		OriginScope:      config.OriginScopeChannelMembers,
		Boards:           []string{"alpha", "bravo"},
		Identity:         "real",
		MinPrecisionBits: 10,
		MaxPrecisionBits: 16,
	}
	if overrides != nil {
		overrides(&r)
	}
	return r
}

func testResult(overrides func(*decode.Result)) *decode.Result {
	res := &decode.Result{
		Topic:          "msh/pvt/2/e/pvt/!11223344",
		ChannelSegment: "pvt",
		GatewayID:      "!11223344",
		PacketID:       12345,
		FromNode:       0x11223344,
		ToNode:         0xffffffff,
		Status:         decode.StatusDecoded,
		Portnum:        decode.PortNumPosition,
		Position: &decode.Position{
			HasLatLon:        true,
			LatitudeI:        407128000,
			LongitudeI:       -740060000,
			HasPrecisionBits: true,
			PrecisionBits:    16,
		},
	}
	// A real decoded Result always carries RawPayload alongside the parsed
	// struct -- internal/decode fills it for every portnum. The fixture kept
	// only the parsed Position, which stopped representing reality once the
	// relay began republishing the source bytes verbatim
	// (docs/outbound-relay.md 5), so it is generated here to match.
	res.RawPayload = decode.EncodePosition(*res.Position)
	if overrides != nil {
		overrides(res)
	}
	return res
}

func newTestEngine(cfg config.OutboundRelay, boards []config.Board, pub Publisher) *Engine {
	return New(cfg, boards, pub, nil)
}

func testConfig(rules ...config.RelayRule) config.OutboundRelay {
	return config.OutboundRelay{
		Enabled:        true,
		DryRunAllRules: false,
		Targets:        []config.RelayTarget{testTarget()},
		Rules:          rules,
	}
}

func TestEvaluate_EligiblePublishes(t *testing.T) {
	pub := &fakePublisher{}
	e := newTestEngine(testConfig(testRule(nil)), nil, pub)

	e.Evaluate(testResult(nil), "alpha")

	if len(pub.published) != 1 {
		t.Fatalf("published = %d messages, want 1", len(pub.published))
	}
	if got := e.PublishedTotal()["coarse-position"]; got != 1 {
		t.Errorf("PublishedTotal[coarse-position] = %d, want 1", got)
	}
}

func TestEvaluate_DisabledEngineDoesNothing(t *testing.T) {
	pub := &fakePublisher{}
	cfg := testConfig(testRule(nil))
	cfg.Enabled = false
	e := newTestEngine(cfg, nil, pub)

	e.Evaluate(testResult(nil), "alpha")

	if len(pub.published) != 0 {
		t.Fatalf("published = %d messages, want 0 (engine disabled)", len(pub.published))
	}
}

func TestEvaluate_DisabledRuleDoesNothing(t *testing.T) {
	pub := &fakePublisher{}
	e := newTestEngine(testConfig(testRule(func(r *config.RelayRule) { r.Enabled = false })), nil, pub)

	e.Evaluate(testResult(nil), "alpha")

	if len(pub.published) != 0 {
		t.Fatalf("published = %d messages, want 0 (rule disabled)", len(pub.published))
	}
}

func TestEvaluate_NoFixIsIneligible(t *testing.T) {
	pub := &fakePublisher{}
	e := newTestEngine(testConfig(testRule(nil)), nil, pub)

	e.Evaluate(testResult(func(r *decode.Result) {
		r.Position = &decode.Position{HasPrecisionBits: true, PrecisionBits: 16} // no fix
	}), "alpha")

	if len(pub.published) != 0 {
		t.Fatalf("published = %d messages, want 0 (no-fix broadcast must never be eligible)", len(pub.published))
	}
}

func TestEvaluate_PrecisionOutOfRangeIsIneligible(t *testing.T) {
	pub := &fakePublisher{}
	e := newTestEngine(testConfig(testRule(nil)), nil, pub)

	e.Evaluate(testResult(func(r *decode.Result) {
		r.Position.PrecisionBits = 25 // too precise, outside [10,16]
	}), "alpha")

	if len(pub.published) != 0 {
		t.Fatalf("published = %d messages, want 0 (precision_bits=25 is outside [10,16])", len(pub.published))
	}
}

func TestEvaluate_MissingPrecisionBitsIsIneligible(t *testing.T) {
	pub := &fakePublisher{}
	e := newTestEngine(testConfig(testRule(nil)), nil, pub)

	e.Evaluate(testResult(func(r *decode.Result) {
		r.Position.HasPrecisionBits = false
	}), "alpha")

	if len(pub.published) != 0 {
		t.Fatal("published a message with no precision_bits at all, want 0")
	}
}

func TestEvaluate_ChannelMembersScope_UnlistedBoardStillEligible(t *testing.T) {
	// docs/outbound-relay.md section 2 point 7: channel_members
	// relays any pvt member's position, not just the listed gateway
	// boards' own -- "boards" here filters by which account gatewayed
	// it, and an empty/omitted list means "all configured boards".
	pub := &fakePublisher{}
	rule := testRule(func(r *config.RelayRule) { r.Boards = nil })
	e := newTestEngine(testConfig(rule), nil, pub)

	e.Evaluate(testResult(nil), "some-other-board")

	if len(pub.published) != 1 {
		t.Fatalf("published = %d messages, want 1 (empty Boards list means all boards)", len(pub.published))
	}
}

func TestEvaluate_ChannelMembersScope_ExplicitListExcludes(t *testing.T) {
	pub := &fakePublisher{}
	e := newTestEngine(testConfig(testRule(nil)), nil, pub) // Boards: ["alpha", "bravo"]

	e.Evaluate(testResult(nil), "cabin")

	if len(pub.published) != 0 {
		t.Fatalf("published = %d messages, want 0 (\"cabin\" is not in the rule's boards list)", len(pub.published))
	}
}

func TestEvaluate_OwnBoardsOnlyScope_MatchesByNodeID(t *testing.T) {
	pub := &fakePublisher{}
	boards := []config.Board{
		{ID: "alpha", HasNodeID: true, NodeIDDec: 0x11223344},
		{ID: "bravo", HasNodeID: true, NodeIDDec: 0xdeadbeef},
	}
	rule := testRule(func(r *config.RelayRule) { r.OriginScope = config.OriginScopeOwnBoardsOnly })
	e := newTestEngine(testConfig(rule), boards, pub)

	// from_node in testResult is 0x11223344, matching "alpha"'s node_id,
	// even though the gatewaying account here is unrelated.
	e.Evaluate(testResult(nil), "some-gateway-account")

	if len(pub.published) != 1 {
		t.Fatalf("published = %d messages, want 1 (from_node matches office's node_id)", len(pub.published))
	}
}

func TestEvaluate_OwnBoardsOnlyScope_RejectsNonOwnedOrigin(t *testing.T) {
	pub := &fakePublisher{}
	boards := []config.Board{
		{ID: "alpha", HasNodeID: true, NodeIDDec: 0x11111111},
		{ID: "bravo", HasNodeID: true, NodeIDDec: 0x22222222},
	}
	rule := testRule(func(r *config.RelayRule) { r.OriginScope = config.OriginScopeOwnBoardsOnly })
	e := newTestEngine(testConfig(rule), boards, pub)

	// from_node (0x11223344) matches neither listed board's node_id.
	e.Evaluate(testResult(nil), "alpha")

	if len(pub.published) != 0 {
		t.Fatalf("published = %d messages, want 0 (from_node matches no listed board's node_id)", len(pub.published))
	}
}

func TestEvaluate_DryRun_NeverCallsPublisher(t *testing.T) {
	pub := &fakePublisher{}
	cfg := testConfig(testRule(nil))
	cfg.DryRunAllRules = true
	e := newTestEngine(cfg, nil, pub)

	e.Evaluate(testResult(nil), "alpha")

	if len(pub.published) != 0 {
		t.Fatalf("dry_run called the real publisher %d times, want 0", len(pub.published))
	}
	if got := e.DryRunTotal()["coarse-position"]; got != 1 {
		t.Errorf("DryRunTotal[coarse-position] = %d, want 1", got)
	}
	if got := e.PublishedTotal()["coarse-position"]; got != 0 {
		t.Errorf("PublishedTotal[coarse-position] = %d, want 0 under dry_run", got)
	}
}

func TestEvaluate_NilPublisherWithDryRunFalse_CountsFailureNotPanic(t *testing.T) {
	cfg := testConfig(testRule(nil))
	e := newTestEngine(cfg, nil, nil) // no publisher at all

	e.Evaluate(testResult(nil), "alpha") // must not panic

	if got := e.PublishFailuresTotal()["coarse-position"]; got != 1 {
		t.Errorf("PublishFailuresTotal[coarse-position] = %d, want 1", got)
	}
}

func TestEvaluate_PublishFailureIsCounted(t *testing.T) {
	pub := &fakePublisher{failNext: true}
	e := newTestEngine(testConfig(testRule(nil)), nil, pub)

	e.Evaluate(testResult(nil), "alpha")

	if got := e.PublishFailuresTotal()["coarse-position"]; got != 1 {
		t.Errorf("PublishFailuresTotal[coarse-position] = %d, want 1", got)
	}
	if got := e.PublishedTotal()["coarse-position"]; got != 0 {
		t.Errorf("PublishedTotal[coarse-position] = %d, want 0 on failure", got)
	}
}

func TestBuildPacket_TopicAndRoundTrip(t *testing.T) {
	target := testTarget()
	res := testResult(nil)

	topic, payload, err := BuildPacket(target, res)
	if err != nil {
		t.Fatalf("BuildPacket: %v", err)
	}
	wantTopic := "msh/KR/2/e/LongFast/!11223344"
	if topic != wantTopic {
		t.Errorf("topic = %q, want %q", topic, wantTopic)
	}

	// Decrypt/parse it back exactly like a real MQTT subscriber would,
	// to confirm the constructed packet is actually valid and readable
	// with the target's own PSK. decode.Decode's channels map assumes
	// 32-byte PSKs (ADR-11, this project's own channels only), so the
	// target's 16-byte AES-128 default key is verified through the
	// lower-level Parse*/CryptCTR calls directly instead.
	env, err := decode.ParseServiceEnvelope(payload)
	if err != nil {
		t.Fatalf("ParseServiceEnvelope: %v", err)
	}
	if env.ChannelID != "LongFast" || env.GatewayID != "!11223344" {
		t.Errorf("envelope = %+v, want channel=LongFast gateway=!11223344", env)
	}

	mp, err := decode.ParseMeshPacket(env.PacketBytes)
	if err != nil {
		t.Fatalf("ParseMeshPacket: %v", err)
	}

	// The channel hash must be present and match the target's own
	// name+PSK -- a consumer that filters on the hash instead of the topic
	// string would otherwise reject the relayed packet
	// (docs/outbound-relay.md section 5).
	wantHash := decode.ChannelHash(target.ChannelName, target.PSK)
	if mp.Channel != uint32(wantHash) {
		t.Errorf("MeshPacket.channel = %d, want %d (ChannelHash of target name+PSK)", mp.Channel, wantHash)
	}
	if mp.Channel == 0 {
		t.Error("MeshPacket.channel is 0 -- the hash was not set at all")
	}

	nonce := decode.DeriveNonce(mp.ID, mp.From)
	plain, err := decode.CryptCTR(target.PSK, nonce, mp.Encrypted)
	if err != nil {
		t.Fatalf("CryptCTR: %v", err)
	}
	data, err := decode.ParseData(plain)
	if err != nil {
		t.Fatalf("ParseData: %v", err)
	}
	if decode.PortNum(data.Portnum) != decode.PortNumPosition {
		t.Fatalf("Portnum = %d, want %d", data.Portnum, decode.PortNumPosition)
	}
}

// A position whose underlying coordinates were zero must never be relayed.
//
// Observed on a real board: after a mis-applied --setlat/--setlon the board
// kept broadcasting POSITION_APP with latitude_i = longitude_i = 0. Meshtastic
// truncation masks the low (32-precision) bits and then adds half a cell, so a
// zero coordinate does not arrive as zero — at 13 bits it arrives as
// 0x00040000 (0.0262°) on both axes. HasLatLon is therefore true and the
// precision check passes, so this sailed straight through eligibility and
// dry_run reported it as publishable.
//
// Publishing it would put a "Null Island" node in the Gulf of Guinea onto
// public maps, which is exactly the kind of pollution of shared community
// infrastructure this filter exists to avoid.
//
// The signature is exact, not a heuristic: a zero coordinate at precision p
// becomes precisely 1<<(31-p) on both axes.
func TestEligible_RejectsTruncatedZeroPosition(t *testing.T) {
	for _, prec := range []uint32{10, 13, 16} {
		half := int32(1) << (31 - prec)
		pub := &fakePublisher{}
		e := newTestEngine(testConfig(testRule(nil)), nil, pub)
		res := testResult(func(r *decode.Result) {
			r.Position.LatitudeI = half
			r.Position.LongitudeI = half
			r.Position.PrecisionBits = prec
		})
		e.Evaluate(res, "alpha")
		if got := len(pub.published); got != 0 {
			t.Errorf("precision %d: relayed a truncated-zero position (%d publishes), want 0", prec, got)
		}
	}
}

// An unmasked zero (precision 32, i.e. no truncation at all) must also go.
func TestEligible_RejectsExactZeroPosition(t *testing.T) {
	pub := &fakePublisher{}
	e := newTestEngine(testConfig(testRule(nil)), nil, pub)
	res := testResult(func(r *decode.Result) {
		r.Position.LatitudeI = 0
		r.Position.LongitudeI = 0
		r.Position.PrecisionBits = 16
	})
	e.Evaluate(res, "alpha")
	if got := len(pub.published); got != 0 {
		t.Errorf("relayed an exactly-zero position (%d publishes), want 0", got)
	}
}

// The guard must not reject a real position that merely sits on a cell
// boundary: only the both-axes zero signature is disqualifying.
func TestEligible_AcceptsRealPositionWithHalfCellOnOneAxis(t *testing.T) {
	const prec = 13
	half := int32(1) << (31 - prec)
	pub := &fakePublisher{}
	e := newTestEngine(testConfig(testRule(nil)), nil, pub)
	res := testResult(func(r *decode.Result) {
		r.Position.LatitudeI = half // as if truly near the equator
		r.Position.LongitudeI = 0x4BBC0000
		r.Position.PrecisionBits = prec
	})
	e.Evaluate(res, "alpha")
	if got := len(pub.published); got != 1 {
		t.Errorf("rejected a real position (%d publishes), want 1", got)
	}
}

// A real publish must leave a log line, not only bump a counter.
//
// This was missing: dry_run logged, publish *failure* logged, but a
// successful publish incremented published_total silently. Since that
// counter is in-memory it is lost on restart, so after publishing to a
// public server — an irreversible disclosure — the system kept no record
// that it had happened at all.
//
// The line deliberately carries the same fields as the dry_run line and no
// more: §8 requires that no per-message content or coordinates are logged.
func TestEvaluate_LogsSuccessfulPublish(t *testing.T) {
	var buf bytes.Buffer
	pub := &fakePublisher{}
	cfg := testConfig(testRule(nil))
	e := New(cfg, nil, pub, slog.New(slog.NewTextHandler(&buf, nil)))

	res := testResult(nil)
	e.Evaluate(res, "alpha")

	if len(pub.published) != 1 {
		t.Fatalf("published %d messages, want 1", len(pub.published))
	}

	out := buf.String()
	if !strings.Contains(out, "outbound_relay published") {
		t.Errorf("successful publish produced no log line; got %q", out)
	}
	for _, want := range []string{"coarse-position", "meshtastic-public", pub.published[0].topic} {
		if !strings.Contains(out, want) {
			t.Errorf("publish log line omits %q; got %q", want, out)
		}
	}
	// docs/outbound-relay.md §8: counts only, never coordinates.
	for _, forbidden := range []string{"407128000", "-740060000", "latitude", "longitude"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("publish log line leaks position data (%q); §8 allows counts only.\nlog: %s", forbidden, out)
		}
	}
}

// The relayed payload must be the source's own bytes, not a re-encoding.
//
// docs/outbound-relay.md §5 has always specified "relayed as-is, never
// re-synthesized", but BuildPacket rebuilt the Position from the parsed
// struct — so every field this decoder does not model was silently dropped.
// A real board's Position carries latitude_i, longitude_i, altitude, time,
// location_source and precision_bits; the re-encoded version carried three
// of them. Losing `time` matters most: a public map decides whether a
// position is current from it (nodes age off after 8 hours), so a position
// with no timestamp is not usable even though it decodes cleanly.
func TestBuildPacket_RelaysSourcePayloadVerbatim(t *testing.T) {
	// A payload with fields this package deliberately does not model, so a
	// re-encode cannot reproduce it.
	sourcePayload := []byte{
		0x0d, 0x00, 0x00, 0x5c, 0x16, // latitude_i  (fixed32)
		0x15, 0x00, 0x00, 0xbc, 0x4b, // longitude_i (fixed32)
		0x18, 0x00, // altitude = 0
		0x25, 0x81, 0x08, 0x85, 0x6a, // time (fixed32)
		0x28, 0x01, // location_source = 1
		0xb8, 0x01, 0x0d, // precision_bits = 13
	}

	res := testResult(func(r *decode.Result) {
		r.RawPayload = sourcePayload
	})

	_, envelope, err := BuildPacket(testTarget(), res)
	if err != nil {
		t.Fatalf("BuildPacket: %v", err)
	}

	// Decrypt the envelope back and confirm the Data payload is byte-identical.
	env, err := decode.ParseServiceEnvelope(envelope)
	if err != nil {
		t.Fatalf("ParseServiceEnvelope: %v", err)
	}
	mp, err := decode.ParseMeshPacket(env.PacketBytes)
	if err != nil {
		t.Fatalf("ParseMeshPacket: %v", err)
	}
	plain, err := decode.DecryptChannelPacket(testTarget().PSK, mp.ID, mp.From, mp.Encrypted)
	if err != nil {
		t.Fatalf("DecryptChannelPacket: %v", err)
	}
	data, err := decode.ParseData(plain)
	if err != nil {
		t.Fatalf("ParseData: %v", err)
	}
	if !bytes.Equal(data.Payload, sourcePayload) {
		t.Errorf("relayed payload was rewritten.\n got %x\nwant %x", data.Payload, sourcePayload)
	}
	if data.Portnum != uint32(decode.PortNumPosition) {
		t.Errorf("portnum = %d, want %d", data.Portnum, decode.PortNumPosition)
	}
}

// A NodeInfo rule must relay NodeInfo, and must not be gated on
// position-shaped eligibility it has no concept of.
func TestEvaluate_NodeInfoRuleRelaysNodeInfo(t *testing.T) {
	pub := &fakePublisher{}
	rule := testRule(func(r *config.RelayRule) { r.SourcePortnum = "NODEINFO_APP" })
	e := newTestEngine(testConfig(rule), nil, pub)

	res := testResult(func(r *decode.Result) {
		r.Portnum = decode.PortNumNodeInfo
		r.Position = nil // NodeInfo carries no position at all
		r.RawPayload = []byte{0x0a, 0x09, '!', 'a', 'b', 'c', 'd', '1', '2', '3', '4'}
	})
	e.Evaluate(res, "alpha")

	if len(pub.published) != 1 {
		t.Fatalf("published %d, want 1", len(pub.published))
	}
}

// Rules are portnum-scoped: a position rule must ignore NodeInfo traffic and
// vice versa, so enabling one does not silently start relaying the other.
func TestEvaluate_RulesDoNotCrossPortnums(t *testing.T) {
	t.Run("position rule ignores nodeinfo", func(t *testing.T) {
		pub := &fakePublisher{}
		e := newTestEngine(testConfig(testRule(nil)), nil, pub)
		res := testResult(func(r *decode.Result) {
			r.Portnum = decode.PortNumNodeInfo
			r.Position = nil
			r.RawPayload = []byte{0x01}
		})
		e.Evaluate(res, "alpha")
		if len(pub.published) != 0 {
			t.Errorf("position rule relayed a NodeInfo packet (%d publishes)", len(pub.published))
		}
	})

	t.Run("nodeinfo rule ignores position", func(t *testing.T) {
		pub := &fakePublisher{}
		rule := testRule(func(r *config.RelayRule) { r.SourcePortnum = "NODEINFO_APP" })
		e := newTestEngine(testConfig(rule), nil, pub)
		e.Evaluate(testResult(nil), "alpha") // a POSITION_APP result
		if len(pub.published) != 0 {
			t.Errorf("nodeinfo rule relayed a position packet (%d publishes)", len(pub.published))
		}
	})
}

// A NodeInfo packet must still respect origin_scope: relaying a *stranger's*
// NodeInfo would republish someone else's name and hardware to a public
// server, which is not ours to disclose.
func TestEvaluate_NodeInfoRespectsOriginScope(t *testing.T) {
	pub := &fakePublisher{}
	rule := testRule(func(r *config.RelayRule) {
		r.SourcePortnum = "NODEINFO_APP"
		r.OriginScope = config.OriginScopeOwnBoardsOnly
		r.Boards = []string{"alpha"}
	})
	boards := []config.Board{{ID: "alpha", Username: "alpha", HasNodeID: true, NodeIDDec: 0x11111111}}
	e := newTestEngine(testConfig(rule), boards, pub)

	res := testResult(func(r *decode.Result) {
		r.Portnum = decode.PortNumNodeInfo
		r.Position = nil
		r.RawPayload = []byte{0x01}
		r.FromNode = 0x99999999 // not one of our boards
	})
	e.Evaluate(res, "alpha")

	if len(pub.published) != 0 {
		t.Errorf("relayed a stranger's NodeInfo (%d publishes), want 0", len(pub.published))
	}
}

// A relayed map report must look like a real one on the wire.
//
// Real map reports differ from ordinary packets in three ways at once, all
// verified against a live board's own publish and the firmware source
// (docs/firmware-config.md §14):
//
//   - topic is <root>/2/map/, not <root>/2/e/<channel>/<node>
//   - the payload is the MeshPacket's *decoded* (plaintext) variant; the
//     firmware never encrypts a map report
//   - the packet carries no id (the firmware allocates it zeroed and never
//     sets one)
//
// Publishing one encrypted on a /2/e/ topic produces a combination that
// exists nowhere in real traffic, and consumers ignored it: meshmap reads
// GetDecoded() directly for /2/map/ topics.
func TestBuildPacket_MapReportUsesMapTopicAndPlaintext(t *testing.T) {
	mapPayload := []byte{0x0a, 0x04, 'n', 'a', 'm', 'e'}
	res := testResult(func(r *decode.Result) {
		r.Portnum = decode.PortNumMapReport
		r.Position = nil
		r.RawPayload = mapPayload
		r.PacketID = 0 // as the firmware leaves it
	})

	target := testTarget()
	topic, envelope, err := BuildPacket(target, res)
	if err != nil {
		t.Fatalf("BuildPacket: %v", err)
	}

	wantTopic := target.RootTopic + "/2/map/"
	if topic != wantTopic {
		t.Errorf("topic = %q, want %q", topic, wantTopic)
	}

	env, err := decode.ParseServiceEnvelope(envelope)
	if err != nil {
		t.Fatalf("ParseServiceEnvelope: %v", err)
	}
	mp, err := decode.ParseMeshPacket(env.PacketBytes)
	if err != nil {
		t.Fatalf("ParseMeshPacket: %v", err)
	}
	if len(mp.Encrypted) != 0 {
		t.Errorf("map report was encrypted (%d bytes); real ones are plaintext", len(mp.Encrypted))
	}
	if len(mp.Decoded) == 0 {
		t.Fatal("map report has no decoded payload")
	}
	data, err := decode.ParseData(mp.Decoded)
	if err != nil {
		t.Fatalf("ParseData: %v", err)
	}
	if data.Portnum != uint32(decode.PortNumMapReport) {
		t.Errorf("portnum = %d, want MAP_REPORT_APP", data.Portnum)
	}
	if !bytes.Equal(data.Payload, mapPayload) {
		t.Errorf("payload was rewritten:\n got %x\nwant %x", data.Payload, mapPayload)
	}
}

// Ordinary payloads must keep the packet topic and stay encrypted.
func TestBuildPacket_PositionKeepsPacketTopicAndEncryption(t *testing.T) {
	target := testTarget()
	topic, envelope, err := BuildPacket(target, testResult(nil))
	if err != nil {
		t.Fatalf("BuildPacket: %v", err)
	}
	if !strings.Contains(topic, "/2/e/") {
		t.Errorf("topic = %q, want the /2/e/ packet grammar", topic)
	}
	env, _ := decode.ParseServiceEnvelope(envelope)
	mp, _ := decode.ParseMeshPacket(env.PacketBytes)
	if len(mp.Encrypted) == 0 {
		t.Error("position was published in plaintext; it must be encrypted with the target's key")
	}
	if len(mp.Decoded) != 0 {
		t.Error("position used the decoded variant; it must use the encrypted one")
	}
}
