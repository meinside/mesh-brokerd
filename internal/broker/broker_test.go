package broker

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
	"github.com/meinside/mesh-brokerd/internal/relay"
	"github.com/meinside/mesh-brokerd/internal/storage"
)

func newTestClient(username string) *mqtt.Client {
	cl := &mqtt.Client{}
	cl.Properties.Username = []byte(username)
	return cl
}

func TestRelayAndWorker_FullPipeline(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	relay := NewRelayHook(16)
	worker := NewWorker(relay, store, map[string][decode.PSKSize]byte{}, map[string]string{"alpha": "alpha"}, nil, nil, nil)

	data := decode.EncodeData(decode.PortNumTextMessage, []byte("hello"))
	mp := decode.EncodeMeshPacketDecoded(1, 0xffffffff, 42, data)
	envelope := decode.EncodeServiceEnvelope(mp, "pvt", "!aabbccdd")

	cl := newTestClient("alpha")
	pk := packets.Packet{TopicName: "msh/pvt/2/e/pvt/!aabbccdd", Payload: envelope}

	if _, err := relay.OnPublish(cl, pk); err != nil {
		t.Fatalf("OnPublish: %v", err)
	}
	if relay.DropCount() != 0 {
		t.Fatalf("DropCount = %d, want 0", relay.DropCount())
	}

	msg := <-relay.messages()
	worker.processOne(msg)

	counts := worker.DecodeStatusCounts()
	if counts[string(decode.StatusDecoded)] != 1 {
		t.Fatalf("DecodeStatusCounts() = %+v, want decoded=1", counts)
	}

	var text, boardID string
	row := store.DB().QueryRow(`SELECT tm.text, rf.board_id FROM text_messages tm JOIN raw_frames rf ON rf.id = tm.raw_frame_id;`)
	if err := row.Scan(&text, &boardID); err != nil {
		t.Fatalf("querying stored text message: %v", err)
	}
	if text != "hello" {
		t.Errorf("text = %q, want %q", text, "hello")
	}
	if boardID != "alpha" {
		t.Errorf("board_id = %q, want %q", boardID, "alpha")
	}
}

func TestRelayHook_DropsWhenQueueFull(t *testing.T) {
	relay := NewRelayHook(1)
	cl := newTestClient("alpha")
	pk := packets.Packet{TopicName: "msh/pvt/2/e/pvt/!aabbccdd", Payload: []byte{0x00}}

	if _, err := relay.OnPublish(cl, pk); err != nil {
		t.Fatalf("first OnPublish: %v", err)
	}
	if _, err := relay.OnPublish(cl, pk); err != nil {
		t.Fatalf("second OnPublish: %v", err)
	}

	if got := relay.DropCount(); got != 1 {
		t.Errorf("DropCount() = %d, want 1 (queue depth 1, two sends)", got)
	}
}

func TestWorker_MalformedTopicIsLoggedNotPanicked(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	relay := NewRelayHook(4)
	worker := NewWorker(relay, store, map[string][decode.PSKSize]byte{}, nil, nil, nil, nil)

	// Missing the "2/e" literal segments entirely.
	worker.processOne(queuedMessage{Topic: "not/a/valid/topic", Payload: []byte{0x00}, ReceivedAt: time.Now()})

	var count int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM raw_frames;`).Scan(&count); err != nil {
		t.Fatalf("querying raw_frames: %v", err)
	}
	if count != 0 {
		t.Errorf("raw_frames count = %d, want 0 (malformed topic should not be inserted)", count)
	}
}

type fakeRelayPublisher struct {
	published int
}

func (f *fakeRelayPublisher) Publish(targetID, topic string, payload []byte) error {
	f.published++
	return nil
}

func TestWorker_PositionPacketReachesRelayEngine(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	pub := &fakeRelayPublisher{}
	relayCfg := config.OutboundRelay{
		Enabled:        true,
		DryRunAllRules: false,
		Targets: []config.RelayTarget{{
			ID: "meshtastic-public", Address: "mqtt.meshtastic.org:8883",
			RootTopic: "msh/KR", ChannelName: "LongFast", PSK: decode.DefaultChannelPSK[:],
		}},
		Rules: []config.RelayRule{{
			ID: "coarse-position", Enabled: true, SourcePortnum: "POSITION_APP",
			TargetID: "meshtastic-public", OriginScope: config.OriginScopeChannelMembers,
			Identity: "real", MinPrecisionBits: 10, MaxPrecisionBits: 16,
		}},
	}
	engine := relay.New(relayCfg, nil, pub, nil)

	relayHook := NewRelayHook(4)
	worker := NewWorker(relayHook, store, map[string][decode.PSKSize]byte{}, map[string]string{"alpha": "alpha"}, engine, nil, nil)

	posPayload := decode.EncodePosition(decode.Position{
		HasLatLon: true, LatitudeI: 1, LongitudeI: 2,
		HasPrecisionBits: true, PrecisionBits: 12,
	})
	data := decode.EncodeData(decode.PortNumPosition, posPayload)
	mp := decode.EncodeMeshPacketDecoded(1, 0xffffffff, 42, data)
	envelope := decode.EncodeServiceEnvelope(mp, "pvt", "!aabbccdd")

	worker.processOne(queuedMessage{
		Topic: "msh/pvt/2/e/pvt/!aabbccdd", Payload: envelope,
		Username: "alpha", ReceivedAt: time.Now(),
	})

	if pub.published != 1 {
		t.Fatalf("fakeRelayPublisher.published = %d, want 1", pub.published)
	}
}

// buildTestTextEnvelope builds an encrypted-variant envelope for a text
// message, so worker tests can exercise the real decrypt path (and thus
// the real StatusDecoded path that dedup keys off).
func buildTestTextEnvelope(t *testing.T, psk [decode.PSKSize]byte, from, packetID uint32, text string) []byte {
	t.Helper()
	data := decode.EncodeData(decode.PortNumTextMessage, []byte(text))
	nonce := decode.DeriveNonce(packetID, from)
	ciphertext, err := decode.CryptCTR(psk[:], nonce, data)
	if err != nil {
		t.Fatalf("CryptCTR: %v", err)
	}
	mp := decode.EncodeMeshPacket(decode.MeshPacketFields{From: from, To: 0xffffffff, ID: packetID, ChannelHash: decode.ChannelHash("pvt", psk[:]), Encrypted: ciphertext})
	return decode.EncodeServiceEnvelope(mp, "pvt", "!11223344")
}

func TestWorker_SuppressesDuplicateDelivery(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	var psk [decode.PSKSize]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	channels := map[string][decode.PSKSize]byte{"pvt": psk}

	relayHook := NewRelayHook(8)
	worker := NewWorker(relayHook, store, channels, map[string]string{"alpha": "alpha"}, nil, nil, nil)

	envelope := buildTestTextEnvelope(t, psk, 0x11223344, 1573662254, "hello once")
	msg := queuedMessage{
		Topic: "msh/pvt/2/e/pvt/!11223344", Payload: envelope,
		Username: "alpha", ReceivedAt: time.Now(),
	}

	// Same packet delivered three times, exactly as real firmware did
	// during the first board integration test.
	worker.processOne(msg)
	worker.processOne(msg)
	worker.processOne(msg)

	var rawCount int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM raw_frames;`).Scan(&rawCount); err != nil {
		t.Fatalf("counting raw_frames: %v", err)
	}
	if rawCount != 3 {
		t.Errorf("raw_frames count = %d, want 3 (raw-frame-first: every delivery is still recorded)", rawCount)
	}

	var textCount int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM text_messages;`).Scan(&textCount); err != nil {
		t.Fatalf("counting text_messages: %v", err)
	}
	if textCount != 1 {
		t.Errorf("text_messages count = %d, want 1 (duplicates must not produce extra decoded rows)", textCount)
	}

	counts := worker.DecodeStatusCounts()
	if counts[string(decode.StatusDecoded)] != 1 {
		t.Errorf("decoded count = %d, want 1", counts[string(decode.StatusDecoded)])
	}
	if counts[string(decode.StatusDuplicate)] != 2 {
		t.Errorf("duplicate count = %d, want 2", counts[string(decode.StatusDuplicate)])
	}
}

func TestWorker_DistinctPacketsAreNotSuppressed(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	var psk [decode.PSKSize]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	channels := map[string][decode.PSKSize]byte{"pvt": psk}

	relayHook := NewRelayHook(8)
	worker := NewWorker(relayHook, store, channels, map[string]string{"alpha": "alpha"}, nil, nil, nil)

	now := time.Now()
	for i, packetID := range []uint32{1000, 1001, 1002} {
		envelope := buildTestTextEnvelope(t, psk, 0x11223344, packetID, "message")
		worker.processOne(queuedMessage{
			Topic: "msh/pvt/2/e/pvt/!11223344", Payload: envelope,
			Username: "alpha", ReceivedAt: now.Add(time.Duration(i) * time.Second),
		})
	}

	var textCount int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM text_messages;`).Scan(&textCount); err != nil {
		t.Fatalf("counting text_messages: %v", err)
	}
	if textCount != 3 {
		t.Errorf("text_messages count = %d, want 3 (distinct packet ids are not duplicates)", textCount)
	}
}

func TestWorker_DuplicatePositionIsNotRelayedTwice(t *testing.T) {
	// The outbound relay must not publish the same position repeatedly
	// just because firmware re-delivered it -- that would waste shared
	// public-broker capacity (docs/outbound-relay.md section 7's spirit).
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	var psk [decode.PSKSize]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	channels := map[string][decode.PSKSize]byte{"pvt": psk}

	pub := &fakeRelayPublisher{}
	relayCfg := config.OutboundRelay{
		Enabled:        true,
		DryRunAllRules: false,
		Targets: []config.RelayTarget{{
			ID: "meshtastic-public", Address: "example:8883",
			RootTopic: "msh/KR", ChannelName: "LongFast", PSK: decode.DefaultChannelPSK[:],
		}},
		Rules: []config.RelayRule{{
			ID: "coarse-position", Enabled: true, SourcePortnum: "POSITION_APP",
			TargetID: "meshtastic-public", OriginScope: config.OriginScopeChannelMembers,
			Identity: "real", MinPrecisionBits: 10, MaxPrecisionBits: 16,
		}},
	}
	engine := relay.New(relayCfg, nil, pub, nil)

	relayHook := NewRelayHook(8)
	worker := NewWorker(relayHook, store, channels, map[string]string{"alpha": "alpha"}, engine, nil, nil)

	posPayload := decode.EncodePosition(decode.Position{
		HasLatLon: true, LatitudeI: 407128000, LongitudeI: -740060000,
		HasPrecisionBits: true, PrecisionBits: 13,
	})
	data := decode.EncodeData(decode.PortNumPosition, posPayload)
	nonce := decode.DeriveNonce(4242, 0x11223344)
	ciphertext, err := decode.CryptCTR(psk[:], nonce, data)
	if err != nil {
		t.Fatalf("CryptCTR: %v", err)
	}
	mp := decode.EncodeMeshPacket(decode.MeshPacketFields{From: 0x11223344, To: 0xffffffff, ID: 4242, ChannelHash: decode.ChannelHash("pvt", psk[:]), Encrypted: ciphertext})
	envelope := decode.EncodeServiceEnvelope(mp, "pvt", "!11223344")

	msg := queuedMessage{
		Topic: "msh/pvt/2/e/pvt/!11223344", Payload: envelope,
		Username: "alpha", ReceivedAt: time.Now(),
	}
	worker.processOne(msg)
	worker.processOne(msg)
	worker.processOne(msg)

	if pub.published != 1 {
		t.Errorf("relay published %d times, want 1 (duplicates must not be relayed again)", pub.published)
	}
}

// The relay engine must see every decoded payload, not just positions.
//
// The worker called Evaluate only under `case res.Position != nil`, so a
// NODEINFO_APP or MAP_REPORT_APP rule could never fire however it was
// configured -- the packet never reached the engine. The same position-only
// assumption existed in the engine and in internal/config's portnum
// whitelist; this was the third layer of it.
//
// Which portnums are relayed is the engine's decision (it matches each
// rule's source_portnum), so the worker must not pre-filter.
func TestWorker_RelayEngineSeesNonPositionPayloads(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	var psk [decode.PSKSize]byte
	for i := range psk {
		psk[i] = 0x01
	}

	pub := &recordingPublisher{}
	engine := relay.New(config.OutboundRelay{
		Enabled: true,
		Targets: []config.RelayTarget{{
			ID: "t", Address: "example.org:1883", RootTopic: "msh/XX",
			ChannelName: "LongFast", PSK: psk[:],
		}},
		Rules: []config.RelayRule{{
			ID: "own-nodeinfo", Enabled: true,
			SourcePortnum: "NODEINFO_APP", TargetID: "t",
			OriginScope: config.OriginScopeChannelMembers,
		}},
	}, nil, pub, nil)

	worker := NewWorker(NewRelayHook(16), store, map[string][decode.PSKSize]byte{"pvt": psk},
		map[string]string{"alpha": "alpha"}, engine, nil, nil)

	payload := decode.EncodeData(decode.PortNumNodeInfo, []byte{0x0a, 0x02, 'h', 'i'})
	nonce := decode.DeriveNonce(4242, 0x11223344)
	ciphertext, err := decode.CryptCTR(psk[:], nonce, payload)
	if err != nil {
		t.Fatalf("CryptCTR: %v", err)
	}
	mp := decode.EncodeMeshPacket(decode.MeshPacketFields{
		From: 0x11223344, To: 0xffffffff, ID: 4242,
		ChannelHash: decode.ChannelHash("pvt", psk[:]), Encrypted: ciphertext,
	})
	envelope := decode.EncodeServiceEnvelope(mp, "pvt", "!11223344")

	worker.processOne(queuedMessage{
		Topic: "msh/pvt/2/e/pvt/!11223344", Payload: envelope,
		Username: "alpha", ReceivedAt: time.Now(),
	})

	if len(pub.published) == 0 {
		t.Error("a NodeInfo packet never reached the relay engine; the worker still pre-filters on position")
	}
}

type recordingPublisher struct{ published []string }

func (r *recordingPublisher) Publish(targetID, topic string, payload []byte) error {
	r.published = append(r.published, topic)
	return nil
}

// TestWorker_WritesDecodedPayloadRow proves the real worker path -- not
// just storage's own test -- reaches decoded_payloads. Before this table
// existed, a position frame left decode_status = 'decoded' and nothing
// else, so nothing downstream could tell it apart from a nodeinfo frame.
func TestWorker_WritesDecodedPayloadRow(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	worker := NewWorker(NewRelayHook(4), store, map[string][decode.PSKSize]byte{},
		map[string]string{"alpha": "alpha"}, nil, nil, nil)

	posPayload := decode.EncodePosition(decode.Position{
		HasLatLon: true, LatitudeI: 375128064, LongitudeI: 1270611968,
		HasPrecisionBits: true, PrecisionBits: 23,
	})
	envelope := decode.EncodeServiceEnvelope(
		decode.EncodeMeshPacketDecoded(0x11223344, 0xffffffff, 4242,
			decode.EncodeData(decode.PortNumPosition, posPayload)),
		"pvt", "!11223344")

	worker.processOne(queuedMessage{
		Topic: "msh/pvt/2/e/pvt/!11223344", Payload: envelope,
		Username: "alpha", ReceivedAt: time.Now(),
	})

	var name, fields string
	if err := store.DB().QueryRow(
		`SELECT portnum_name, fields FROM decoded_payloads;`).Scan(&name, &fields); err != nil {
		t.Fatalf("querying decoded_payloads after processOne: %v", err)
	}
	if name != "POSITION_APP" {
		t.Errorf("portnum_name = %q, want POSITION_APP", name)
	}
	if !strings.Contains(fields, "precision_bits") {
		t.Errorf("stored fields = %q, want the position's precision_bits", fields)
	}

	// The reception columns on raw_frames must be populated from the same
	// pass: hop_limit is stated by every packet, rx_snr by none of our own.
	var hopLimit, portnum int
	if err := store.DB().QueryRow(
		`SELECT hop_limit, portnum FROM raw_frames;`).Scan(&hopLimit, &portnum); err != nil {
		t.Fatalf("querying raw_frames: %v", err)
	}
	if portnum != int(decode.PortNumPosition) {
		t.Errorf("raw_frames.portnum = %d, want %d", portnum, decode.PortNumPosition)
	}
}
