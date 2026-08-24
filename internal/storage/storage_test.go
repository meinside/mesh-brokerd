package storage

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/meinside/mesh-brokerd/internal/decode"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpen_AppliesSchemaAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, table := range []string{"raw_frames", "text_messages", "decoded_payloads"} {
		var name string
		if err := s.db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?;`, table).Scan(&name); err != nil {
			t.Errorf("table %s missing after Open: %v", table, err)
		}
	}
	// A column added late in the schema's life, to catch a schema.sql that
	// was edited without the table being recreated.
	if _, err := s.db.Exec(`SELECT rx_snr, portnum_name, bitfield FROM raw_frames LIMIT 0;`); err != nil {
		t.Errorf("expected reception/Data columns to exist: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-opening the same file must be a no-op rather than an error: the
	// schema is applied with CREATE ... IF NOT EXISTS on every Open, which
	// is what replaced the migration runner.
	again, err := Open(path)
	if err != nil {
		t.Fatalf("second Open on an existing database: %v", err)
	}
	var frames int
	if err := again.db.QueryRow(`SELECT COUNT(*) FROM raw_frames;`).Scan(&frames); err != nil {
		t.Errorf("querying after reopen: %v", err)
	}
	_ = again.Close()
}

func TestInsertRawFrame_AndTextMessage(t *testing.T) {
	s := openTestStore(t)

	res := &decode.Result{
		Topic:          "msh/pvt/2/e/pvt/!11223344",
		ChannelSegment: "pvt",
		NodeSegment:    "!11223344",
		GatewayID:      "!11223344",
		PacketID:       0x5674c7f4,
		FromNode:       0x11223344,
		ToNode:         0xffffffff,
		Status:         decode.StatusDecoded,
		Portnum:        decode.PortNumTextMessage,
		PacketParsed:   true,
		TextMessage:    &decode.TextMessage{Text: "test a"},
	}

	now := time.Now()
	rawID, err := s.InsertRawFrame(res, "alpha", "alpha", []byte{0x01, 0x02}, now)
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
	if rawID == 0 {
		t.Fatalf("InsertRawFrame returned id 0")
	}

	textID, err := s.InsertTextMessage(rawID, res, "pvt", now)
	if err != nil {
		t.Fatalf("InsertTextMessage: %v", err)
	}
	if textID == 0 {
		t.Fatalf("InsertTextMessage returned id 0")
	}

	var text string
	var gotRawID int64
	if err := s.db.QueryRow(`SELECT raw_frame_id, text FROM text_messages WHERE id = ?;`, textID).Scan(&gotRawID, &text); err != nil {
		t.Fatalf("reading back text_messages: %v", err)
	}
	if gotRawID != rawID || text != "test a" {
		t.Errorf("got (raw_frame_id=%d, text=%q), want (%d, %q)", gotRawID, text, rawID, "test a")
	}

	var status string
	if err := s.db.QueryRow(`SELECT decode_status FROM raw_frames WHERE id = ?;`, rawID).Scan(&status); err != nil {
		t.Fatalf("reading back raw_frames: %v", err)
	}
	if status != string(decode.StatusDecoded) {
		t.Errorf("decode_status = %q, want %q", status, decode.StatusDecoded)
	}
}

func TestInsertRawFrame_NullableFieldsWhenPacketNotParsed(t *testing.T) {
	s := openTestStore(t)

	res := &decode.Result{
		Topic:          "msh/pvt/2/e/pvt/!11223344",
		ChannelSegment: "pvt",
		Status:         decode.StatusDecryptFailed,
		PacketParsed:   false, // envelope never parsed
	}

	rawID, err := s.InsertRawFrame(res, "alpha", "alpha", []byte{0xff}, time.Now())
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}

	var packetID *int64
	if err := s.db.QueryRow(`SELECT packet_id FROM raw_frames WHERE id = ?;`, rawID).Scan(&packetID); err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if packetID != nil {
		t.Errorf("packet_id = %v, want NULL when PacketParsed=false", *packetID)
	}
}

func TestDeleteExpired(t *testing.T) {
	s := openTestStore(t)

	old := &decode.Result{Topic: "t", ChannelSegment: "pvt", Status: decode.StatusDecoded}
	rawID, err := s.InsertRawFrame(old, "alpha", "alpha", []byte{0x00}, time.Now().Add(-48*time.Hour))
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
	recent, err := s.InsertRawFrame(old, "alpha", "alpha", []byte{0x00}, time.Now())
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}

	rawDeleted, _, err := s.DeleteExpired(1, 0) // 1 day retention
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if rawDeleted != 1 {
		t.Errorf("rawDeleted = %d, want 1", rawDeleted)
	}

	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM raw_frames WHERE id = ?;`, rawID).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Errorf("old row (id=%d) still present after retention delete", rawID)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM raw_frames WHERE id = ?;`, recent).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("recent row (id=%d) was unexpectedly deleted", recent)
	}
}

func TestDeleteExpired_ZeroMeansUnlimited(t *testing.T) {
	s := openTestStore(t)

	old := &decode.Result{Topic: "t", ChannelSegment: "pvt", Status: decode.StatusDecoded}
	if _, err := s.InsertRawFrame(old, "alpha", "alpha", []byte{0x00}, time.Now().Add(-365*24*time.Hour)); err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}

	rawDeleted, decodedDeleted, err := s.DeleteExpired(0, 0)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if rawDeleted != 0 || decodedDeleted != 0 {
		t.Errorf("DeleteExpired(0, 0) deleted rows, want none (0 = unlimited)")
	}
}
