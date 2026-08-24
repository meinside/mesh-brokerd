package storage

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/meinside/mesh-brokerd/internal/decode"
)

// insertLegacyFrame writes a raw_frames row the way a build before ADR-15
// did: the frame's bytes and its status, with every later column left NULL.
// This is what the live database's existing rows look like, and reproducing
// it is the only way to test the backfill honestly.
// packetID matters: the live database has always had that column, and
// reprocessing compares a freshly decoded packet id against it.
func insertLegacyFrame(t *testing.T, s *Store, topic string, payload []byte, status string, receivedAt time.Time, packetID uint32) int64 {
	t.Helper()
	res, err := s.db.Exec(
		`INSERT INTO raw_frames
			(received_at, topic, mqtt_username, board_id, channel_segment,
			 node_segment, gateway_id, packet_id, from_node, to_node,
			 payload, decode_status, decode_version)
		 VALUES (?, ?, 'alpha', 'alpha', 'pvt', '!11223344', '!11223344', ?, 1, 2, ?, ?, 1);`,
		receivedAt.UTC().Format(time.RFC3339), topic, int64(packetID), payload, status)
	if err != nil {
		t.Fatalf("inserting legacy frame: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}
	return id
}

func testChannel(t *testing.T) (map[string][decode.PSKSize]byte, [decode.PSKSize]byte) {
	t.Helper()
	var psk [decode.PSKSize]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	return map[string][decode.PSKSize]byte{"pvt": psk}, psk
}

func encryptedTextEnvelope(t *testing.T, psk [decode.PSKSize]byte, from, packetID uint32, text string) []byte {
	t.Helper()
	data := decode.EncodeData(decode.PortNumTextMessage, []byte(text))
	ciphertext, err := decode.CryptCTR(psk[:], decode.DeriveNonce(packetID, from), data)
	if err != nil {
		t.Fatalf("CryptCTR: %v", err)
	}
	return decode.EncodeServiceEnvelope(decode.EncodeMeshPacket(decode.MeshPacketFields{
		From: from, To: 0xffffffff, ID: packetID,
		ChannelHash: decode.ChannelHash("pvt", psk[:]), Encrypted: ciphertext,
	}), "pvt", "!11223344")
}

// TestReprocess_FillsColumnsAddedLater is the point of the whole exercise:
// a frame stored before the reception/Data columns existed can still be
// given them, because its bytes were kept (ADR-3).
func TestReprocess_FillsColumnsAddedLater(t *testing.T) {
	s := openTestStore(t)
	channels, psk := testChannel(t)

	id := insertLegacyFrame(t, s, "msh/pvt/2/e/pvt/!11223344",
		encryptedTextEnvelope(t, psk, 0x99aabbcc, 0x4242, "backfill me"), "decoded", time.Now(), 0x4242)

	// Before: everything added later is NULL.
	var portnum sql.NullInt64
	if err := s.db.QueryRow(`SELECT portnum FROM raw_frames WHERE id = ?;`, id).Scan(&portnum); err != nil {
		t.Fatalf("querying: %v", err)
	}
	if portnum.Valid {
		t.Fatalf("legacy fixture already has portnum set: %+v", portnum)
	}

	report, err := s.Reprocess(channels, 30, true, nil)
	if err != nil {
		t.Fatalf("Reprocess: %v", err)
	}
	if report.Scanned != 1 || report.FieldsUpdated != 1 || report.DecodedRowsInserted != 1 {
		t.Errorf("report = %+v, want 1 scanned/updated/inserted", report)
	}
	if report.BackupPath == "" {
		t.Error("apply=true produced no backup path")
	} else if _, err := os.Stat(report.BackupPath); err != nil {
		t.Errorf("backup file missing: %v", err)
	}

	var name sql.NullString
	var version int
	if err := s.db.QueryRow(
		`SELECT portnum, portnum_name, decode_version FROM raw_frames WHERE id = ?;`, id,
	).Scan(&portnum, &name, &version); err != nil {
		t.Fatalf("querying after reprocess: %v", err)
	}
	if !portnum.Valid || portnum.Int64 != int64(decode.PortNumTextMessage) || name.String != "TEXT_MESSAGE_APP" {
		t.Errorf("portnum/name = %+v/%+v, want 1/TEXT_MESSAGE_APP", portnum, name)
	}
	if version != DecodeVersion {
		t.Errorf("decode_version = %d, want %d", version, DecodeVersion)
	}

	var fields string
	if err := s.db.QueryRow(`SELECT fields FROM decoded_payloads WHERE raw_frame_id = ?;`, id).Scan(&fields); err != nil {
		t.Fatalf("no decoded payload after reprocess: %v", err)
	}
	if fields == "" {
		t.Error("decoded payload fields are empty")
	}
}

// TestReprocess_DryRunChangesNothing keeps the default harmless.
func TestReprocess_DryRunChangesNothing(t *testing.T) {
	s := openTestStore(t)
	channels, psk := testChannel(t)
	id := insertLegacyFrame(t, s, "msh/pvt/2/e/pvt/!11223344",
		encryptedTextEnvelope(t, psk, 0x99aabbcc, 1, "dry run"), "decoded", time.Now(), 1)

	report, err := s.Reprocess(channels, 30, false, nil)
	if err != nil {
		t.Fatalf("Reprocess: %v", err)
	}
	if report.FieldsUpdated != 1 || report.DecodedRowsInserted != 1 {
		t.Errorf("dry run report = %+v, want it to say what would change", report)
	}
	if report.BackupPath != "" {
		t.Errorf("dry run made a backup at %q; it should not touch the disk", report.BackupPath)
	}

	var portnum sql.NullInt64
	var decoded int
	if err := s.db.QueryRow(`SELECT portnum FROM raw_frames WHERE id = ?;`, id).Scan(&portnum); err != nil {
		t.Fatalf("querying: %v", err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM decoded_payloads;`).Scan(&decoded); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if portnum.Valid || decoded != 0 {
		t.Errorf("dry run wrote: portnum=%+v decoded_payloads=%d", portnum, decoded)
	}
}

// TestReprocess_IsIdempotent guards the obvious failure of a backfill:
// running it twice must not double the decoded rows.
func TestReprocess_IsIdempotent(t *testing.T) {
	s := openTestStore(t)
	channels, psk := testChannel(t)
	insertLegacyFrame(t, s, "msh/pvt/2/e/pvt/!11223344",
		encryptedTextEnvelope(t, psk, 0x99aabbcc, 2, "twice"), "decoded", time.Now(), 2)

	for pass := 1; pass <= 2; pass++ {
		if _, err := s.Reprocess(channels, 30, true, nil); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
	}

	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM decoded_payloads;`).Scan(&n); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if n != 1 {
		t.Errorf("decoded_payloads has %d rows after two passes, want 1", n)
	}
}

// TestReprocess_RecordsStatusChangeForNewDecoder covers the case that
// motivated this: frames stored as unhandled_portnum before a decoder for
// that portnum existed. The transition is reported rather than applied
// quietly, because it changes a recorded fact.
func TestReprocess_RecordsStatusChangeForNewDecoder(t *testing.T) {
	s := openTestStore(t)
	channels, psk := testChannel(t)

	// A ROUTING_APP frame: portnum 5, which had no decoder when the earlier
	// rows were written.
	data := decode.EncodeData(decode.PortNumRouting, []byte{0x18, 0x00})
	ciphertext, err := decode.CryptCTR(psk[:], decode.DeriveNonce(9, 0x99aabbcc), data)
	if err != nil {
		t.Fatalf("CryptCTR: %v", err)
	}
	envelope := decode.EncodeServiceEnvelope(decode.EncodeMeshPacket(decode.MeshPacketFields{
		From: 0x99aabbcc, To: 0xffffffff, ID: 9,
		ChannelHash: decode.ChannelHash("pvt", psk[:]), Encrypted: ciphertext,
	}), "pvt", "!11223344")

	id := insertLegacyFrame(t, s, "msh/pvt/2/e/pvt/!11223344", envelope, "unhandled_portnum", time.Now(), 9)

	report, err := s.Reprocess(channels, 30, true, nil)
	if err != nil {
		t.Fatalf("Reprocess: %v", err)
	}
	if got := report.StatusChanges["unhandled_portnum->decoded"]; got != 1 {
		t.Errorf("StatusChanges = %v, want one unhandled_portnum->decoded", report.StatusChanges)
	}

	var status, name string
	if err := s.db.QueryRow(`SELECT decode_status, portnum_name FROM raw_frames WHERE id = ?;`, id).
		Scan(&status, &name); err != nil {
		t.Fatalf("querying: %v", err)
	}
	if status != string(decode.StatusDecoded) || name != "ROUTING_APP" {
		t.Errorf("status/name = %q/%q, want decoded/ROUTING_APP", status, name)
	}
}

// TestReprocess_LeavesUndecodableFrameAlone keeps a stored diagnosis from
// being replaced by a fresh guess.
func TestReprocess_LeavesUndecodableFrameAlone(t *testing.T) {
	s := openTestStore(t)
	channels, _ := testChannel(t)

	// Encrypted under a channel with no configured PSK.
	envelope := decode.EncodeServiceEnvelope(decode.EncodeMeshPacket(decode.MeshPacketFields{
		From: 0x99aabbcc, To: 0xffffffff, ID: 11, Encrypted: []byte{0xde, 0xad},
	}), "unknown", "!11223344")
	id := insertLegacyFrame(t, s, "msh/pvt/2/e/unknown/!11223344", envelope, "unknown_channel", time.Now(), 11)

	if _, err := s.Reprocess(channels, 30, true, nil); err != nil {
		t.Fatalf("Reprocess: %v", err)
	}

	var status string
	var portnum sql.NullInt64
	if err := s.db.QueryRow(`SELECT decode_status, portnum FROM raw_frames WHERE id = ?;`, id).
		Scan(&status, &portnum); err != nil {
		t.Fatalf("querying: %v", err)
	}
	if status != "unknown_channel" {
		t.Errorf("decode_status = %q, want it left as unknown_channel", status)
	}
	if portnum.Valid {
		t.Errorf("portnum set for a frame that still cannot be decrypted: %+v", portnum)
	}
}

// TestReprocess_DoesNotResurrectPrunedDecodedRows: a frame older than the
// decoded retention window still gets its raw columns, but no decoded row --
// re-creating one would undo a deletion the operator asked for.
func TestReprocess_DoesNotResurrectPrunedDecodedRows(t *testing.T) {
	s := openTestStore(t)
	channels, psk := testChannel(t)

	old := time.Now().AddDate(0, 0, -40)
	id := insertLegacyFrame(t, s, "msh/pvt/2/e/pvt/!11223344",
		encryptedTextEnvelope(t, psk, 0x99aabbcc, 3, "long ago"), "decoded", old, 3)

	report, err := s.Reprocess(channels, 30, true, nil)
	if err != nil {
		t.Fatalf("Reprocess: %v", err)
	}
	if report.DecodedRowsSkipped != 1 || report.DecodedRowsInserted != 0 {
		t.Errorf("report = %+v, want the old frame's decoded row skipped", report)
	}

	var portnum sql.NullInt64
	if err := s.db.QueryRow(`SELECT portnum FROM raw_frames WHERE id = ?;`, id).Scan(&portnum); err != nil {
		t.Fatalf("querying: %v", err)
	}
	if !portnum.Valid {
		t.Error("raw columns were not updated for an old frame; they are part of the raw record")
	}
}

// TestReprocess_MatchesTheInsertPath is the anti-drift test: reprocessing a
// frame must leave exactly what storing it fresh would have left. Two write
// paths with their own copy of the NULL rules would diverge, and the
// divergence would look like real data.
func TestReprocess_MatchesTheInsertPath(t *testing.T) {
	channels, psk := testChannel(t)
	topic := "msh/pvt/2/e/pvt/!11223344"
	payload := encryptedTextEnvelope(t, psk, 0x99aabbcc, 0x5150, "same both ways")
	receivedAt := time.Now()

	// Path 1: the normal insert.
	fresh := openTestStore(t)
	res, err := decode.Decode(topic, payload, channels)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if _, err := fresh.InsertRawFrame(res, "alpha", "alpha", payload, receivedAt); err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}

	// Path 2: a legacy row, then reprocessing.
	backfilled := openTestStore(t)
	insertLegacyFrame(t, backfilled, topic, payload, "decoded", receivedAt, 0x5150)
	if _, err := backfilled.Reprocess(channels, 30, true, nil); err != nil {
		t.Fatalf("Reprocess: %v", err)
	}

	const cols = `decode_status, decode_version, rx_snr, rx_rssi, rx_time, hop_limit,
		hop_start, want_ack, via_mqtt, priority, relay_node, portnum, portnum_name,
		want_response, dest_node, source_node, request_id, reply_id, bitfield`

	read := func(s *Store) []any {
		row := s.db.QueryRow(`SELECT ` + cols + ` FROM raw_frames LIMIT 1;`)
		vals := make([]any, 19)
		ptrs := make([]any, len(vals))
		for i := range vals {
			var v any
			vals[i] = &v
			ptrs[i] = vals[i]
		}
		if err := row.Scan(ptrs...); err != nil {
			t.Fatalf("scanning: %v", err)
		}
		out := make([]any, len(vals))
		for i, p := range vals {
			out[i] = *(p.(*any))
		}
		return out
	}

	want, got := read(fresh), read(backfilled)
	names := []string{"decode_status", "decode_version", "rx_snr", "rx_rssi", "rx_time",
		"hop_limit", "hop_start", "want_ack", "via_mqtt", "priority", "relay_node",
		"portnum", "portnum_name", "want_response", "dest_node", "source_node",
		"request_id", "reply_id", "bitfield"}
	for i := range want {
		if fmtAny(want[i]) != fmtAny(got[i]) {
			t.Errorf("%s: insert path stored %v, reprocess stored %v", names[i], want[i], got[i])
		}
	}
}

func fmtAny(v any) string {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return fmt.Sprintf("%v", v)
}

// TestReprocess_RecomputesDuplicatesWithTheLiveRule covers both directions
// of the dedup interaction: a genuine re-delivery must stay duplicate and
// gain no decoded row (ADR-14), while a frame wrongly marked duplicate by
// the packet-id-zero bug must come back as decoded.
func TestReprocess_RecomputesDuplicatesWithTheLiveRule(t *testing.T) {
	s := openTestStore(t)
	channels, psk := testChannel(t)
	base := time.Now().Add(-time.Hour)

	// Two deliveries of the same packet, 8 seconds apart: the second is a
	// real duplicate.
	env := encryptedTextEnvelope(t, psk, 0x99aabbcc, 0x7777, "retried")
	firstID := insertLegacyFrame(t, s, "msh/pvt/2/e/pvt/!11223344", env, "decoded", base, 0x7777)
	dupID := insertLegacyFrame(t, s, "msh/pvt/2/e/pvt/!11223344", env, "duplicate", base.Add(8*time.Second), 0x7777)

	// Two id-less map-report frames from the same gateway, 30 seconds apart.
	// The second was stored as duplicate by the bug this release fixes.
	mapEnv := decode.EncodeServiceEnvelope(
		decode.EncodeMeshPacketDecodedFields(decode.MeshPacketFields{From: 0x11223344, To: 0xffffffff},
			decode.EncodeData(decode.PortNumMapReport, []byte{0x01, 0x02})),
		"LongFast", "!11223344")
	mapFirstID := insertLegacyFrame(t, s, "msh/pvt/2/map/", mapEnv, "decoded", base.Add(time.Minute), 0)
	mapDupID := insertLegacyFrame(t, s, "msh/pvt/2/map/", mapEnv, "duplicate", base.Add(90*time.Second), 0)

	if _, err := s.Reprocess(channels, 30, true, nil); err != nil {
		t.Fatalf("Reprocess: %v", err)
	}

	statusOf := func(id int64) string {
		var st string
		if err := s.db.QueryRow(`SELECT decode_status FROM raw_frames WHERE id = ?;`, id).Scan(&st); err != nil {
			t.Fatalf("querying status of %d: %v", id, err)
		}
		return st
	}
	decodedRows := func(id int64) int {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM decoded_payloads WHERE raw_frame_id = ?;`, id).Scan(&n); err != nil {
			t.Fatalf("counting decoded rows of %d: %v", id, err)
		}
		return n
	}

	if got := statusOf(firstID); got != "decoded" {
		t.Errorf("first delivery status = %q, want decoded", got)
	}
	if got := statusOf(dupID); got != "duplicate" {
		t.Errorf("real re-delivery status = %q, want it kept as duplicate", got)
	}
	if got := decodedRows(dupID); got != 0 {
		t.Errorf("duplicate frame gained %d decoded rows, want 0 (ADR-14)", got)
	}

	if got := statusOf(mapFirstID); got != "decoded" {
		t.Errorf("first map report status = %q, want decoded", got)
	}
	if got := statusOf(mapDupID); got != "decoded" {
		t.Errorf("second id-less map report status = %q, want decoded: a frame with no packet id is not a duplicate", got)
	}
}

// TestReprocess_KeepsWhatItCanNoLongerDecode covers what a real channel key
// rotation did to a real database: two frames stored as decoded, decrypted at
// the time with the key then in use, would decode as decrypt_failed today. The
// pass must leave them alone -- overwriting would replace a real portnum and a
// real payload with NULLs, and the key that could recover them is gone.
func TestReprocess_KeepsWhatItCanNoLongerDecode(t *testing.T) {
	s := openTestStore(t)

	var oldPSK, newPSK [decode.PSKSize]byte
	for i := range oldPSK {
		oldPSK[i] = byte(i + 1)
		newPSK[i] = byte(i + 100)
	}
	oldChannels := map[string][decode.PSKSize]byte{"pvt": oldPSK}
	newChannels := map[string][decode.PSKSize]byte{"pvt": newPSK}

	// A frame that arrived before the rotation, decoded with the key of the day.
	payload := encryptedTextEnvelope(t, oldPSK, 0x11223344, 0x1001, "before the rotation")
	topic := "msh/pvt/2/e/pvt/!11223344"
	res, err := decode.Decode(topic, payload, oldChannels)
	if err != nil {
		t.Fatalf("decoding with the old key: %v", err)
	}
	if res.Status != decode.StatusDecoded {
		t.Fatalf("setup: status = %s, want decoded", res.Status)
	}
	rawID, err := s.InsertRawFrame(res, "alpha", "alpha", payload, time.Now())
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
	if _, err := s.InsertDecodedPayload(rawID, res); err != nil {
		t.Fatalf("InsertDecodedPayload: %v", err)
	}

	// Reprocess with only the new key, as a rotated deployment would.
	report, err := s.Reprocess(newChannels, 30, true, nil)
	if err != nil {
		t.Fatalf("Reprocess: %v", err)
	}

	if len(report.Regressions) != 1 {
		t.Errorf("Regressions = %v, want the one frame that can no longer be decoded", report.Regressions)
	}
	if n := report.StatusChanges["decoded->decrypt_failed"]; n != 0 {
		t.Errorf("a decoded frame was downgraded %d times", n)
	}

	var status, portnum sql.NullString
	if err := s.db.QueryRow(
		`SELECT decode_status, portnum_name FROM raw_frames WHERE id = ?;`, rawID,
	).Scan(&status, &portnum); err != nil {
		t.Fatalf("reading the frame back: %v", err)
	}
	if status.String != string(decode.StatusDecoded) {
		t.Errorf("decode_status = %q, want the stored diagnosis kept", status.String)
	}
	if portnum.String != "TEXT_MESSAGE_APP" {
		t.Errorf("portnum_name = %q, want the value decoded with the old key", portnum.String)
	}
}

// TestReprocess_DryRunPredictsWhatApplyDoes: the dry run's numbers are what an
// operator decides on. One real pass predicted 118 decoded rows and inserted 1,
// because 117 already existed from an earlier pass -- the prediction counted
// every decodable frame rather than every frame that would gain a row.
func TestReprocess_DryRunPredictsWhatApplyDoes(t *testing.T) {
	s := openTestStore(t)
	channels, psk := testChannel(t)

	now := time.Now().UTC()
	for i, text := range []string{"one", "two", "three"} {
		packetID := uint32(0x2000 + i)
		payload := encryptedTextEnvelope(t, psk, 0x11223344, packetID, text)
		insertLegacyFrame(t, s, "msh/pvt/2/e/pvt/!11223344", payload, "decoded",
			now.Add(time.Duration(i)*time.Minute), packetID)
	}

	// First pass: everything is new.
	firstDry, err := s.Reprocess(channels, 30, false, nil)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	firstApply, err := s.Reprocess(channels, 30, true, nil)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if firstDry.DecodedRowsInserted != firstApply.DecodedRowsInserted {
		t.Errorf("first pass: dry run predicted %d rows, apply inserted %d",
			firstDry.DecodedRowsInserted, firstApply.DecodedRowsInserted)
	}

	// Second pass: the rows exist, so both must report none.
	secondDry, err := s.Reprocess(channels, 30, false, nil)
	if err != nil {
		t.Fatalf("second dry run: %v", err)
	}
	secondApply, err := s.Reprocess(channels, 30, true, nil)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if secondDry.DecodedRowsInserted != 0 {
		t.Errorf("second dry run predicted %d insertions with every row already present",
			secondDry.DecodedRowsInserted)
	}
	if secondApply.DecodedRowsInserted != 0 {
		t.Errorf("second apply inserted %d rows that already existed", secondApply.DecodedRowsInserted)
	}
}
