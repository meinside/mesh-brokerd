package storage

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/meinside/mesh-brokerd/internal/decode"
)

// TestInsertRawFrame_ReceptionFieldsNullVsZero is the whole point of
// ADR-15's nullable columns: rx_snr = 0.0 is a measurement of 0 dB, while
// rx_snr IS NULL means the packet never stated one (a gateway's own
// traffic). Storing the second as 0 would invent evidence.
func TestInsertRawFrame_ReceptionFieldsNullVsZero(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()

	measuredZero := &decode.Result{
		Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt",
		GatewayID: "!11223344", PacketID: 1, FromNode: 0x11223344, ToNode: 0xffffffff,
		Status: decode.StatusDecoded, Portnum: decode.PortNumTextMessage, PacketParsed: true,
		HasRxSnr: true, RxSnr: 0, HasRxRssi: true, RxRssi: -120,
		TextMessage: &decode.TextMessage{Text: "x"},
	}
	notStated := &decode.Result{
		Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt",
		GatewayID: "!11223344", PacketID: 2, FromNode: 0x11223344, ToNode: 0xffffffff,
		Status: decode.StatusDecoded, Portnum: decode.PortNumTextMessage, PacketParsed: true,
		TextMessage: &decode.TextMessage{Text: "y"},
	}

	idZero, err := s.InsertRawFrame(measuredZero, "alpha", "alpha", []byte{1}, now)
	if err != nil {
		t.Fatalf("InsertRawFrame (measured): %v", err)
	}
	idNull, err := s.InsertRawFrame(notStated, "alpha", "alpha", []byte{2}, now)
	if err != nil {
		t.Fatalf("InsertRawFrame (absent): %v", err)
	}

	var snr sql.NullFloat64
	var rssi sql.NullInt64
	if err := s.db.QueryRow(`SELECT rx_snr, rx_rssi FROM raw_frames WHERE id = ?;`, idZero).Scan(&snr, &rssi); err != nil {
		t.Fatalf("querying measured row: %v", err)
	}
	if !snr.Valid || snr.Float64 != 0 {
		t.Errorf("measured rx_snr = %+v, want a valid 0", snr)
	}
	if !rssi.Valid || rssi.Int64 != -120 {
		t.Errorf("measured rx_rssi = %+v, want a valid -120 (negative must survive)", rssi)
	}

	if err := s.db.QueryRow(`SELECT rx_snr, rx_rssi FROM raw_frames WHERE id = ?;`, idNull).Scan(&snr, &rssi); err != nil {
		t.Fatalf("querying absent row: %v", err)
	}
	if snr.Valid || rssi.Valid {
		t.Errorf("absent rx_snr/rx_rssi stored as %+v/%+v, want NULL", snr, rssi)
	}
}

// TestInsertRawFrame_DataFieldsNullWhenNeverDecrypted keeps a failed
// decryption from looking like a frame that stated portnum 0 and an empty
// bitfield.
func TestInsertRawFrame_DataFieldsNullWhenNeverDecrypted(t *testing.T) {
	s := openTestStore(t)

	res := &decode.Result{
		Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt",
		GatewayID: "!11223344", PacketID: 3, FromNode: 0x11223344, ToNode: 0xffffffff,
		Status: decode.StatusDecryptFailed, PacketParsed: true,
	}
	id, err := s.InsertRawFrame(res, "alpha", "alpha", []byte{3}, time.Now())
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}

	var portnum, bitfield, wantResponse sql.NullInt64
	var portnumName sql.NullString
	if err := s.db.QueryRow(
		`SELECT portnum, portnum_name, bitfield, want_response FROM raw_frames WHERE id = ?;`, id,
	).Scan(&portnum, &portnumName, &bitfield, &wantResponse); err != nil {
		t.Fatalf("querying row: %v", err)
	}
	if portnum.Valid || portnumName.Valid || bitfield.Valid || wantResponse.Valid {
		t.Errorf("decrypt-failed frame stored Data fields: portnum=%+v name=%+v bitfield=%+v want_response=%+v",
			portnum, portnumName, bitfield, wantResponse)
	}
}

// TestInsertDecodedPayload_StoresJSON covers the table that made the
// difference between "189 decoded frames" and knowing what they were.
func TestInsertDecodedPayload_StoresJSON(t *testing.T) {
	s := openTestStore(t)

	res := &decode.Result{
		Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt",
		GatewayID: "!11223344", PacketID: 4, FromNode: 0x11223344, ToNode: 0xffffffff,
		Status: decode.StatusDecoded, Portnum: decode.PortNumTelemetry, PacketParsed: true,
		Telemetry: &decode.Telemetry{Device: &decode.DeviceMetrics{
			HasBatteryLevel: true, BatteryLevel: 91,
			HasVoltage: true, Voltage: 4.3,
		}},
	}
	rawID, err := s.InsertRawFrame(res, "alpha", "alpha", []byte{4}, time.Now())
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
	id, err := s.InsertDecodedPayload(rawID, res)
	if err != nil {
		t.Fatalf("InsertDecodedPayload: %v", err)
	}
	if id == 0 {
		t.Fatal("InsertDecodedPayload returned id 0 for a decoded telemetry frame")
	}

	var name, fields string
	var portnum int
	if err := s.db.QueryRow(
		`SELECT portnum, portnum_name, fields FROM decoded_payloads WHERE raw_frame_id = ?;`, rawID,
	).Scan(&portnum, &name, &fields); err != nil {
		t.Fatalf("querying decoded_payloads: %v", err)
	}
	if portnum != int(decode.PortNumTelemetry) || name != "TELEMETRY_APP" {
		t.Errorf("portnum/name = %d/%q, want 67/TELEMETRY_APP", portnum, name)
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(fields), &decoded); err != nil {
		t.Fatalf("stored fields are not valid JSON: %v (%q)", err, fields)
	}
	dev, ok := decoded["device_metrics"].(map[string]any)
	if !ok {
		t.Fatalf("device_metrics missing from stored JSON: %v", decoded)
	}
	if dev["battery_level"] != float64(91) {
		t.Errorf("stored battery_level = %v, want 91", dev["battery_level"])
	}

	// The same JSON must be queryable by SQL, which is why it is a text
	// column rather than a blob.
	var battery int
	if err := s.db.QueryRow(
		`SELECT json_extract(fields, '$.device_metrics.battery_level') FROM decoded_payloads WHERE raw_frame_id = ?;`,
		rawID,
	).Scan(&battery); err != nil {
		t.Fatalf("json_extract: %v", err)
	}
	if battery != 91 {
		t.Errorf("json_extract battery_level = %d, want 91", battery)
	}
}

// TestInsertDecodedPayload_NoRowForUninterpretedPortnum keeps
// raw-frame-first honest: an unhandled portnum is stored as bytes and
// nothing else, rather than as an empty decoded row.
func TestInsertDecodedPayload_NoRowForUninterpretedPortnum(t *testing.T) {
	s := openTestStore(t)
	res := &decode.Result{
		Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt",
		GatewayID: "!11223344", PacketID: 5, FromNode: 0x11223344, ToNode: 0xffffffff,
		Status: decode.StatusUnhandledPortnum, Portnum: decode.PortNum(99), PacketParsed: true,
	}
	rawID, err := s.InsertRawFrame(res, "alpha", "alpha", []byte{5}, time.Now())
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
	id, err := s.InsertDecodedPayload(rawID, res)
	if err != nil {
		t.Fatalf("InsertDecodedPayload: %v", err)
	}
	if id != 0 {
		t.Errorf("InsertDecodedPayload wrote row %d for an uninterpreted portnum", id)
	}

	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM decoded_payloads;`).Scan(&n); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if n != 0 {
		t.Errorf("decoded_payloads has %d rows, want 0", n)
	}

	// The frame itself is still there, with its portnum recorded.
	var portnum sql.NullInt64
	var portnumName sql.NullString
	if err := s.db.QueryRow(`SELECT portnum, portnum_name FROM raw_frames WHERE id = ?;`, rawID).
		Scan(&portnum, &portnumName); err != nil {
		t.Fatalf("querying raw frame: %v", err)
	}
	if !portnum.Valid || portnum.Int64 != 99 || portnumName.String != "PORTNUM_99" {
		t.Errorf("portnum/name = %+v/%+v, want 99/PORTNUM_99", portnum, portnumName)
	}
}

// TestDeleteExpired_SweepsOrphanedDecodedPayloads covers the case a
// join-only prune would miss: raw_frames retention is shorter than the
// decoded retention, so rows can lose their frame before their own cutoff.
func TestDeleteExpired_SweepsOrphanedDecodedPayloads(t *testing.T) {
	s := openTestStore(t)

	old := time.Now().AddDate(0, 0, -40)
	res := &decode.Result{
		Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt",
		GatewayID: "!11223344", PacketID: 6, FromNode: 0x11223344, ToNode: 0xffffffff,
		Status: decode.StatusDecoded, Portnum: decode.PortNumPosition, PacketParsed: true,
		Position: &decode.Position{HasLatLon: true, LatitudeI: 375128064, LongitudeI: 1270611968},
	}
	rawID, err := s.InsertRawFrame(res, "alpha", "alpha", []byte{6}, old)
	if err != nil {
		t.Fatalf("InsertRawFrame: %v", err)
	}
	if _, err := s.InsertDecodedPayload(rawID, res); err != nil {
		t.Fatalf("InsertDecodedPayload: %v", err)
	}

	// Prune raw frames only (decodedDays = 0 means "keep decoded content
	// forever"), which is exactly the configuration that would otherwise
	// leave a row pointing at a frame that no longer exists.
	if _, _, err := s.DeleteExpired(30, 0); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM decoded_payloads;`).Scan(&n); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if n != 0 {
		t.Errorf("decoded_payloads has %d orphaned rows after pruning raw_frames, want 0", n)
	}
}
