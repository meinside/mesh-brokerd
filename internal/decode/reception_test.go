package decode

import (
	"encoding/json"
	"math"
	"os"
	"testing"
)

// TestParseMeshPacket_ReceptionFields locks in the fields that describe how
// a packet was *received*, using hand-written protobuf bytes from the
// schema -- never this package's own encoder, for the reason
// TestParseMeshPacket_WireFormatGroundTruth documents.
//
// The two risky ones:
//
//	field  8 rx_snr  is a **float**, so wire type 5 (fixed32 bits) --
//	         tag 0x45, then 4 bytes of IEEE-754. Reading it as a varint is
//	         the exact class of mistake that once shipped for from/to/id.
//	field 12 rx_rssi is an **int32**, so a varint, and negative in
//	         practice: protobuf encodes -98 as its 64-bit two's
//	         complement, ten bytes long.
func TestParseMeshPacket_ReceptionFields(t *testing.T) {
	raw := []byte{
		0x0d, 0x44, 0x33, 0x22, 0x11, // 1 from = 0x11223344 (fixed32)
		0x45, 0x00, 0x00, 0xc0, 0x40, // 8 rx_snr = 6.0 (float bits 0x40c00000)
		0x48, 0x03, // 9 hop_limit = 3
		0x50, 0x01, // 10 want_ack = true
		// 12 rx_rssi = -98, as a 64-bit two's complement varint
		0x60, 0x9e, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
		0x70, 0x01, // 14 via_mqtt = true
		0x78, 0x03, // 15 hop_start = 3
	}

	mp, err := ParseMeshPacket(raw)
	if err != nil {
		t.Fatalf("ParseMeshPacket: %v", err)
	}
	if !mp.HasRxSnr || mp.RxSnr != 6.0 {
		t.Errorf("RxSnr = %v (has=%v), want 6.0 (field 8 is a float, wire type 5)", mp.RxSnr, mp.HasRxSnr)
	}
	if !mp.HasRxRssi || mp.RxRssi != -98 {
		t.Errorf("RxRssi = %d (has=%v), want -98 (field 12 is a signed int32 varint)", mp.RxRssi, mp.HasRxRssi)
	}
	if !mp.WantAck {
		t.Errorf("WantAck = false, want true (field 10)")
	}
	if !mp.ViaMqtt {
		t.Errorf("ViaMqtt = false, want true (field 14)")
	}
	if mp.HopLimit != 3 || mp.HopStart != 3 {
		t.Errorf("HopLimit/HopStart = %d/%d, want 3/3", mp.HopLimit, mp.HopStart)
	}
}

// TestParseMeshPacket_AbsentReceptionFieldsAreNotZero is the reason
// HasRxSnr/HasRxRssi exist. A gateway's own packet was never received over
// RF and states neither field; storing that as 0 would claim a measurement
// of 0 dB / 0 dBm that nothing ever made.
func TestParseMeshPacket_AbsentReceptionFieldsAreNotZero(t *testing.T) {
	raw := []byte{
		0x0d, 0x44, 0x33, 0x22, 0x11, // from only
		0x48, 0x03, // hop_limit = 3
	}
	mp, err := ParseMeshPacket(raw)
	if err != nil {
		t.Fatalf("ParseMeshPacket: %v", err)
	}
	if mp.HasRxSnr {
		t.Errorf("HasRxSnr = true for a packet with no field 8")
	}
	if mp.HasRxRssi {
		t.Errorf("HasRxRssi = true for a packet with no field 12")
	}
}

// TestParseMeshPacket_RealCaptureRxSnr checks the float decode against a
// real frame rather than against hand-written bytes: a gateway relaying a
// third node's private-channel message, whose own serial console logged
// "SNR 6 dB" for that packet in the same second. Two independent sources
// agreeing is what makes 6.0 ground truth here.
//
// The fixture's identifiers were overwritten in place with anonymised
// values of identical length (see the .expected file), so the encrypted
// payload no longer decrypts -- this is an envelope/packet parsing test
// only.
func TestParseMeshPacket_RealCaptureRxSnr(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/rf_received_1.bin")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var want struct {
		RxSnr        float64 `json:"rx_snr"`
		HopLimit     uint32  `json:"hop_limit"`
		HopStart     uint32  `json:"hop_start"`
		GatewayField string  `json:"gateway_id_field"`
	}
	expected, err := os.ReadFile("../../testdata/rf_received_1.expected")
	if err != nil {
		t.Fatalf("reading expectations: %v", err)
	}
	if err := json.Unmarshal(expected, &want); err != nil {
		t.Fatalf("decoding expectations: %v", err)
	}

	env, err := ParseServiceEnvelope(raw)
	if err != nil {
		t.Fatalf("ParseServiceEnvelope: %v", err)
	}
	if env.GatewayID != want.GatewayField {
		t.Errorf("GatewayID = %q, want %q", env.GatewayID, want.GatewayField)
	}
	mp, err := ParseMeshPacket(env.PacketBytes)
	if err != nil {
		t.Fatalf("ParseMeshPacket: %v", err)
	}
	if !mp.HasRxSnr || float64(mp.RxSnr) != want.RxSnr {
		t.Errorf("RxSnr = %v (has=%v), want %v from a real capture", mp.RxSnr, mp.HasRxSnr, want.RxSnr)
	}
	// The same capture is the evidence that an RF-received packet can still
	// omit rx_rssi entirely.
	if mp.HasRxRssi {
		t.Errorf("HasRxRssi = true, but field 12 is absent in this capture")
	}
	if mp.HopLimit != want.HopLimit || mp.HopStart != want.HopStart {
		t.Errorf("HopLimit/HopStart = %d/%d, want %d/%d", mp.HopLimit, mp.HopStart, want.HopLimit, want.HopStart)
	}
}

// TestParseData_AllFields covers the Data fields brokerd now stores, with
// field 7 asserted explicitly: it is reply_id, a fixed32. "Field 7" was
// once assumed to be bitfield and returned a confident zero; bitfield is
// field 9, a varint.
func TestParseData_AllFields(t *testing.T) {
	raw := []byte{
		0x08, 0x01, // 1 portnum = 1
		0x12, 0x02, 'h', 'i', // 2 payload = "hi"
		0x18, 0x01, // 3 want_response = true
		0x25, 0x88, 0x77, 0x66, 0x55, // 4 dest   = 0x55667788 (fixed32)
		0x2d, 0x44, 0x33, 0x22, 0x11, // 5 source = 0x11223344 (fixed32)
		0x35, 0xef, 0xbe, 0xad, 0xde, // 6 request_id = 0xdeadbeef
		0x3d, 0x0d, 0xf0, 0xfe, 0xca, // 7 reply_id   = 0xcafef00d
		0x48, 0x01, // 9 bitfield = 1 (OK_TO_MQTT)
	}
	d, err := ParseData(raw)
	if err != nil {
		t.Fatalf("ParseData: %v", err)
	}
	if d.Portnum != 1 || string(d.Payload) != "hi" {
		t.Errorf("portnum/payload = %d/%q, want 1/\"hi\"", d.Portnum, d.Payload)
	}
	if !d.WantResponse {
		t.Errorf("WantResponse = false, want true (field 3)")
	}
	if d.Dest != 0x55667788 || d.Source != 0x11223344 {
		t.Errorf("Dest/Source = %#x/%#x, want 0x55667788/0x11223344 (fixed32)", d.Dest, d.Source)
	}
	if d.RequestID != 0xdeadbeef {
		t.Errorf("RequestID = %#x, want 0xdeadbeef (field 6, fixed32)", d.RequestID)
	}
	if d.ReplyID != 0xcafef00d {
		t.Errorf("ReplyID = %#x, want 0xcafef00d -- field 7 is reply_id, not bitfield", d.ReplyID)
	}
	if !d.HasBitfield || d.Bitfield != 1 {
		t.Errorf("Bitfield = %d (has=%v), want 1 from field 9", d.Bitfield, d.HasBitfield)
	}
}

// TestParseData_BitfieldZeroIsNotAbsent separates "the sender said
// OK_TO_MQTT is off" from "the sender said nothing", which is the
// difference between a gateway refusing to uplink for a reason and a
// gateway with no instruction at all.
func TestParseData_BitfieldZeroIsNotAbsent(t *testing.T) {
	withZero := []byte{0x08, 0x01, 0x48, 0x00} // portnum 1, bitfield = 0
	d, err := ParseData(withZero)
	if err != nil {
		t.Fatalf("ParseData: %v", err)
	}
	if !d.HasBitfield || d.Bitfield != 0 {
		t.Errorf("explicit bitfield 0: got %d (has=%v), want 0/true", d.Bitfield, d.HasBitfield)
	}

	without := []byte{0x08, 0x01}
	d, err = ParseData(without)
	if err != nil {
		t.Fatalf("ParseData: %v", err)
	}
	if d.HasBitfield {
		t.Errorf("absent bitfield reported as present")
	}
}

func TestFloat32Bits_SanityOfTestVectors(t *testing.T) {
	// Guards the hand-written byte literals above: if 0x40c00000 is not
	// 6.0, the test vector is wrong rather than the parser.
	if got := math.Float32frombits(0x40c00000); got != 6.0 {
		t.Fatalf("0x40c00000 = %v, want 6.0", got)
	}
}
