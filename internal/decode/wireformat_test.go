package decode

import (
	"encoding/binary"
	"testing"
)

// TestParseMeshPacket_WireFormatGroundTruth locks in MeshPacket's real
// field numbers and wire types using hand-written protobuf bytes --
// deliberately NOT built with this package's own Encode* helpers.
//
// Why hand-written: an earlier version of this package had `decoded`
// and `encrypted` transposed (4 vs 5) and treated from/to/id as varints
// instead of fixed32. Because the encoder and decoder shared those same
// wrong assumptions, every round-trip unit test passed while real
// firmware traffic failed to decode. Ground truth here must therefore
// come from the schema, not from our own encoder.
//
// Byte layout below (tag = fieldNumber<<3 | wireType):
//
//	field 1 from,  fixed32 -> tag 0x0d, then 4 bytes little-endian
//	field 2 to,    fixed32 -> tag 0x15
//	field 3 channel, varint -> tag 0x18
//	field 6 id,    fixed32 -> tag 0x35
//	field 5 encrypted, bytes -> tag 0x2a, then varint length
//	field 4 decoded,   bytes -> tag 0x22, then varint length
func TestParseMeshPacket_WireFormatGroundTruth(t *testing.T) {
	t.Run("encrypted variant", func(t *testing.T) {
		raw := []byte{
			0x0d, 0x44, 0x33, 0x22, 0x11, // from = 0x11223344
			0x15, 0xff, 0xff, 0xff, 0xff, // to   = 0xffffffff
			0x18, 0x64, // channel = 100 (varint)
			0x35, 0x3a, 0x08, 0xc1, 0x4d, // id   = 0x4dc1083a
			0x2a, 0x03, 0xaa, 0xbb, 0xcc, // encrypted = 3 opaque bytes
		}

		mp, err := ParseMeshPacket(raw)
		if err != nil {
			t.Fatalf("ParseMeshPacket: %v", err)
		}
		if mp.From != 0x11223344 {
			t.Errorf("From = %#x, want 0x11223344 (fixed32, not varint)", mp.From)
		}
		if mp.To != 0xffffffff {
			t.Errorf("To = %#x, want 0xffffffff", mp.To)
		}
		if mp.ID != 0x4dc1083a {
			t.Errorf("ID = %#x, want 0x4dc1083a", mp.ID)
		}
		if mp.Channel != 100 {
			t.Errorf("Channel = %d, want 100 (field 3, varint)", mp.Channel)
		}
		if len(mp.Encrypted) != 3 {
			t.Errorf("Encrypted length = %d, want 3 (field 5 is `encrypted`)", len(mp.Encrypted))
		}
		if mp.Decoded != nil {
			t.Errorf("Decoded = %x, want nil (field 4 absent in the encrypted variant)", mp.Decoded)
		}
	})

	t.Run("decoded variant", func(t *testing.T) {
		raw := []byte{
			0x0d, 0x44, 0x33, 0x22, 0x11, // from
			0x22, 0x02, 0x08, 0x01, // decoded = Data{portnum:1}
		}

		mp, err := ParseMeshPacket(raw)
		if err != nil {
			t.Fatalf("ParseMeshPacket: %v", err)
		}
		if len(mp.Decoded) != 2 {
			t.Fatalf("Decoded length = %d, want 2 (field 4 is `decoded`)", len(mp.Decoded))
		}
		if mp.Encrypted != nil {
			t.Errorf("Encrypted = %x, want nil (field 5 absent in the decoded variant)", mp.Encrypted)
		}
		data, err := ParseData(mp.Decoded)
		if err != nil {
			t.Fatalf("ParseData on Decoded: %v", err)
		}
		if PortNum(data.Portnum) != PortNumTextMessage {
			t.Errorf("portnum = %d, want %d", data.Portnum, PortNumTextMessage)
		}
	})
}

// TestEncodeMeshPacket_MatchesGroundTruth confirms the encoder produces
// exactly the wire bytes the schema calls for, so the encoder can never
// silently drift away from the decoder again (the two agreeing with
// each other is not evidence -- they must both match the schema).
func TestEncodeMeshPacket_MatchesGroundTruth(t *testing.T) {
	got := EncodeMeshPacket(MeshPacketFields{From: 0x11223344, To: 0xffffffff, ID: 0x4dc1083a, ChannelHash: 100, Encrypted: []byte{0xaa, 0xbb, 0xcc}})
	want := []byte{
		0x0d, 0x44, 0x33, 0x22, 0x11,
		0x15, 0xff, 0xff, 0xff, 0xff,
		0x18, 0x64,
		0x35, 0x3a, 0x08, 0xc1, 0x4d,
		0x2a, 0x03, 0xaa, 0xbb, 0xcc,
	}
	if string(got) != string(want) {
		t.Errorf("EncodeMeshPacket =\n  %x\nwant\n  %x", got, want)
	}
}

// Node numbers in this file are obviously-fake stand-ins: the byte layout
// (field numbers, wire types, fixed32-vs-varint) is what these tests assert
// and it is unchanged from the real captures, but the identifiers those
// captures carried are deployment data and are not published.
//
// realGatewayMeshPacketFields records the field numbers and wire types of a
// MeshPacket as a real Meshtastic gateway actually uplinks it, captured from
// live traffic (a POSITION_APP broadcast). Only the structure
// is recorded — not the values, which are deployment data.
//
// This exists because the relay's constructed packets were missing five of
// these fields and nothing caught it: brokerd's own decoder reads what
// brokerd's own encoder writes, so encoder and decoder agreed with each
// other while disagreeing with real traffic, and it cost a publish to a
// public server that no consumer picked up.
var realGatewayMeshPacketFields = map[int]int{
	1:  5, // from       fixed32
	2:  5, // to         fixed32
	3:  0, // channel    varint (channel hash)
	5:  2, // encrypted  bytes
	6:  5, // id         fixed32
	7:  5, // rx_time    fixed32
	9:  0, // hop_limit  varint
	11: 0, // priority   varint
	15: 0, // hop_start  varint
	19: 0, // relay_node varint
}

// fieldSet returns field number -> wire type for a protobuf message.
func fieldSet(t *testing.T, b []byte) map[int]int {
	t.Helper()
	out := map[int]int{}
	for i := 0; i < len(b); {
		key, n := binaryUvarint(b[i:])
		if n <= 0 {
			t.Fatalf("malformed key at offset %d", i)
		}
		i += n
		fn, wt := int(key>>3), int(key&7)
		out[fn] = wt
		switch wt {
		case 0:
			_, n := binaryUvarint(b[i:])
			i += n
		case 5:
			i += 4
		case 2:
			l, n := binaryUvarint(b[i:])
			i += n + int(l)
		default:
			t.Fatalf("unexpected wire type %d for field %d", wt, fn)
		}
	}
	return out
}

// An uplinked packet must carry every field real gateway traffic carries.
//
// A packet missing hop_limit/hop_start reads as "no hops left", and one
// missing rx_time gives a consumer no observation time — both plausible
// reasons for a public map to ignore an otherwise-accepted packet.
func TestEncodeMeshPacket_MatchesRealGatewayFieldSet(t *testing.T) {
	got := fieldSet(t, EncodeMeshPacket(MeshPacketFields{
		From:        0x11111111,
		To:          0xffffffff,
		ID:          0x22222222,
		ChannelHash: 159,
		Encrypted:   []byte{0xaa, 0xbb},
		RxTime:      1787105302,
		HopLimit:    3,
		HopStart:    3,
		Priority:    10,
		RelayNode:   255,
	}))

	for field, wire := range realGatewayMeshPacketFields {
		gotWire, ok := got[field]
		if !ok {
			t.Errorf("field %d is missing; real gateway traffic includes it", field)
			continue
		}
		if gotWire != wire {
			t.Errorf("field %d wire type = %d, want %d (as in real traffic)", field, gotWire, wire)
		}
	}
	for field := range got {
		if _, ok := realGatewayMeshPacketFields[field]; !ok {
			t.Errorf("field %d is not present in real gateway traffic", field)
		}
	}
}

// Optional fields must stay absent when unset rather than being written as
// zero: hop_limit=0 is meaningfully different from "no hop_limit".
func TestEncodeMeshPacket_OmitsUnsetOptionalFields(t *testing.T) {
	got := fieldSet(t, EncodeMeshPacket(MeshPacketFields{
		From:        1,
		To:          2,
		ID:          3,
		ChannelHash: 4,
		Encrypted:   []byte{0x01},
	}))
	for _, field := range []int{7, 9, 11, 15, 19} {
		if _, ok := got[field]; ok {
			t.Errorf("field %d was written even though it was not set", field)
		}
	}
	for _, field := range []int{1, 2, 3, 5, 6} {
		if _, ok := got[field]; !ok {
			t.Errorf("required field %d is missing", field)
		}
	}
}

// binaryUvarint wraps encoding/binary so the helper above reads clearly.
func binaryUvarint(b []byte) (uint64, int) { return binary.Uvarint(b) }
