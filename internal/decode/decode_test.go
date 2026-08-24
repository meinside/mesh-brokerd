package decode

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// fixture mirrors the shape of testdata/*.expected
// (docs/protocol-spec.md §5).
type fixture struct {
	ChannelName                   string `json:"channel_name"`
	PacketID                      string `json:"packet_id"`
	FromNode                      string `json:"from_node"`
	ExpectedPlaintextDataProtobuf string `json:"expected_plaintext_data_protobuf_hex"`
	ExpectedText                  string `json:"expected_text"`
	NonceHex                      string `json:"nonce_hex"`
}

func loadFixture(t *testing.T, name string) fixture {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parsing fixture %s: %v", path, err)
	}
	return f
}

// parseHexU32 parses a "0x..." hex string (as used in
// testdata/*.expected) into a uint32.
func parseHexU32(t *testing.T, hexStr string) uint32 {
	t.Helper()
	n, err := strconv.ParseUint(hexStr, 0, 32)
	if err != nil {
		t.Fatalf("parsing %q as uint32: %v", hexStr, err)
	}
	return uint32(n)
}

// TestCaptureFixtures verifies everything the committed hardware-capture
// fixtures can prove **without any key material** (docs/protocol-spec.md
// §5):
//
//  1. the nonce our DeriveNonce builds matches the nonce real firmware
//     actually used for that packet -- the single most valuable
//     assertion in the crypto path, and pure ground truth: the expected
//     value was captured from a device, not produced by this code;
//  2. the plaintext Data protobuf the firmware produced parses to the
//     expected portnum and text with our hand-written parser (ADR-13);
//  3. ciphertext length == plaintext length, the structural invariant of
//     an AES-CTR pair, confirming the captured pair is self-consistent.
//
// The ciphertext->plaintext step itself is deliberately NOT asserted
// here: it needs the channel PSK, the capture channels were throwaway
// channels that have since been deleted, and their PSK was never
// recorded anywhere (by design). See §5 for where end-to-end decryption
// *is* verified instead.
func TestCaptureFixtures(t *testing.T) {
	cases := []struct {
		name    string
		binFile string
		expFile string
	}{
		{"broadcast_text_1", "broadcast_text_1.bin", "broadcast_text_1.expected"},
		{"broadcast_text_2", "broadcast_text_2.bin", "broadcast_text_2.expected"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := loadFixture(t, c.expFile)
			ciphertext, err := os.ReadFile(filepath.Join("..", "..", "testdata", c.binFile))
			if err != nil {
				t.Fatalf("reading %s: %v", c.binFile, err)
			}

			// (1) Nonce derivation against real captured firmware output.
			packetID := parseHexU32(t, f.PacketID)
			fromNode := parseHexU32(t, f.FromNode)
			nonce := DeriveNonce(packetID, fromNode)
			if got := hex.EncodeToString(nonce[:]); got != f.NonceHex {
				t.Errorf("DeriveNonce(%#x, %#x) = %s, want %s (captured from real firmware)",
					packetID, fromNode, got, f.NonceHex)
			}

			// (2) The firmware's own plaintext Data protobuf, parsed by
			// our hand-written parser.
			plaintext, err := hex.DecodeString(f.ExpectedPlaintextDataProtobuf)
			if err != nil {
				t.Fatalf("fixture's expected_plaintext_data_protobuf_hex is not valid hex: %v", err)
			}
			data, err := ParseData(plaintext)
			if err != nil {
				t.Fatalf("ParseData on captured plaintext: %v", err)
			}
			if PortNum(data.Portnum) != PortNumTextMessage {
				t.Errorf("Data.Portnum = %d, want %d (TEXT_MESSAGE_APP)", data.Portnum, PortNumTextMessage)
			}
			if string(data.Payload) != f.ExpectedText {
				t.Errorf("Data.Payload = %q, want %q", data.Payload, f.ExpectedText)
			}

			// (3) AES-CTR is a stream cipher, so the captured ciphertext
			// must be exactly as long as the plaintext it came from. A
			// mismatch would mean the fixture pair itself is corrupt.
			if len(ciphertext) != len(plaintext) {
				t.Errorf("ciphertext length %d != plaintext length %d -- fixture pair is inconsistent",
					len(ciphertext), len(plaintext))
			}
		})
	}
}

// A map report must decode without a channel PSK.
//
// The firmware sends it as the MeshPacket's `decoded` (plaintext) variant —
// docs call it an "unencrypted map report" and the source confirms
// `which_payload_variant = decoded_tag` — so there is nothing to decrypt,
// and the topic carries no channel segment to look a PSK up by. An
// implementation that required either would silently drop it
// (docs/outbound-relay.md §10.1).
func TestDecode_MapReportNeedsNoChannelKey(t *testing.T) {
	// A minimal MapReport payload; contents are not interpreted by brokerd.
	mapReport := []byte{0x0a, 0x04, 'n', 'a', 'm', 'e'}
	data := EncodeData(PortNumMapReport, mapReport)
	mp := EncodeMeshPacketDecoded(0x55667788, 0xffffffff, 4242, data)
	// The firmware puts the *primary* channel's name in channel_id here.
	envelope := EncodeServiceEnvelope(mp, "LongFast", "!55667788")

	// Deliberately pass an empty channel map: no PSK is available at all.
	res, err := Decode("msh/pvt/2/map/", envelope, map[string][PSKSize]byte{})
	if err != nil {
		t.Fatalf("Decode returned an error for a map topic: %v", err)
	}
	if res.Status != StatusDecoded {
		t.Fatalf("Status = %v, want decoded", res.Status)
	}
	if res.Portnum != PortNumMapReport {
		t.Errorf("Portnum = %v, want MAP_REPORT_APP", res.Portnum)
	}
	if !bytes.Equal(res.RawPayload, mapReport) {
		t.Errorf("RawPayload = %x, want %x", res.RawPayload, mapReport)
	}
	if res.GatewayID != "!55667788" {
		t.Errorf("GatewayID = %q, want the envelope's gateway_id", res.GatewayID)
	}
	// There is no channel segment in the topic; the envelope's channel_id is
	// the honest stand-in and storage needs a non-empty value for it.
	if res.ChannelSegment != "LongFast" {
		t.Errorf("ChannelSegment = %q, want the envelope's channel_id", res.ChannelSegment)
	}
}
