package decode

import "testing"

func TestDecodePosition_WithFix(t *testing.T) {
	// latitude_i=407128000 (~40.7128 deg), longitude_i=-740060000 (~-74.006 deg),
	// precision_bits=16.
	payload := EncodePosition(Position{
		HasLatLon:        true,
		LatitudeI:        407128000,
		LongitudeI:       -740060000,
		HasPrecisionBits: true,
		PrecisionBits:    16,
	})

	res := &Result{}
	if err := decodePosition(res, payload); err != nil {
		t.Fatalf("decodePosition: %v", err)
	}
	if !res.Position.HasLatLon {
		t.Fatal("HasLatLon = false, want true")
	}
	if res.Position.LatitudeI != 407128000 || res.Position.LongitudeI != -740060000 {
		t.Errorf("lat/lon = %d/%d, want 407128000/-740060000", res.Position.LatitudeI, res.Position.LongitudeI)
	}
	if !res.Position.HasPrecisionBits || res.Position.PrecisionBits != 16 {
		t.Errorf("PrecisionBits = %d (has=%v), want 16 (has=true)", res.Position.PrecisionBits, res.Position.HasPrecisionBits)
	}
}

func TestDecodePosition_NoFix(t *testing.T) {
	// A no-fix broadcast: no lat/lon at all, per docs/outbound-relay.md.
	payload := EncodePosition(Position{HasPrecisionBits: true, PrecisionBits: 16})

	res := &Result{}
	if err := decodePosition(res, payload); err != nil {
		t.Fatalf("decodePosition: %v", err)
	}
	if res.Position.HasLatLon {
		t.Error("HasLatLon = true for a no-fix broadcast, want false")
	}
}

func TestEncodeDecodeRoundTrip_FullPipeline(t *testing.T) {
	// Build a plaintext (already-decoded style) ServiceEnvelope end to
	// end using the encode helpers, then run it back through Decode to
	// confirm the encoder/decoder pair agree with each other.
	posPayload := EncodePosition(Position{HasLatLon: true, LatitudeI: 1, LongitudeI: 2, HasPrecisionBits: true, PrecisionBits: 12})
	data := EncodeData(PortNumPosition, posPayload)
	mpDecoded := EncodeMeshPacketDecoded(0xaabbccdd, 0xffffffff, 99, data)
	envelope := EncodeServiceEnvelope(mpDecoded, "pvt", "!aabbccdd")

	res, err := Decode("msh/pvt/2/e/pvt/!aabbccdd", envelope, map[string][PSKSize]byte{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.Status != StatusDecoded {
		t.Fatalf("Status = %s, want %s", res.Status, StatusDecoded)
	}
	if res.Position == nil || !res.Position.HasLatLon || res.Position.PrecisionBits != 12 {
		t.Errorf("Position = %+v, want HasLatLon=true PrecisionBits=12", res.Position)
	}
}
