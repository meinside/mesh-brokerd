package decode

// Position field numbers (docs/protocol-spec.md's decoder table --
// confirmed against the public mesh.proto schema's field numbers, a
// protocol fact, never generated from meshtastic/protobufs (ADR-13)).
const (
	fePositionLatitudeI     = 1  // sfixed32 -- wire type fixed32
	fePositionLongitudeI    = 2  // sfixed32 -- wire type fixed32
	fePositionPrecisionBits = 23 // uint32 -- wire type varint
)

// Position is the decoded payload of a POSITION_APP packet
// (docs/outbound-relay.md's eligibility check needs exactly these
// three fields, not a full position record).
type Position struct {
	// HasLatLon is false for a no-fix broadcast (docs/outbound-relay.md
	// section 4): Meshtastic boards broadcast position on a fixed timer
	// regardless of GPS fix, so an empty position is a normal, expected
	// message, not a decode error.
	HasLatLon  bool
	LatitudeI  int32
	LongitudeI int32

	HasPrecisionBits bool
	PrecisionBits    uint32
}

// decodePosition implements PortNumPosition.
func decodePosition(res *Result, payload []byte) error {
	fields, err := parsePBFields(payload)
	if err != nil {
		return err
	}

	pos := &Position{}
	latField, hasLat := lastField(fields, fePositionLatitudeI)
	lonField, hasLon := lastField(fields, fePositionLongitudeI)
	if hasLat && hasLon {
		pos.HasLatLon = true
		pos.LatitudeI = int32(latField.Fixed32)
		pos.LongitudeI = int32(lonField.Fixed32)
	}
	if f, ok := lastField(fields, fePositionPrecisionBits); ok {
		pos.HasPrecisionBits = true
		pos.PrecisionBits = uint32(f.Varint)
	}

	res.Position = pos
	return nil
}
