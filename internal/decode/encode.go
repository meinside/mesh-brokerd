package decode

import "encoding/binary"

// The functions below build protobuf wire bytes for the same
// ServiceEnvelope/MeshPacket/Data shapes envelope.go parses -- used by
// the selective outbound relay (docs/outbound-relay.md section 5,
// ADR-12) to construct a new packet for the target broker. Kept as a
// hand-written encoder, mirroring the hand-written decoder, per
// ADR-13.

func appendVarint(b []byte, v uint64) []byte { return binary.AppendUvarint(b, v) }

func appendTag(b []byte, fieldNum, wireType int) []byte {
	return appendVarint(b, uint64(fieldNum<<3|wireType))
}

func appendVarintField(b []byte, fieldNum int, v uint64) []byte {
	b = appendTag(b, fieldNum, wireVarint)
	return appendVarint(b, v)
}

func appendBytesField(b []byte, fieldNum int, data []byte) []byte {
	b = appendTag(b, fieldNum, wireBytes)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

func appendFixed32Field(b []byte, fieldNum int, v uint32) []byte {
	b = appendTag(b, fieldNum, wireFixed32)
	return binary.LittleEndian.AppendUint32(b, v)
}

// EncodeData builds a plaintext Data message (portnum + payload).
func EncodeData(portnum PortNum, payload []byte) []byte {
	var b []byte
	b = appendVarintField(b, feDataPortnum, uint64(portnum))
	b = appendBytesField(b, feDataPayload, payload)
	return b
}

// EncodePosition builds a Position message carrying only latitude_i,
// longitude_i, and precision_bits -- the fields the outbound relay
// forwards verbatim from the source packet (docs/outbound-relay.md
// section 5: "relayed as-is, never re-synthesized").
func EncodePosition(pos Position) []byte {
	var b []byte
	if pos.HasLatLon {
		b = appendFixed32Field(b, fePositionLatitudeI, uint32(pos.LatitudeI))
		b = appendFixed32Field(b, fePositionLongitudeI, uint32(pos.LongitudeI))
	}
	if pos.HasPrecisionBits {
		b = appendVarintField(b, fePositionPrecisionBits, uint64(pos.PrecisionBits))
	}
	return b
}

// EncodeMeshPacket builds a MeshPacket carrying already-encrypted bytes
// in its Encrypted (oneof) field, plus id/from/to and the channel hash.
// from/to/id are fixed32 on the wire, not varints; channel is a varint
// (see envelope.go's field table).
//
// channelHash must be decode.ChannelHash(channelName, psk) for the
// channel this packet is being published on. It is not optional in
// practice: consumers that filter on the hash rather than the topic
// string will reject a packet whose hash is zero/wrong
// (docs/outbound-relay.md section 5).
// MeshPacketFields describes one MeshPacket to encode.
//
// The optional fields exist because real gateway-uplinked traffic always
// carries them, and a packet without them is not equivalent: an absent
// hop_limit reads as zero ("no hops left") rather than "unspecified", and an
// absent rx_time gives a consumer no observation time. brokerd's outbound
// relay copies them from the source packet rather than inventing values
// (docs/outbound-relay.md §5). Field structure verified against a real
// capture in TestEncodeMeshPacket_MatchesRealGatewayFieldSet.
type MeshPacketFields struct {
	From        uint32
	To          uint32
	ID          uint32
	ChannelHash byte
	Encrypted   []byte

	// Optional: written only when non-zero, so "unset" stays distinct from
	// an explicit zero on the wire.
	RxTime    uint32
	HopLimit  uint32
	HopStart  uint32
	Priority  uint32
	RelayNode uint32
}

func EncodeMeshPacket(f MeshPacketFields) []byte {
	var b []byte
	b = appendFixed32Field(b, feMeshPacketFrom, f.From)
	b = appendFixed32Field(b, feMeshPacketTo, f.To)
	b = appendVarintField(b, feMeshPacketChannel, uint64(f.ChannelHash))
	b = appendFixed32Field(b, feMeshPacketID, f.ID)
	b = appendBytesField(b, feMeshPacketEncrypted, f.Encrypted)
	if f.RxTime != 0 {
		b = appendFixed32Field(b, feMeshPacketRxTime, f.RxTime)
	}
	if f.HopLimit != 0 {
		b = appendVarintField(b, feMeshPacketHopLimit, uint64(f.HopLimit))
	}
	if f.Priority != 0 {
		b = appendVarintField(b, feMeshPacketPriority, uint64(f.Priority))
	}
	if f.HopStart != 0 {
		b = appendVarintField(b, feMeshPacketHopStart, uint64(f.HopStart))
	}
	if f.RelayNode != 0 {
		b = appendVarintField(b, feMeshPacketRelayNode, uint64(f.RelayNode))
	}
	return b
}

// EncodeMeshPacketDecoded builds a MeshPacket carrying an already
// plaintext Data message in its Decoded (oneof) field -- the
// PKC/public-packet variant (docs/protocol-spec.md section 2).
//
// No channel hash is written: this variant exists to synthesize
// plaintext packets for tests, and brokerd never publishes one (its own
// outbound path always encrypts, EncodeMeshPacket above).
func EncodeMeshPacketDecoded(from, to, id uint32, data []byte) []byte {
	var b []byte
	b = appendFixed32Field(b, feMeshPacketFrom, from)
	b = appendFixed32Field(b, feMeshPacketTo, to)
	b = appendFixed32Field(b, feMeshPacketID, id)
	b = appendBytesField(b, feMeshPacketDecoded, data)
	return b
}

// EncodeServiceEnvelope builds the top-level MQTT payload.
func EncodeServiceEnvelope(packet []byte, channelID, gatewayID string) []byte {
	var b []byte
	b = appendBytesField(b, feServiceEnvelopePacket, packet)
	b = appendBytesField(b, feServiceEnvelopeChannelID, []byte(channelID))
	b = appendBytesField(b, feServiceEnvelopeGatewayID, []byte(gatewayID))
	return b
}

// EncodeMeshPacketDecodedFields encodes a MeshPacket carrying a plaintext
// Data payload, keeping the same optional envelope fields as the encrypted
// form. Used for map reports, which the firmware always publishes
// unencrypted (docs/outbound-relay.md §10.1).
func EncodeMeshPacketDecodedFields(f MeshPacketFields, data []byte) []byte {
	var b []byte
	b = appendFixed32Field(b, feMeshPacketFrom, f.From)
	b = appendFixed32Field(b, feMeshPacketTo, f.To)
	b = appendVarintField(b, feMeshPacketChannel, uint64(f.ChannelHash))
	if f.ID != 0 {
		b = appendFixed32Field(b, feMeshPacketID, f.ID)
	}
	b = appendBytesField(b, feMeshPacketDecoded, data)
	if f.RxTime != 0 {
		b = appendFixed32Field(b, feMeshPacketRxTime, f.RxTime)
	}
	if f.HopLimit != 0 {
		b = appendVarintField(b, feMeshPacketHopLimit, uint64(f.HopLimit))
	}
	if f.Priority != 0 {
		b = appendVarintField(b, feMeshPacketPriority, uint64(f.Priority))
	}
	if f.HopStart != 0 {
		b = appendVarintField(b, feMeshPacketHopStart, uint64(f.HopStart))
	}
	if f.RelayNode != 0 {
		b = appendVarintField(b, feMeshPacketRelayNode, uint64(f.RelayNode))
	}
	return b
}
