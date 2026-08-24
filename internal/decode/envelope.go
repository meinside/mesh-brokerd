package decode

import (
	"fmt"
	"math"
)

// Field numbers below are documented directly against
// docs/protocol-spec.md §2 (confirmed against real captured traffic,
// testdata/) — never generated from meshtastic/protobufs (ADR-13).
// Only the fields brokerd actually needs are parsed; anything else in
// the real messages is simply skipped by parsePBFields's generic walk.

// ServiceEnvelope field numbers.
const (
	feServiceEnvelopePacket    = 1 // MeshPacket, embedded message
	feServiceEnvelopeChannelID = 2 // string
	feServiceEnvelopeGatewayID = 3 // string
)

// MeshPacket field numbers and wire types, confirmed directly against
// the public mesh.proto schema (a protocol fact, never generated from
// meshtastic/protobufs -- ADR-13). Note that from/to/id are `fixed32`,
// NOT varint-encoded uint32, and that `decoded` is field 4 while
// `encrypted` is field 5 -- they are easy to transpose, and an earlier
// version of this file had them swapped, which only real-hardware
// integration testing caught (a symmetric encoder/decoder bug agrees
// with itself in unit tests).
const (
	feMeshPacketFrom         = 1  // fixed32
	feMeshPacketTo           = 2  // fixed32
	feMeshPacketChannel      = 3  // uint32 varint (channel *hash*, not used for PSK lookup)
	feMeshPacketDecoded      = 4  // Data, embedded message (plaintext variant)
	feMeshPacketEncrypted    = 5  // bytes (ciphertext variant)
	feMeshPacketID           = 6  // fixed32 (packet id, used in nonce derivation + dedup)
	feMeshPacketRxTime       = 7  // fixed32 (gateway's observation time)
	feMeshPacketRxSnr        = 8  // float, i.e. wire type fixed32 -- NOT a varint
	feMeshPacketHopLimit     = 9  // uint32 varint
	feMeshPacketWantAck      = 10 // bool varint
	feMeshPacketRxRssi       = 12 // int32 varint, negative in practice
	feMeshPacketViaMqtt      = 14 // bool varint
	feMeshPacketPriority     = 11 // uint32 varint
	feMeshPacketRelayNode    = 19 // uint32 varint
	feMeshPacketHopStart     = 15 // uint32 varint
	feMeshPacketPKIEncrypted = 17 // bool varint, reserved-channel DM signal
)

// Data field numbers (the decrypted/decoded payload).
const (
	feDataPortnum      = 1 // PortNum enum (varint)
	feDataPayload      = 2 // bytes, portnum-specific
	feDataWantResponse = 3 // bool varint
	feDataDest         = 4 // fixed32
	feDataSource       = 5 // fixed32
	feDataRequestID    = 6 // fixed32
	feDataReplyID      = 7 // fixed32 -- NOT bitfield, which is field 9
	feDataBitfield     = 9 // uint32 varint (OK_TO_MQTT bit 0, WANT_RESPONSE bit 1)
)

// ServiceEnvelope is the top-level MQTT payload structure.
type ServiceEnvelope struct {
	PacketBytes []byte // raw embedded MeshPacket bytes, parsed separately
	ChannelID   string
	GatewayID   string
}

// ParseServiceEnvelope parses the raw MQTT payload bytes into a
// ServiceEnvelope. It does not recurse into MeshPacket; callers parse
// PacketBytes via ParseMeshPacket once channel routing has already been
// decided against ChannelID (docs/protocol-spec.md §2).
func ParseServiceEnvelope(payload []byte) (*ServiceEnvelope, error) {
	fields, err := parsePBFields(payload)
	if err != nil {
		return nil, fmt.Errorf("decode: ServiceEnvelope: %w", err)
	}

	env := &ServiceEnvelope{}
	if f, ok := lastField(fields, feServiceEnvelopePacket); ok {
		env.PacketBytes = f.Bytes
	} else {
		return nil, fmt.Errorf("decode: ServiceEnvelope: missing packet field (%d)", feServiceEnvelopePacket)
	}
	if f, ok := lastField(fields, feServiceEnvelopeChannelID); ok {
		env.ChannelID = string(f.Bytes)
	}
	if f, ok := lastField(fields, feServiceEnvelopeGatewayID); ok {
		env.GatewayID = string(f.Bytes)
	}
	return env, nil
}

// MeshPacket is the packet embedded in a ServiceEnvelope.
type MeshPacket struct {
	From         uint32
	To           uint32
	ID           uint32
	Channel      uint32 // channel *hash*, not the name -- see ChannelHash
	HopLimit     uint32
	HopStart     uint32
	PKIEncrypted bool

	// Carried so the outbound relay can reproduce the field set real
	// gateway traffic has instead of a reduced one
	// (docs/outbound-relay.md §5, TestEncodeMeshPacket_MatchesRealGatewayFieldSet).
	RxTime    uint32
	Priority  uint32
	RelayNode uint32

	// Reception quality as the *gateway* measured it, and the transport
	// flags that say how the packet got there. Only meaningful for a packet
	// the gateway heard over RF: a packet the gateway generated itself
	// carries neither, which is why HasRxSnr/HasRxRssi exist -- an absent
	// field and a measured 0 dB are different facts (ADR-15).
	RxSnr    float32
	HasRxSnr bool
	// RxRssi is signed: real values are negative (e.g. -98 dBm).
	RxRssi    int32
	HasRxRssi bool
	WantAck   bool
	ViaMqtt   bool

	// Exactly one of Encrypted/Decoded is populated, matching the
	// firmware's oneof payload_variant.
	Encrypted []byte // ciphertext; decrypt with the channel PSK (crypto.go)
	Decoded   []byte // raw Data bytes, already plaintext (PKC/public packets)
}

// ParseMeshPacket parses the embedded MeshPacket bytes from a
// ServiceEnvelope.
func ParseMeshPacket(b []byte) (*MeshPacket, error) {
	fields, err := parsePBFields(b)
	if err != nil {
		return nil, fmt.Errorf("decode: MeshPacket: %w", err)
	}

	mp := &MeshPacket{}
	if f, ok := lastField(fields, feMeshPacketFrom); ok {
		mp.From = f.Fixed32
	}
	if f, ok := lastField(fields, feMeshPacketTo); ok {
		mp.To = f.Fixed32
	}
	if f, ok := lastField(fields, feMeshPacketID); ok {
		mp.ID = f.Fixed32
	}
	if f, ok := lastField(fields, feMeshPacketChannel); ok {
		mp.Channel = uint32(f.Varint)
	}
	if f, ok := lastField(fields, feMeshPacketHopLimit); ok {
		mp.HopLimit = uint32(f.Varint)
	}
	if f, ok := lastField(fields, feMeshPacketHopStart); ok {
		mp.HopStart = uint32(f.Varint)
	}
	if f, ok := lastField(fields, feMeshPacketRxTime); ok {
		mp.RxTime = f.Fixed32
	}
	if f, ok := lastField(fields, feMeshPacketRxSnr); ok {
		// float on the wire: fixed32 bits, not a varint. Reading this as a
		// varint is the exact mistake that once shipped for from/to/id.
		mp.RxSnr = math.Float32frombits(f.Fixed32)
		mp.HasRxSnr = true
	}
	if f, ok := lastField(fields, feMeshPacketWantAck); ok {
		mp.WantAck = f.Varint != 0
	}
	if f, ok := lastField(fields, feMeshPacketRxRssi); ok {
		// int32: protobuf encodes a negative value as its 64-bit two's
		// complement, so truncating to uint32 first is what recovers the sign.
		mp.RxRssi = int32(uint32(f.Varint))
		mp.HasRxRssi = true
	}
	if f, ok := lastField(fields, feMeshPacketViaMqtt); ok {
		mp.ViaMqtt = f.Varint != 0
	}
	if f, ok := lastField(fields, feMeshPacketPriority); ok {
		mp.Priority = uint32(f.Varint)
	}
	if f, ok := lastField(fields, feMeshPacketRelayNode); ok {
		mp.RelayNode = uint32(f.Varint)
	}
	if f, ok := lastField(fields, feMeshPacketPKIEncrypted); ok {
		mp.PKIEncrypted = f.Varint != 0
	}
	if f, ok := lastField(fields, feMeshPacketEncrypted); ok {
		mp.Encrypted = f.Bytes
	}
	if f, ok := lastField(fields, feMeshPacketDecoded); ok {
		mp.Decoded = f.Bytes
	}
	return mp, nil
}

// Data is the decrypted/decoded payload inside a MeshPacket.
type Data struct {
	Portnum uint32
	Payload []byte

	// Everything else the Data message can carry. brokerd stores all of it
	// (ADR-15): request_id/reply_id are what makes a reply attributable to
	// the message it answers, and bitfield's bit 0 (OK_TO_MQTT) decides
	// whether a *stranger's* gateway may uplink this packet at all.
	WantResponse bool
	Dest         uint32
	Source       uint32
	RequestID    uint32
	ReplyID      uint32
	Bitfield     uint32
	HasBitfield  bool
}

// ParseData parses plaintext Data bytes (post-decryption, or already
// plaintext for PKC/public packets).
func ParseData(b []byte) (*Data, error) {
	fields, err := parsePBFields(b)
	if err != nil {
		return nil, fmt.Errorf("decode: Data: %w", err)
	}

	d := &Data{}
	if f, ok := lastField(fields, feDataPortnum); ok {
		d.Portnum = uint32(f.Varint)
	}
	if f, ok := lastField(fields, feDataPayload); ok {
		d.Payload = f.Bytes
	}
	if f, ok := lastField(fields, feDataWantResponse); ok {
		d.WantResponse = f.Varint != 0
	}
	if f, ok := lastField(fields, feDataDest); ok {
		d.Dest = f.Fixed32
	}
	if f, ok := lastField(fields, feDataSource); ok {
		d.Source = f.Fixed32
	}
	if f, ok := lastField(fields, feDataRequestID); ok {
		d.RequestID = f.Fixed32
	}
	if f, ok := lastField(fields, feDataReplyID); ok {
		d.ReplyID = f.Fixed32
	}
	if f, ok := lastField(fields, feDataBitfield); ok {
		d.Bitfield = uint32(f.Varint)
		d.HasBitfield = true
	}
	return d, nil
}

// IsPKIEncrypted reports whether a ServiceEnvelope/MeshPacket pair
// carries a direct message that brokerd cannot decode
// (docs/protocol-spec.md §3): either signal is sufficient alone.
func IsPKIEncrypted(env *ServiceEnvelope, mp *MeshPacket) bool {
	return env.ChannelID == "PKI" || mp.PKIEncrypted
}
