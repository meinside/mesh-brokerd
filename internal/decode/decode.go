package decode

// Status is one raw_frames.decode_status value
// (docs/storage-schema.md §1).
type Status string

const (
	StatusDecoded          Status = "decoded"
	StatusDuplicate        Status = "duplicate"
	StatusUnknownChannel   Status = "unknown_channel"
	StatusDecryptFailed    Status = "decrypt_failed"
	StatusPKIEncrypted     Status = "pki_encrypted"
	StatusUnhandledPortnum Status = "unhandled_portnum"
)

// Result is what Decode produces for one MQTT message: everything
// internal/storage needs to write a raw_frames row, plus an optional
// decoded payload when Status == StatusDecoded.
type Result struct {
	Topic          string
	ChannelSegment string
	NodeSegment    string
	GatewayID      string
	PacketID       uint32
	FromNode       uint32
	ToNode         uint32

	// Envelope fields carried through so the outbound relay can rebuild a
	// packet with the same field set real gateway traffic has, copying
	// rather than inventing values (docs/outbound-relay.md §5).
	RxTime    uint32
	HopLimit  uint32
	HopStart  uint32
	Priority  uint32
	RelayNode uint32

	// Reception quality and transport flags, recorded because nothing else
	// in the pipeline carries them and they cannot be reconstructed later
	// (ADR-15). Has* distinguishes "the packet did not state this" from a
	// measured zero -- a gateway's own packet states neither.
	RxSnr     float32
	HasRxSnr  bool
	RxRssi    int32
	HasRxRssi bool
	WantAck   bool
	ViaMqtt   bool

	// Data-level fields, populated once the payload is plaintext.
	WantResponse bool
	Dest         uint32
	Source       uint32
	RequestID    uint32
	ReplyID      uint32
	Bitfield     uint32
	HasBitfield  bool

	Status  Status
	Portnum PortNum

	// RawPayload is the decrypted Data.payload exactly as it arrived, for
	// every portnum -- including ones this package has no parser for. The
	// outbound relay re-publishes these bytes verbatim rather than
	// re-encoding from a parsed struct, so fields this decoder does not
	// model (a Position's time, altitude and location_source, for
	// instance) survive the relay (docs/outbound-relay.md §5).
	RawPayload []byte

	// Populated iff Status == StatusDecoded and Portnum has a matching
	// field below (docs/protocol-spec.md section 4's decoder table).
	TextMessage *TextMessage
	Position    *Position
	NodeInfo    *NodeInfo
	Telemetry   *Telemetry
	Routing     *Routing

	// PacketParsed reports whether PacketID/FromNode/ToNode/GatewayID
	// were actually populated from a successfully parsed
	// ServiceEnvelope/MeshPacket — false when StatusDecryptFailed happened
	// before that point (e.g. a malformed envelope), so callers
	// (internal/storage) can store those columns as NULL rather than a
	// misleading 0.
	PacketParsed bool
}

// Decode parses one MQTT (topic, payload) pair through the full
// pipeline described in docs/protocol-spec.md: topic grammar ->
// ServiceEnvelope -> MeshPacket -> (channel decrypt) -> Data -> portnum
// decoder.
//
// channels maps a configured channel name (matched against the topic's
// {channel} segment, docs/protocol-spec.md §2) to its 32-byte PSK
// (docs/brokerd-config.md's channels[].psk_env, already base64-decoded
// by internal/config per ADR-11).
//
// Decode always returns a non-nil Result with Status set, except when
// the topic itself doesn't match the expected grammar at all — that
// case returns a Go error, since it means the row shouldn't have
// reached this code path (mochi-mqtt's ACL already restricts board
// accounts to msh/pvt/2/e/#, docs/security.md §3), not a protocol-level
// decode outcome to store.
func Decode(topic string, payload []byte, channels map[string][PSKSize]byte) (*Result, error) {
	t, err := ParseTopic(topic)
	if err != nil {
		return nil, err
	}

	res := &Result{
		Topic:          topic,
		ChannelSegment: t.Channel,
		NodeSegment:    t.Node,
	}

	env, err := ParseServiceEnvelope(payload)
	if err != nil {
		res.Status = StatusDecryptFailed
		return res, nil
	}
	res.GatewayID = env.GatewayID
	// A map report's topic carries no channel segment (docs/protocol-spec.md
	// §1's second grammar), so take the envelope's channel_id -- which the
	// firmware sets to the *primary* channel's name. storage's
	// channel_segment is NOT NULL, and this is the only channel identity the
	// packet actually states.
	if t.IsMapReport {
		res.ChannelSegment = env.ChannelID
	}

	mp, err := ParseMeshPacket(env.PacketBytes)
	if err != nil {
		res.Status = StatusDecryptFailed
		return res, nil
	}
	res.PacketID = mp.ID
	res.FromNode = mp.From
	res.ToNode = mp.To
	res.RxTime = mp.RxTime
	res.HopLimit = mp.HopLimit
	res.HopStart = mp.HopStart
	res.Priority = mp.Priority
	res.RelayNode = mp.RelayNode
	res.RxSnr = mp.RxSnr
	res.HasRxSnr = mp.HasRxSnr
	res.RxRssi = mp.RxRssi
	res.HasRxRssi = mp.HasRxRssi
	res.WantAck = mp.WantAck
	res.ViaMqtt = mp.ViaMqtt
	res.PacketParsed = true

	if IsPKIEncrypted(env, mp) {
		res.Status = StatusPKIEncrypted
		return res, nil
	}

	var dataBytes []byte
	switch {
	case mp.Decoded != nil:
		dataBytes = mp.Decoded
	case mp.Encrypted != nil:
		psk, ok := channels[t.Channel]
		if !ok {
			res.Status = StatusUnknownChannel
			return res, nil
		}
		plain, err := DecryptChannelPacket(psk[:], mp.ID, mp.From, mp.Encrypted)
		if err != nil {
			res.Status = StatusDecryptFailed
			return res, nil
		}
		dataBytes = plain
	default:
		// Neither payload_variant is present — malformed packet.
		res.Status = StatusDecryptFailed
		return res, nil
	}

	data, err := ParseData(dataBytes)
	if err != nil {
		res.Status = StatusDecryptFailed
		return res, nil
	}
	res.Portnum = PortNum(data.Portnum)
	res.WantResponse = data.WantResponse
	res.Dest = data.Dest
	res.Source = data.Source
	res.RequestID = data.RequestID
	res.ReplyID = data.ReplyID
	res.Bitfield = data.Bitfield
	res.HasBitfield = data.HasBitfield
	// Kept for every portnum, before the registry lookup: the relay needs
	// these bytes even for payloads this package cannot interpret.
	res.RawPayload = data.Payload

	decodeFn, ok := portnumRegistry[res.Portnum]
	if !ok {
		res.Status = StatusUnhandledPortnum
		return res, nil
	}
	if err := decodeFn(res, data.Payload); err != nil {
		res.Status = StatusDecryptFailed
		return res, nil
	}

	res.Status = StatusDecoded
	return res, nil
}
