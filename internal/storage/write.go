package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/meinside/mesh-brokerd/internal/decode"
)

// InsertRawFrame writes one raw_frames row from a decode.Result plus
// the metadata only the broker/storage layer knows (mqtt username,
// resolved board id, the payload bytes as received). This is called
// unconditionally, before any retry/normalization, per the
// raw-frame-first principle (docs/architecture.md §3, ADR-3/ADR-4) —
// callers must insert this row regardless of res.Status.
//
// It returns the new row's id, needed to link a decoded row (e.g.
// InsertTextMessage) back to its raw frame.
func (s *Store) InsertRawFrame(res *decode.Result, mqttUsername, boardID string, payload []byte, receivedAt time.Time) (int64, error) {
	var gatewayID, nodeSegment sql.NullString
	if res.GatewayID != "" {
		gatewayID = sql.NullString{String: res.GatewayID, Valid: true}
	}
	if res.NodeSegment != "" {
		nodeSegment = sql.NullString{String: res.NodeSegment, Valid: true}
	}

	var packetID, fromNode, toNode sql.NullInt64
	if res.PacketParsed {
		packetID = sql.NullInt64{Int64: int64(res.PacketID), Valid: true}
		fromNode = sql.NullInt64{Int64: int64(res.FromNode), Valid: true}
		toNode = sql.NullInt64{Int64: int64(res.ToNode), Valid: true}
	}

	f := newFrameFields(res)

	result, err := s.db.Exec(
		`INSERT INTO raw_frames
			(received_at, topic, mqtt_username, board_id, channel_segment,
			 node_segment, gateway_id, packet_id, from_node, to_node,
			 payload, decode_status, decode_version,
			 rx_snr, rx_rssi, rx_time, hop_limit, hop_start, want_ack,
			 via_mqtt, priority, relay_node,
			 portnum, portnum_name, want_response, dest_node, source_node,
			 request_id, reply_id, bitfield)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
		         ?, ?, ?, ?, ?, ?, ?, ?, ?,
		         ?, ?, ?, ?, ?, ?, ?, ?);`,
		receivedAt.UTC().Format(time.RFC3339),
		res.Topic,
		mqttUsername,
		boardID,
		res.ChannelSegment,
		nodeSegment,
		gatewayID,
		packetID,
		fromNode,
		toNode,
		payload,
		string(res.Status),
		DecodeVersion,
		f.RxSnr, f.RxRssi, f.RxTime, f.HopLimit, f.HopStart, f.WantAck,
		f.ViaMqtt, f.Priority, f.RelayNode,
		f.Portnum, f.PortnumName, f.WantResponse, f.DestNode, f.SourceNode,
		f.RequestID, f.ReplyID, f.Bitfield,
	)
	if err != nil {
		return 0, fmt.Errorf("storage: inserting raw_frames row: %w", err)
	}
	return result.LastInsertId()
}

// InsertTextMessage writes one text_messages row derived from a
// decoded TEXT_MESSAGE_APP raw frame (docs/storage-schema.md §2).
// channelName is the resolved channel name from brokerd's config (may
// be empty if not yet resolved); receivedAt is the raw frame's
// received_at when the packet itself carries no timestamp field
// (Meshtastic's MeshPacket does not, in the fields brokerd parses).
func (s *Store) InsertTextMessage(rawFrameID int64, res *decode.Result, channelName string, receivedAt time.Time) (int64, error) {
	if res.TextMessage == nil {
		return 0, fmt.Errorf("storage: InsertTextMessage called without a decoded TextMessage")
	}

	var toNode sql.NullInt64
	if res.ToNode != 0 {
		toNode = sql.NullInt64{Int64: int64(res.ToNode), Valid: true}
	}
	var channelNameVal sql.NullString
	if channelName != "" {
		channelNameVal = sql.NullString{String: channelName, Valid: true}
	}

	result, err := s.db.Exec(
		`INSERT INTO text_messages
			(raw_frame_id, portnum, channel_name, from_node, to_node, received_at, text, decode_version)
		 VALUES (?, 'TEXT_MESSAGE_APP', ?, ?, ?, ?, ?, ?);`,
		rawFrameID,
		channelNameVal,
		res.FromNode,
		toNode,
		receivedAt.UTC().Format(time.RFC3339),
		res.TextMessage.Text,
		DecodeVersion,
	)
	if err != nil {
		return 0, fmt.Errorf("storage: inserting text_messages row: %w", err)
	}
	return result.LastInsertId()
}

// InsertDecodedPayload writes one decoded_payloads row: whatever a portnum
// decoder understood, as JSON (docs/storage-schema.md §2.1). Returns
// (0, nil) when this result has no interpreted payload -- an unhandled
// portnum is not an error, and raw_frames already holds its bytes (ADR-4).
func (s *Store) InsertDecodedPayload(rawFrameID int64, res *decode.Result) (int64, error) {
	ok, encoded, err := encodeDecodedFields(res)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, nil
	}

	result, err := s.db.Exec(
		`INSERT INTO decoded_payloads
			(raw_frame_id, portnum, portnum_name, fields, decode_version)
		 VALUES (?, ?, ?, ?, ?);`,
		rawFrameID,
		int64(res.Portnum),
		res.Portnum.Name(),
		string(encoded),
		DecodeVersion,
	)
	if err != nil {
		return 0, fmt.Errorf("storage: inserting decoded_payloads row: %w", err)
	}
	return result.LastInsertId()
}

// nullInt64NonZero stores 0 as NULL, for fields the firmware omits when
// unset: protobuf does not transmit a zero-valued scalar, so a parsed 0 and
// an absent field are indistinguishable and must not be recorded as a
// measured value.
func nullInt64NonZero(v int64) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: v, Valid: true}
}

func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// frameFields holds every raw_frames column derived from a decode result,
// with SQL NULL standing for "the frame did not state this" (ADR-15).
//
// One struct rather than two lists of locals because both the insert path
// and the reprocessing path (reprocess.go) write these columns: two copies
// of the null rules would drift, and the drift would look like real data.
type frameFields struct {
	RxSnr     sql.NullFloat64
	RxRssi    sql.NullInt64
	RxTime    sql.NullInt64
	HopLimit  sql.NullInt64
	HopStart  sql.NullInt64
	WantAck   sql.NullBool
	ViaMqtt   sql.NullBool
	Priority  sql.NullInt64
	RelayNode sql.NullInt64

	Portnum      sql.NullInt64
	PortnumName  sql.NullString
	WantResponse sql.NullInt64
	DestNode     sql.NullInt64
	SourceNode   sql.NullInt64
	RequestID    sql.NullInt64
	ReplyID      sql.NullInt64
	Bitfield     sql.NullInt64
}

func newFrameFields(res *decode.Result) frameFields {
	var f frameFields

	if res.HasRxSnr {
		f.RxSnr = sql.NullFloat64{Float64: float64(res.RxSnr), Valid: true}
	}
	if res.HasRxRssi {
		f.RxRssi = sql.NullInt64{Int64: int64(res.RxRssi), Valid: true}
	}
	if res.PacketParsed {
		f.RxTime = nullInt64NonZero(int64(res.RxTime))
		f.HopLimit = sql.NullInt64{Int64: int64(res.HopLimit), Valid: true}
		f.HopStart = nullInt64NonZero(int64(res.HopStart))
		f.Priority = nullInt64NonZero(int64(res.Priority))
		f.RelayNode = nullInt64NonZero(int64(res.RelayNode))
		f.WantAck = sql.NullBool{Bool: res.WantAck, Valid: true}
		f.ViaMqtt = sql.NullBool{Bool: res.ViaMqtt, Valid: true}
	}

	// The Data fields exist only once the payload was plaintext. Anything
	// short of that (unknown channel, decrypt failure, PKI-encrypted DM)
	// leaves them NULL rather than 0.
	switch res.Status {
	case decode.StatusDecoded, decode.StatusUnhandledPortnum, decode.StatusDuplicate:
		if res.Portnum != 0 {
			f.Portnum = sql.NullInt64{Int64: int64(res.Portnum), Valid: true}
			f.PortnumName = sql.NullString{String: res.Portnum.Name(), Valid: true}
		}
		f.WantResponse = sql.NullInt64{Int64: boolToInt64(res.WantResponse), Valid: true}
		f.DestNode = nullInt64NonZero(int64(res.Dest))
		f.SourceNode = nullInt64NonZero(int64(res.Source))
		f.RequestID = nullInt64NonZero(int64(res.RequestID))
		f.ReplyID = nullInt64NonZero(int64(res.ReplyID))
		if res.HasBitfield {
			f.Bitfield = sql.NullInt64{Int64: int64(res.Bitfield), Valid: true}
		}
	}

	return f
}

// reprocessedColumns is the argument list for reprocess.go's UPDATE, in the
// order that statement names its columns.
func reprocessedColumns(res *decode.Result) []any {
	f := newFrameFields(res)
	return []any{
		string(res.Status), DecodeVersion,
		f.RxSnr, f.RxRssi, f.RxTime, f.HopLimit, f.HopStart,
		f.WantAck, f.ViaMqtt, f.Priority, f.RelayNode,
		f.Portnum, f.PortnumName, f.WantResponse,
		f.DestNode, f.SourceNode, f.RequestID, f.ReplyID, f.Bitfield,
	}
}

// encodeDecodedFields renders a decoded payload for storage. ok is false
// when this portnum has no interpreter.
func encodeDecodedFields(res *decode.Result) (ok bool, encoded string, err error) {
	fields, ok := res.DecodedFields()
	if !ok {
		return false, "", nil
	}
	b, err := json.Marshal(fields)
	if err != nil {
		return false, "", fmt.Errorf("storage: encoding decoded payload fields: %w", err)
	}
	return true, string(b), nil
}
