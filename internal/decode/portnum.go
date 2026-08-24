package decode

import "fmt"

import "strconv"

// PortNum identifies which decoder a Data payload should be dispatched
// to (docs/protocol-spec.md §4). Values match the wire-level portnum
// numbers used by the Meshtastic protocol itself — these are protocol
// facts (also documented throughout meshtastic.org's own docs), not
// anything copied from meshtastic/protobufs' generated code (ADR-13).
type PortNum uint32

const (
	PortNumTextMessage  PortNum = 1
	PortNumPosition     PortNum = 3
	PortNumNodeInfo     PortNum = 4
	PortNumRouting      PortNum = 5
	PortNumTelemetry    PortNum = 67
	PortNumNeighborInfo PortNum = 71
	PortNumMapReport    PortNum = 73
)

// portnumNames are the names stored alongside a decoded payload
// (decoded_payloads.portnum_name) so a stored row is readable without
// this table. A portnum with no name here is stored numerically.
var portnumNames = map[PortNum]string{
	PortNumTextMessage:  "TEXT_MESSAGE_APP",
	PortNumPosition:     "POSITION_APP",
	PortNumNodeInfo:     "NODEINFO_APP",
	PortNumRouting:      "ROUTING_APP",
	PortNumTelemetry:    "TELEMETRY_APP",
	PortNumNeighborInfo: "NEIGHBORINFO_APP",
	PortNumMapReport:    "MAP_REPORT_APP",
}

// Name returns the portnum's Meshtastic name, or a decimal string for one
// this package does not name.
func (p PortNum) Name() string {
	if n, ok := portnumNames[p]; ok {
		return n
	}
	return "PORTNUM_" + strconv.FormatUint(uint64(p), 10)
}

// decodeFunc decodes a Data.payload for one portnum, filling in the
// portnum-specific field(s) on res. Returning an error means the bytes
// didn't parse as expected for this portnum (folded into
// decode_status = decrypt_failed per docs/storage-schema.md §1's
// combined "decryption/parse failed" bucket).
type decodeFunc func(res *Result, payload []byte) error

// portnumRegistry is the pluggable per-portnum decoder table
// (docs/architecture.md §10.3, docs/protocol-spec.md §4). A portnum
// with no registered decoder here is not an error — it is stored as
// decode_status = unhandled_portnum, distinct from an actual parse
// failure (ADR-4).
var portnumRegistry = map[PortNum]decodeFunc{
	PortNumTextMessage: decodeTextMessage,
	PortNumPosition:    decodePosition,
	PortNumNodeInfo:    decodeNodeInfo,
	PortNumTelemetry:   decodeTelemetry,
	PortNumRouting:     decodeRouting,
	// A map report is published as plaintext with no channel segment and is
	// republished verbatim by the outbound relay, so nothing needs its
	// fields parsed (docs/outbound-relay.md §10.1). Registering it keeps it
	// out of decode_failures_by_reason's unhandled_portnum bucket, where it
	// otherwise looked like a decoding defect rather than traffic brokerd
	// deliberately passes through.
	PortNumMapReport: decodeOpaque,
}

// TextMessage is the decoded payload of a TEXT_MESSAGE_APP packet
// (docs/storage-schema.md §2's text_messages table).
type TextMessage struct {
	Text string
}

// decodeTextMessage implements PortNumTextMessage: the payload is the
// message body as UTF-8 text, verbatim — no further structure.
func decodeTextMessage(res *Result, payload []byte) error {
	res.TextMessage = &TextMessage{Text: string(payload)}
	return nil
}

// decodeOpaque accepts a payload without interpreting it. Result.RawPayload
// already carries the bytes for anything that needs them.
func decodeOpaque(res *Result, payload []byte) error { return nil }

// NodeIDString renders a node number the way Meshtastic writes it everywhere
// else: eight lowercase hex digits behind a bang. One formatter, so a node id
// in a log line, on the monitoring page and in a hook payload are the same
// string and can be grepped for as one.
func NodeIDString(id uint32) string {
	return fmt.Sprintf("!%08x", id)
}

// FormatNodeName renders what a node calls itself for a reader: the long name
// with the short name after it, since the short name is what the node's own
// screen and the phone app show. Either may be missing, and when both are the
// result is empty -- a node id is not a name and callers render the two
// separately (docs/monitoring-api.md §4.9).
//
//	"Some Node (SOME)"   both stated
//	"Some Node"          long only
//	"SOME"               short only
//	""                   neither
//
// One formatter for every surface: the monitoring page and a hook payload
// disagreeing about how a node is written is the kind of difference that makes
// two reports of the same event look like two events.
func FormatNodeName(long, short string) string {
	switch {
	case long != "" && short != "":
		return long + " (" + short + ")"
	case long != "":
		return long
	default:
		return short
	}
}
