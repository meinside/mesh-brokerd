// Package hook delivers brokerd's events to configured targets: either an
// HTTPS POST or a local program (docs/event-hooks.md, ADR-17).
//
// A hook is a notification, not a delivery guarantee. The database is the
// durable record; a hook that fails is counted and dropped. Nothing here
// may block the broker's own path, so dispatch is queued with a bounded
// queue that drops its oldest entry when full (ADR-3).
package hook

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
)

// Event is what a target receives. Fields the frame did not state are
// omitted rather than sent as zero, the same rule the database follows
// (ADR-15): a consumer must not be able to read an absent measurement as
// 0 dB.
type Event struct {
	Event       string `json:"event"`
	DeliveredAt string `json:"delivered_at"`

	// Frame events.
	ReceivedAt string `json:"received_at,omitempty"`
	BoardID    string `json:"board_id,omitempty"`
	GatewayID  string `json:"gateway_id,omitempty"`
	Topic      string `json:"topic,omitempty"`
	Channel    string `json:"channel,omitempty"`
	PacketID   string `json:"packet_id,omitempty"`
	FromNode   string `json:"from,omitempty"`
	ToNode     string `json:"to,omitempty"`

	// Names a node has said about itself in a NODEINFO frame. Omitted when
	// nothing is known: a receiver must be able to tell "no name learnt yet"
	// from a node that named itself an empty string, and inventing the id as
	// a name would hide which of the two it is.
	FromLongName  string `json:"from_long_name,omitempty"`
	FromShortName string `json:"from_short_name,omitempty"`
	ToLongName    string `json:"to_long_name,omitempty"`

	// FromName is the sender as a reader knows it -- "Some Node (SOME)", the
	// long name with the short name after it -- and FromID is the node id in
	// Meshtastic's own spelling. They are separate fields on purpose: a name
	// and an id answer different questions, and a single combined string hid
	// the short name entirely while making the id look like part of the name.
	//
	// FromID is present whenever `from` is; FromName is absent for a node that
	// has never introduced itself, so `{{or .FromName .FromID}}` names the
	// sender in one expression whatever is known.
	FromName string `json:"from_name,omitempty"`
	FromID   string `json:"from_id,omitempty"`
	ToID     string `json:"to_id,omitempty"`
	ToName   string `json:"to_name,omitempty"`
	Portnum  string `json:"portnum,omitempty"`

	RxSnr    *float32 `json:"rx_snr,omitempty"`
	RxRssi   *int32   `json:"rx_rssi,omitempty"`
	HopLimit *uint32  `json:"hop_limit,omitempty"`
	HopStart *uint32  `json:"hop_start,omitempty"`
	ViaMqtt  *bool    `json:"via_mqtt,omitempty"`
	Bitfield *uint32  `json:"bitfield,omitempty"`

	// Fields is the portnum decoder's output, minus "text" unless the
	// target opted in (config.HookMatch.IncludeText).
	Fields map[string]any `json:"fields,omitempty"`

	// RawPayload is the decrypted Data.payload, base64, present only when
	// the target opted in.
	RawPayload string `json:"raw_payload,omitempty"`

	// Connection events.
	Reason string `json:"reason,omitempty"`
}

// NameResolver answers what a node has called itself. internal/storage
// implements it; a nil resolver means no names, which is what a fresh
// deployment has until the first NODEINFO frame arrives.
type NameResolver interface {
	NodeNameFor(id uint32) (long, short string, ok bool)
}

// FrameEvent builds a frame event from a decode result. boardID is the
// resolved board, receivedAt the arrival time recorded in storage.
func FrameEvent(res *decode.Result, boardID string, receivedAt time.Time) Event {
	e := Event{
		Event:      config.HookEventFrame,
		ReceivedAt: receivedAt.UTC().Format(time.RFC3339),
		BoardID:    boardID,
		GatewayID:  res.GatewayID,
		Topic:      res.Topic,
		Channel:    res.ChannelSegment,
		Portnum:    res.Portnum.Name(),
	}
	if res.PacketParsed {
		// A packet id of 0 means the packet did not state one -- MAP_REPORT_APP
		// never does -- and rendering it as 0x00000000 would offer a consumer
		// an identity the packet never had. This is the same rule the database
		// follows and that duplicate suppression depends on (ADR-14/ADR-15).
		if res.PacketID != 0 {
			e.PacketID = fmt.Sprintf("%#08x", res.PacketID)
		}
		e.FromNode = fmt.Sprintf("%#08x", res.FromNode)
		e.ToNode = fmt.Sprintf("%#08x", res.ToNode)
		// The ids are set wherever `from` is set, not only when a resolver was
		// passed: being present has to be a property of the payload, not of the
		// caller remembering a second call.
		e.FromID = decode.NodeIDString(res.FromNode)
		e.ToID = decode.NodeIDString(res.ToNode)
		// hop_limit and via_mqtt are kept even at zero/false: protobuf's
		// default is the meaningful value for them (0 hops left, not relayed
		// over MQTT). hop_start is omitted at 0 because the field is simply
		// absent from packets that do not set it, which is how storage records
		// it too.
		hopLimit, viaMqtt := res.HopLimit, res.ViaMqtt
		e.HopLimit, e.ViaMqtt = &hopLimit, &viaMqtt
		if res.HopStart != 0 {
			hopStart := res.HopStart
			e.HopStart = &hopStart
		}
	}
	if res.HasRxSnr {
		snr := res.RxSnr
		e.RxSnr = &snr
	}
	if res.HasRxRssi {
		rssi := res.RxRssi
		e.RxRssi = &rssi
	}
	if res.HasBitfield {
		bf := res.Bitfield
		e.Bitfield = &bf
	}
	if fields, ok := res.DecodedFields(); ok {
		e.Fields = fields
	}
	return e
}

// BoardEvent builds a connect/disconnect event. reason may be empty.
func BoardEvent(name, boardID, reason string) Event {
	return Event{Event: name, BoardID: boardID, Reason: reason}
}

// applyMatchOptions strips or adds the opt-in fields for one target. It
// works on a copy so one target's choices cannot affect another's -- the
// map in Fields is shared with the decode result, so it must be cloned
// before anything is deleted from it.
func (e Event) applyMatchOptions(m config.HookMatch, rawPayload []byte) Event {
	if len(e.Fields) > 0 {
		clone := make(map[string]any, len(e.Fields))
		for k, v := range e.Fields {
			if k == "text" && !m.IncludeText {
				continue
			}
			clone[k] = v
		}
		e.Fields = clone
	}
	if m.IncludeRawPayload && len(rawPayload) > 0 {
		e.RawPayload = base64.StdEncoding.EncodeToString(rawPayload)
	}
	return e
}

// JSON renders the event as the body a target receives.
func (e Event) JSON() ([]byte, error) {
	return json.Marshal(e)
}

// AttachNodeNames fills in what is known about the nodes this event names. A
// separate step from FrameEvent because names come from the database while
// everything else comes from the frame, and a caller without a database (the
// -test-hooks self test, broker tests) must still be able to build an event.
//
// A nil resolver, or a node nobody has heard a NODEINFO frame from, leaves the
// fields absent rather than filling them with the id: a receiver can then tell
// "not known" from "known to be called this".
func (e *Event) AttachNodeNames(r NameResolver, from, to uint32) {
	// The label is set even with no resolver at all: its whole purpose is to
	// be safe to interpolate, and a field that is sometimes missing would put
	// the conditional back in every template.
	// The ids do not depend on a resolver; fill them in even when there is
	// none, so a caller that only has names missing still has the node.
	e.FromID = decode.NodeIDString(from)
	if to != 0 {
		e.ToID = decode.NodeIDString(to)
	}
	if r == nil {
		return
	}
	if long, short, ok := r.NodeNameFor(from); ok {
		e.FromLongName, e.FromShortName = long, short
	}
	e.FromName = decode.FormatNodeName(e.FromLongName, e.FromShortName)
	if to != 0 && to != from {
		if long, short, ok := r.NodeNameFor(to); ok {
			e.ToLongName = long
			e.ToName = decode.FormatNodeName(long, short)
		}
	}
}
