package broker

import (
	"context"
	"log/slog"
	"sync"

	"github.com/meinside/mesh-brokerd/internal/decode"
	"github.com/meinside/mesh-brokerd/internal/hook"
	"github.com/meinside/mesh-brokerd/internal/relay"
	"github.com/meinside/mesh-brokerd/internal/storage"
)

// Worker consumes queuedMessages from a RelayHook and performs decode +
// SQLite writes off the broker's relay path (ADR-3). Both its top-level
// loop and each individual message's processing absorb panics via
// recover(), so a bug in decode/storage logic never takes down the
// broker (ADR-2/ADR-3's accepted trade-off).
type Worker struct {
	relay    *RelayHook
	store    *storage.Store
	channels map[string][decode.PSKSize]byte
	// boardIDByUsername maps an MQTT username to its configured board
	// id (docs/architecture.md §10.1 — board_id is free-form, never an
	// enum).
	boardIDByUsername map[string]string

	// nodeIDChecker cross-checks boards[].node_id against the gateway_id
	// seen in traffic. May be nil in tests.
	nodeIDChecker *NodeIDChecker

	// hooks is nil unless event_hooks is configured (ADR-17).
	hooks HookDispatcher
	// relayEngine is nil unless outbound_relay is configured at all
	// (docs/outbound-relay.md, ADR-12) — Evaluate is only called when
	// non-nil.
	relayEngine *relay.Engine
	log         *slog.Logger

	mu             sync.Mutex
	decodeFailures map[decode.Status]int64
}

// NewWorker builds a Worker. boardIDByUsername and channels are
// resolved once from internal/config at startup. relayEngine may be
// nil (outbound_relay entirely absent from behavior in that case).
func NewWorker(relayHook *RelayHook, store *storage.Store, channels map[string][decode.PSKSize]byte, boardIDByUsername map[string]string, relayEngine *relay.Engine, nodeIDChecker *NodeIDChecker, log *slog.Logger) *Worker {
	if log == nil {
		log = slog.Default()
	}
	return &Worker{
		relay:             relayHook,
		store:             store,
		channels:          channels,
		boardIDByUsername: boardIDByUsername,
		nodeIDChecker:     nodeIDChecker,
		relayEngine:       relayEngine,
		log:               log,
		decodeFailures:    make(map[decode.Status]int64),
	}
}

// Run blocks, processing messages until ctx is cancelled. A top-level
// recover() ensures a single malformed message's panic (if decode's
// own internal invariants are ever violated) logs and continues rather
// than killing the worker goroutine entirely.
func (w *Worker) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-w.relay.messages():
			if !ok {
				return
			}
			w.processOne(msg)
		}
	}
}

func (w *Worker) processOne(msg queuedMessage) {
	defer func() {
		if r := recover(); r != nil {
			w.log.Error("storage worker: recovered from panic", "topic", msg.Topic, "panic", r)
		}
	}()

	res, err := decode.Decode(msg.Topic, msg.Payload, w.channels)
	if err != nil {
		// Topic didn't match {root}/2/e/{channel}/{node} at all — per
		// decode.Decode's contract this means the row shouldn't have
		// reached this hook (ACL already restricts board accounts to
		// msh/pvt/2/e/#, docs/security.md §3). Log and drop; there's no
		// raw_frames row to write without a channel segment to key it
		// on.
		w.log.Error("storage worker: topic did not match expected grammar", "topic", msg.Topic, "error", err)
		return
	}

	boardID := w.boardIDByUsername[msg.Username]

	// The gateway_id on this frame is the publishing board's own node
	// ID, so it is the cheapest available check that config's declared
	// node_id still matches reality. Warn only -- never act on it.
	if w.nodeIDChecker != nil {
		w.nodeIDChecker.Check(boardID, res.GatewayID, w.log)
	}

	// Duplicate suppression (ADR-14, docs/protocol-spec.md section 2):
	// firmware re-delivers the same packet more than once in practice.
	// The check runs before the insert so the raw_frames row can record
	// the outcome, and it fails open -- a lookup error must never cause a
	// real message to be dropped, only (at worst) a duplicate to slip
	// through.
	//
	// Only a packet that would otherwise be StatusDecoded is re-labelled
	// StatusDuplicate: a duplicate of a *failed* packet keeps its failure
	// reason (decrypt_failed etc.), since that diagnostic is worth more
	// than the duplicate flag and no decoded row would be written either
	// way.
	isDuplicate := false
	if res.Status == decode.StatusDecoded && res.PacketParsed && res.GatewayID != "" {
		dup, err := w.store.IsDuplicate(res.GatewayID, res.PacketID, msg.Payload, msg.ReceivedAt)
		if err != nil {
			w.log.Error("storage worker: dedup lookup failed, treating as not-duplicate",
				"topic", msg.Topic, "error", err)
		} else {
			isDuplicate = dup
		}
	}
	if isDuplicate {
		res.Status = decode.StatusDuplicate
	}

	rawID, err := w.store.InsertRawFrame(res, msg.Username, boardID, msg.Payload, msg.ReceivedAt)
	if err != nil {
		w.log.Error("storage worker: inserting raw_frames failed", "topic", msg.Topic, "error", err)
		return
	}

	w.recordDecodeStatus(res.Status)

	if isDuplicate {
		// Raw frame kept (raw-frame-first, ADR-3/ADR-4) so the duplicate
		// delivery itself stays visible, but no decoded row is written and
		// no outbound relay is attempted.
		w.log.Debug("duplicate delivery suppressed",
			"topic", msg.Topic,
			"gateway_id", res.GatewayID,
			"packet_id", res.PacketID,
		)
		return
	}

	if res.Status != decode.StatusDecoded {
		// ADR-4: log every decode failure with topic/channel/packet
		// id/gateway id and the reason — never key material or
		// decrypted/attempted-decrypted plaintext.
		w.log.Info("decode failure",
			"topic", msg.Topic,
			"channel_segment", res.ChannelSegment,
			"packet_id", res.PacketID,
			"gateway_id", res.GatewayID,
			"reason", res.Status,
		)
		return
	}

	// Storage is portnum-specific; the relay is not. Which payloads the
	// relay acts on is decided by each rule's source_portnum inside the
	// engine, so this must not pre-filter -- doing so meant a NODEINFO_APP
	// or MAP_REPORT_APP rule could never fire, whatever the config said.
	if res.TextMessage != nil {
		if _, err := w.store.InsertTextMessage(rawID, res, res.ChannelSegment, msg.ReceivedAt); err != nil {
			w.log.Error("storage worker: inserting text_messages failed", "raw_frame_id", rawID, "error", err)
		}
	}
	// Every interpreted payload, text included, also leaves a
	// decoded_payloads row (ADR-15): before this, a position, nodeinfo or
	// telemetry frame was stored as bytes and nothing else, so "189 decoded
	// frames" could not be broken down by kind. Returns (0, nil) without
	// writing for a portnum with no interpreter.
	// A NODEINFO frame is the only thing that ever teaches a node's name, and
	// it arrives a few times a month, so it is recorded in its own table
	// rather than left to be derived from a payload retention will delete.
	if renamed, err := w.store.RecordNodeName(res, msg.ReceivedAt); err != nil {
		w.log.Error("recording node name failed", "error", err, "from", decode.NodeIDString(res.FromNode))
	} else if renamed {
		w.log.Info("node changed its long name",
			"node", decode.NodeIDString(res.FromNode), "board", boardID)
	}

	if _, err := w.store.InsertDecodedPayload(rawID, res); err != nil {
		w.log.Error("storage worker: inserting decoded_payloads failed",
			"raw_frame_id", rawID, "portnum", res.Portnum.Name(), "error", err)
	}
	if w.relayEngine != nil {
		w.relayEngine.Evaluate(res, boardID)
	}
	// Hooks fire last, after the durable record exists: a hook is a
	// notification, and the database is what survives a failure (ADR-17).
	if w.hooks != nil {
		ev := hook.FrameEvent(res, boardID, msg.ReceivedAt)
		if res.PacketParsed {
			ev.AttachNodeNames(w.store, res.FromNode, res.ToNode)
		}
		w.hooks.Dispatch(ev, res.RawPayload)
	}
}

// SetHooks attaches the event-hook dispatcher. A setter rather than
// another constructor parameter, matching RelayHook.SetPresence: this is
// optional wiring, and every call site of NewWorker would otherwise have to
// name it.
func (w *Worker) SetHooks(d HookDispatcher) { w.hooks = d }

func (w *Worker) recordDecodeStatus(status decode.Status) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.decodeFailures[status]++
}

// DecodeStatusCounts returns a snapshot of decode_status occurrences
// since startup, keyed by status string
// (docs/monitoring-api.md's decode_failures_by_reason — includes the
// "decoded" status too, which callers can filter out if only failures
// are wanted).
func (w *Worker) DecodeStatusCounts() map[string]int64 {
	w.mu.Lock()
	defer w.mu.Unlock()

	out := make(map[string]int64, len(w.decodeFailures))
	for status, count := range w.decodeFailures {
		out[string(status)] = count
	}
	return out
}
