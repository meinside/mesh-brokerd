package broker

import (
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/hook"
)

// PresenceHook tracks which boards are currently connected and counts, for
// each frame published, how many configured boards were absent and therefore
// did not receive it.
//
// Why this is a real loss and not a broker bug: the firmware connects with
// `cleanSession` and everything is QoS 0 (docs/architecture.md §7), so an
// MQTT broker has nothing to retain for an absent subscriber. `brokerd`
// still records the frame -- the *record* stays complete while the
// *delivery* does not -- and one site reconnects dozens of times a day.
//
// Why counting comes before fixing: every mitigation considered
// (docs/architecture.md §8.1) either replays stale traffic into a live RF
// mesh or adds a new always-on component per site. At this deployment's
// measured rate (~4 frames/hour) with reconnects lasting seconds, the
// expected loss may be zero, and this counter is what decides whether any of
// that machinery is worth its risk.
//
// What the number means, precisely: "frames published while a configured
// board held no connection". It does not model subscription filters -- every
// board here has been observed subscribing to the same private-channel prefix,
// and SubscriptionTracker (board_subscriptions) is what makes that checkable
// rather than assumed -- and it never counts the publishing board, which
// demonstrably has the frame.
//
// Report-only, like the rest of brokerd's checks: OnConnect always returns
// nil, because mochi-mqtt treats a non-nil error there as grounds to refuse
// the connection, and a counter must never be able to lock a board out
// (TestPresence_OnConnectNeverRejects).
type PresenceHook struct {
	mqtt.HookBase

	log *slog.Logger

	hooks HookDispatcher

	// shuttingDown makes a disconnect caused by brokerd stopping
	// distinguishable from a board that dropped off. mochi-mqtt reports the
	// read error either way ("use of closed network connection"), which reads
	// like a fault, and an alerting hook that cannot tell the two apart cries
	// wolf on every restart.
	shuttingDown atomic.Bool

	mu      sync.Mutex
	boards  []string          // configured MQTT usernames
	boardID map[string]string // username -> board id, for hook events

	// connected holds the *current* session per username, not a boolean.
	//
	// A board that reconnects -- which a Meshtastic node does after every
	// config change, since changing the owner name reboots it -- makes
	// mochi-mqtt accept the new session and then close the one it replaced.
	// The two callbacks arrive in that order, so a boolean keyed by username
	// was set true by the new session and immediately deleted by the old
	// one's disconnect: the board then read as offline on the monitoring page
	// while its live session was publishing, every published frame counted
	// against it as downlink missed, and a board_disconnected hook event fired
	// for a session that had already been replaced.
	//
	// Comparing the client that is disconnecting against the one on record
	// makes the order irrelevant.
	connected map[string]*mqtt.Client
	missed    map[string]int64
	takeovers map[string]int64
}

// NewPresenceHook builds the hook for the configured boards.
func NewPresenceHook(boards []config.Board, log *slog.Logger) *PresenceHook {
	if log == nil {
		log = slog.Default()
	}
	usernames := make([]string, 0, len(boards))
	for _, b := range boards {
		usernames = append(usernames, b.Username)
	}
	ids := make(map[string]string, len(boards))
	for _, b := range boards {
		ids[b.Username] = b.ID
	}
	return &PresenceHook{
		log:       log,
		boards:    usernames,
		boardID:   ids,
		connected: make(map[string]*mqtt.Client, len(boards)),
		missed:    make(map[string]int64, len(boards)),
		takeovers: make(map[string]int64, len(boards)),
	}
}

func (h *PresenceHook) ID() string { return "brokerd-presence" }

func (h *PresenceHook) Provides(b byte) bool {
	return b == mqtt.OnConnect || b == mqtt.OnDisconnect
}

// OnConnect records the board as present. The error is always nil (see the
// type comment).
func (h *PresenceHook) OnConnect(cl *mqtt.Client, _ packets.Packet) error {
	username := clientUsername(cl)
	if username == "" {
		return nil
	}
	h.mu.Lock()
	previous := h.connected[username]
	h.connected[username] = cl
	if previous != nil && previous != cl {
		h.takeovers[username]++
	}
	id := h.boardID[username]
	takeover := previous != nil && previous != cl
	h.mu.Unlock()
	if takeover {
		// Worth a line: nothing else records that a session was replaced, and
		// the disconnect that follows is deliberately not reported.
		h.log.Info("board reconnected, replacing its previous MQTT session",
			"board", id, "username", username)
	}
	h.fire(config.HookEventBoardConnected, username, id, "")
	return nil
}

// OnDisconnect records the board as absent. From this moment until it
// reconnects, anything published is lost to it.
func (h *PresenceHook) OnDisconnect(cl *mqtt.Client, err error, _ bool) {
	username := clientUsername(cl)
	if username == "" {
		return
	}
	h.mu.Lock()
	current := h.connected[username]
	superseded := current != nil && current != cl
	if !superseded {
		delete(h.connected, username)
	}
	id := h.boardID[username]
	h.mu.Unlock()

	if superseded {
		// This is the session that was replaced, closed by mochi-mqtt after
		// the replacement was accepted. The board is connected; saying
		// otherwise would be wrong on the page and a false alarm in a hook.
		h.log.Debug("ignoring the disconnect of a superseded MQTT session",
			"board", id, "username", username)
		return
	}
	h.fire(config.HookEventBoardDisconnected, username, id, h.disconnectReason(err))
}

// RecordPublish credits every absent board with one missed frame. Called
// from the publish path with the publishing client's username.
func (h *PresenceHook) RecordPublish(publisher string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, b := range h.boards {
		if b == publisher || h.connected[b] != nil {
			continue
		}
		h.missed[b]++
	}
}

// SessionTakeovers counts, per board, how many times a new MQTT session
// replaced a live one. A Meshtastic node reboots on every config change, so
// this rises whenever boards are being reconfigured -- and it is the only
// record that a replaced session's disconnect was deliberately not reported.
func (h *PresenceHook) SessionTakeovers() map[string]int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]int64, len(h.takeovers))
	for k, v := range h.takeovers {
		out[k] = v
	}
	return out
}

// DownlinkMissed returns a copy of the per-board missed-frame counters
// (docs/monitoring-api.md's downlink_missed_total).
func (h *PresenceHook) DownlinkMissed() map[string]int64 {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make(map[string]int64, len(h.missed))
	for k, v := range h.missed {
		out[k] = v
	}
	return out
}

// Connected returns the currently-connected board usernames, sorted, for the
// monitoring API's board status.
func (h *PresenceHook) Connected() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make([]string, 0, len(h.connected))
	for u := range h.connected {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func clientUsername(cl *mqtt.Client) string {
	if cl == nil {
		return ""
	}
	return string(cl.Properties.Username)
}

// SetHooks attaches the event-hook dispatcher (a setter for the same
// reason as Worker.SetHooks).
func (h *PresenceHook) SetHooks(d HookDispatcher) { h.hooks = d }

// fire emits a connection event. A board with no configured id still fires,
// under its username: the event exists to say something changed, and
// withholding it because a name is missing would be the worse failure.
func (h *PresenceHook) fire(event, username, boardID, reason string) {
	if h.hooks == nil {
		return
	}
	if boardID == "" {
		boardID = username
	}
	h.hooks.Dispatch(hook.BoardEvent(event, boardID, reason), nil)
}

// disconnectReason renders mochi-mqtt's disconnect error for the event. A
// clean disconnect carries no error at all, and that difference is the
// interesting part: an unexpected drop is the event worth counting.
func (h *PresenceHook) disconnectReason(err error) string {
	if h.shuttingDown.Load() {
		// Deliberately not suppressed: the board really did lose its session,
		// and a consumer may want to know. It just gets to know why.
		return "server shutting down"
	}
	if err == nil {
		return "clean"
	}
	return err.Error()
}

// MarkShuttingDown is called by Broker.shutdown before the mochi-mqtt server
// closes, which is the only moment at which brokerd knows a disconnect is its
// own doing. mochi's own OnStopped hook fires *after* clients are closed, too
// late to label them.
func (h *PresenceHook) MarkShuttingDown() { h.shuttingDown.Store(true) }
