package broker

import (
	"log/slog"
	"sort"
	"sync"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
)

// SubscriptionTracker records the topic filters each board actually
// subscribed to.
//
// The gap it closes: brokerd could already show that a board was connected
// (connected_boards), that its publishes arrived (raw_frames), and that the
// ACL refused something (acl_denials_total). It could not show what the board
// asked to *receive*. A board missing a channel, or holding it with
// downlink_enabled off, never subscribes to that channel's topic -- and an
// absent subscription is not an error anywhere: nothing is refused, nothing is
// logged, the board looks healthy, and the site simply never receives that
// channel. Diagnosing it meant reading `--info` on the board, which is not
// always reachable.
//
// It also puts evidence under an assumption PresenceHook states in prose --
// "every board here subscribes to the same private-channel prefix" -- which is
// exactly what fails in the case above. downlink_missed_total is built on that
// assumption, so being able to check it matters.
//
// Report-only: OnSubscribed is a notification (mochi-mqtt has already granted
// the subscription by then) and this hook returns nothing. Filters are recorded
// verbatim, never parsed: the topic's channel segment is opaque text
// (docs/protocol-spec.md §1), and a wildcard filter has no channel segment at
// all.
type SubscriptionTracker struct {
	mqtt.HookBase

	log *slog.Logger

	mu sync.Mutex
	// filters maps MQTT username -> subscribed filter -> struct{}. Keyed on
	// username rather than client id because that is what boards[] declares
	// and what every other counter here is keyed on.
	filters map[string]map[string]struct{}
}

// NewSubscriptionTracker builds the tracker. log may be nil.
func NewSubscriptionTracker(log *slog.Logger) *SubscriptionTracker {
	if log == nil {
		log = slog.Default()
	}
	return &SubscriptionTracker{
		log:     log,
		filters: make(map[string]map[string]struct{}),
	}
}

func (h *SubscriptionTracker) ID() string { return "brokerd-subscription-tracker" }

func (h *SubscriptionTracker) Provides(b byte) bool {
	return b == mqtt.OnSubscribed || b == mqtt.OnUnsubscribed
}

// OnSubscribed records every filter in the SUBSCRIBE packet. A board resends
// its subscriptions on each reconnect (cleanSession), so a filter is logged
// only the first time it is seen for that account -- the reconnect rate here
// makes one line per reconnect pure noise.
func (h *SubscriptionTracker) OnSubscribed(cl *mqtt.Client, pk packets.Packet, _ []byte) {
	username := clientUsername(cl)
	if username == "" {
		return
	}

	var added []string
	h.mu.Lock()
	if h.filters[username] == nil {
		h.filters[username] = make(map[string]struct{})
	}
	for _, sub := range pk.Filters {
		if _, seen := h.filters[username][sub.Filter]; !seen {
			added = append(added, sub.Filter)
		}
		h.filters[username][sub.Filter] = struct{}{}
	}
	h.mu.Unlock()

	for _, f := range added {
		h.log.Info("board subscribed", "username", username, "filter", f)
	}
}

// OnUnsubscribed drops the filters again, so the reported set stays a
// description of what a board currently asks for rather than a history of
// everything it ever asked for.
func (h *SubscriptionTracker) OnUnsubscribed(cl *mqtt.Client, pk packets.Packet) {
	username := clientUsername(cl)
	if username == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, sub := range pk.Filters {
		delete(h.filters[username], sub.Filter)
	}
	if len(h.filters[username]) == 0 {
		delete(h.filters, username)
	}
}

// Subscriptions returns each account's current filter set, sorted
// (docs/monitoring-api.md's board_subscriptions).
func (h *SubscriptionTracker) Subscriptions() map[string][]string {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make(map[string][]string, len(h.filters))
	for username, set := range h.filters {
		list := make([]string, 0, len(set))
		for f := range set {
			list = append(list, f)
		}
		sort.Strings(list)
		out[username] = list
	}
	return out
}

// compile-time proof the tracker satisfies the hook interface it claims,
// mirroring the other hooks in this package.
var _ interface {
	OnSubscribed(*mqtt.Client, packets.Packet, []byte)
	OnUnsubscribed(*mqtt.Client, packets.Packet)
} = (*SubscriptionTracker)(nil)
