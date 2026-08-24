// Package broker wires mochi-mqtt (embedded MQTT broker) together with
// brokerd's authentication (internal/auth) and storage
// (internal/storage) layers, per docs/architecture.md §3 and ADR-3 in
// docs/adr.md.
package broker

import (
	"sync/atomic"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
)

// queuedMessage is the minimum copied out of a packets.Packet before
// OnPublish returns, so the broker's relay path never blocks on
// storage (ADR-3).
type queuedMessage struct {
	Topic      string
	Payload    []byte
	Username   string
	ReceivedAt time.Time
}

// RelayHook is the OnPublish hook that hands raw messages off to the
// storage worker via a bounded channel (ADR-3): copy-and-return
// immediately, never block the relay path. When the channel is full,
// the message is dropped and counted — never blocked on.
type RelayHook struct {
	mqtt.HookBase

	queue     chan queuedMessage
	dropCount int64 // atomic

	// presence, when set, is told about every publish so it can count the
	// frames absent boards missed. Optional: nil in unit tests that
	// only exercise the queue.
	presence *PresenceHook
}

// SetPresence attaches the presence tracker. Called by New before the
// server starts serving, so no synchronisation is needed here.
func (h *RelayHook) SetPresence(p *PresenceHook) { h.presence = p }

// NewRelayHook creates a RelayHook with the given bounded queue depth.
func NewRelayHook(queueSize int) *RelayHook {
	return &RelayHook{queue: make(chan queuedMessage, queueSize)}
}

func (h *RelayHook) ID() string { return "brokerd-storage-relay" }

func (h *RelayHook) Provides(b byte) bool { return b == mqtt.OnPublish }

// OnPublish implements ADR-3's synchronous minimum: copy the topic and
// payload (packets.Packet's byte slices are reused by mochi-mqtt after
// the hook returns, so a copy is required, not just a reference) and
// enqueue, never blocking.
func (h *RelayHook) OnPublish(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	msg := queuedMessage{
		Topic:      pk.TopicName,
		Payload:    append([]byte(nil), pk.Payload...),
		Username:   string(cl.Properties.Username),
		ReceivedAt: time.Now(),
	}

	select {
	case h.queue <- msg:
	default:
		atomic.AddInt64(&h.dropCount, 1)
	}

	// Credit every board that was not connected at this moment with one
	// frame it will never receive. Cheap (one mutex, one loop over the
	// configured boards) and deliberately on the publish path rather than in
	// the storage worker, so the count reflects the moment of publication
	// rather than whenever the queue drained.
	if h.presence != nil {
		h.presence.RecordPublish(msg.Username)
	}

	return pk, nil
}

// DropCount returns the running total of messages dropped because the
// queue was full (docs/monitoring-api.md's storage_queue_drops).
func (h *RelayHook) DropCount() int64 {
	return atomic.LoadInt64(&h.dropCount)
}

// messages exposes the queue for the storage worker to consume.
// Unexported: only this package's Worker should read from it.
func (h *RelayHook) messages() <-chan queuedMessage {
	return h.queue
}
