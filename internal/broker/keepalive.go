package broker

import (
	"log/slog"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
)

// KeepaliveFloorHook records the keepalive a client asks for and, optionally,
// raises it to a floor.
//
// Why this exists at all: mochi-mqtt sets the connection's read deadline to
// `keepalive * 1.5` ([MQTT-3.1.2-22]) using the value from the client's
// CONNECT packet, and nothing logs that value — so when one deployed board
// began timing out repeatedly there was no way to see what deadline it was
// actually being held to. The hook's first job is to make it observable.
//
// Its second job is optional. With floorSeconds > 0, a client asking for
// less is treated as if it had asked for the floor, which lengthens the read
// deadline without changing anything on the client: it keeps pinging at its
// own interval, which is then more often than required. That does not make a
// flaky network reliable — it stops a stall shorter than the floor from
// costing a TLS handshake, a re-auth, and every message the board would have
// published while disconnected (MQTT keeps no queue for an absent client).
//
// mochi-mqtt calls OnConnect *before* it computes the deadline
// (server.go's establishConnection), which is what makes this possible.
type KeepaliveFloorHook struct {
	mqtt.HookBase

	floorSeconds uint16
	log          *slog.Logger
}

// NewKeepaliveFloorHook builds the hook. A floorSeconds of 0 disables the
// raising behaviour, leaving only the logging — the intended way to measure
// before deciding on a value.
func NewKeepaliveFloorHook(floorSeconds uint16, log *slog.Logger) *KeepaliveFloorHook {
	if log == nil {
		log = slog.Default()
	}
	return &KeepaliveFloorHook{floorSeconds: floorSeconds, log: log}
}

func (h *KeepaliveFloorHook) ID() string { return "brokerd-keepalive-floor" }

func (h *KeepaliveFloorHook) Provides(b byte) bool {
	return b == mqtt.OnConnect
}

func (h *KeepaliveFloorHook) OnConnect(cl *mqtt.Client, _ packets.Packet) error {
	requested := cl.State.Keepalive
	effective := requested

	// Keepalive 0 means "no keepalive" in MQTT and disables the deadline
	// entirely. Raising it would impose a deadline the client never agreed
	// to, so leave it alone.
	if h.floorSeconds > 0 && requested > 0 && requested < h.floorSeconds {
		cl.State.Keepalive = h.floorSeconds
		effective = h.floorSeconds
	}

	h.log.Info("client keepalive",
		"username", string(cl.Properties.Username),
		"requested_secs", requested,
		"effective_secs", effective,
		"read_deadline_secs", uint32(effective)+uint32(effective)/2,
	)
	return nil
}
