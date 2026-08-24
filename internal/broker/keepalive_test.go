package broker

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
)

func keepaliveTestClient(keepalive uint16) *mqtt.Client {
	cl := &mqtt.Client{}
	cl.ID = "test-client"
	cl.State.Keepalive = keepalive
	cl.Properties.Username = []byte("alpha")
	return cl
}

// A client asking for a very short keepalive must not get a correspondingly
// short read deadline.
//
// mochi-mqtt sets the connection's read deadline to keepalive * 1.5
// ([MQTT-3.1.2-22]). Meshtastic firmware does not configure a keepalive at
// all, so it inherits PubSubClient's short default, and the resulting
// deadline is tight enough that an ordinary network stall ends the session.
// One deployed board reconnected 55 times in a day with 42 read timeouts,
// while the other -- same firmware, same settings, different network --
// stayed connected throughout.
//
// Every one of those timeouts costs a TLS handshake and a re-auth, and
// anything the board publishes while disconnected is simply lost: MQTT has
// no queue for a client that is not there. Raising the floor does not make
// the network reliable, it stops a 25-second stall from becoming a much
// longer outage.
func TestKeepaliveFloorHook_RaisesShortKeepalive(t *testing.T) {
	h := NewKeepaliveFloorHook(60, nil)
	cl := keepaliveTestClient(15)

	if err := h.OnConnect(cl, packets.Packet{}); err != nil {
		t.Fatalf("OnConnect: %v", err)
	}
	if cl.State.Keepalive != 60 {
		t.Errorf("Keepalive = %d, want it raised to the 60s floor", cl.State.Keepalive)
	}
}

// A client that already asks for more than the floor is left alone: the
// floor is a minimum, not an override.
func TestKeepaliveFloorHook_LeavesLongerKeepaliveAlone(t *testing.T) {
	h := NewKeepaliveFloorHook(60, nil)
	cl := keepaliveTestClient(300)

	if err := h.OnConnect(cl, packets.Packet{}); err != nil {
		t.Fatalf("OnConnect: %v", err)
	}
	if cl.State.Keepalive != 300 {
		t.Errorf("Keepalive = %d, want the client's own 300 left untouched", cl.State.Keepalive)
	}
}

// Keepalive 0 means "no keepalive" in MQTT and disables the deadline
// entirely; raising it would impose a deadline the client never agreed to.
func TestKeepaliveFloorHook_LeavesZeroAlone(t *testing.T) {
	h := NewKeepaliveFloorHook(60, nil)
	cl := keepaliveTestClient(0)

	if err := h.OnConnect(cl, packets.Packet{}); err != nil {
		t.Fatalf("OnConnect: %v", err)
	}
	if cl.State.Keepalive != 0 {
		t.Errorf("Keepalive = %d, want 0 (no keepalive) preserved", cl.State.Keepalive)
	}
}

// A floor of 0 disables the hook, so the behaviour can be turned off
// without removing the hook from the server.
func TestKeepaliveFloorHook_FloorZeroChangesNothing(t *testing.T) {
	h := NewKeepaliveFloorHook(0, nil)
	cl := keepaliveTestClient(15)

	if err := h.OnConnect(cl, packets.Packet{}); err != nil {
		t.Fatalf("OnConnect: %v", err)
	}
	if cl.State.Keepalive != 15 {
		t.Errorf("Keepalive = %d, want 15 unchanged when the floor is 0", cl.State.Keepalive)
	}
}

// The requested value is logged, because until this hook existed there was
// no way to see what a board actually asks for -- the timeout diagnosis had
// to infer it from firmware source.
func TestKeepaliveFloorHook_LogsRequestedAndEffective(t *testing.T) {
	var buf bytes.Buffer
	h := NewKeepaliveFloorHook(60, slog.New(slog.NewTextHandler(&buf, nil)))

	if err := h.OnConnect(keepaliveTestClient(15), packets.Packet{}); err != nil {
		t.Fatalf("OnConnect: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"keepalive", "15", "60"} {
		if !strings.Contains(out, want) {
			t.Errorf("log line omits %q; got %q", want, out)
		}
	}
}
