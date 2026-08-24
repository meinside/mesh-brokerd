package broker

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
	"golang.org/x/crypto/bcrypt"

	"github.com/meinside/mesh-brokerd/internal/auth"
	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
	"github.com/meinside/mesh-brokerd/internal/storage"
)

// serveTwoBoardBroker starts a broker configured with two boards but only
// one usable credential, so a test can publish as one while the other is
// (necessarily) absent. Returns the address and the Broker, since the
// counters are read from it.
func serveTwoBoardBroker(t *testing.T, sink *syncBuffer, username, password string) (string, *Broker) {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}

	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	addr := freePort(t)
	br, err := New(Options{
		MQTTAddr: addr,
		Boards: []config.Board{
			{ID: username, Username: username, ACLFilters: []string{"msh/pvt/2/e/#"}},
			{ID: "bravo", Username: "bravo", ACLFilters: []string{"msh/pvt/2/e/#"}},
		},
		ChannelPSKs: map[string][decode.PSKSize]byte{},
		AuthHook:    auth.New(map[string]string{username: string(hash)}, 5, 30*time.Minute, nil),
		Store:       store,
		Log:         slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelInfo})),
	})
	if err != nil {
		t.Fatalf("broker.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- br.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("broker did not shut down within 5s")
		}
	})

	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("broker never started listening on %s: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return addr, br
}

func presenceTestBoards() []config.Board {
	return []config.Board{
		{ID: "alpha", Username: "alpha"},
		{ID: "bravo", Username: "bravo"},
	}
}

func clientNamed(username string) *mqtt.Client {
	cl := &mqtt.Client{}
	cl.Properties.Username = []byte(username)
	return cl
}

func TestPresence_StartsWithEveryBoardAbsent(t *testing.T) {
	p := NewPresenceHook(presenceTestBoards(), slog.New(&warnCapture{}))

	if got := p.Connected(); len(got) != 0 {
		t.Errorf("Connected() = %v at startup, want empty", got)
	}
}

func TestPresence_TracksConnectAndDisconnect(t *testing.T) {
	p := NewPresenceHook(presenceTestBoards(), slog.New(&warnCapture{}))

	// One session is one client object, which is what mochi-mqtt passes to
	// both callbacks. Building a second client here would model a *different*
	// session, and presence now distinguishes them deliberately.
	session := clientNamed("alpha")

	if err := p.OnConnect(session, packets.Packet{}); err != nil {
		t.Fatalf("OnConnect: %v", err)
	}
	if got := p.Connected(); len(got) != 1 || got[0] != "alpha" {
		t.Fatalf("Connected() = %v, want [alpha]", got)
	}

	p.OnDisconnect(session, errors.New("read timeout"), false)
	if got := p.Connected(); len(got) != 0 {
		t.Errorf("Connected() = %v after disconnect, want empty", got)
	}
}

// TestPresence_OnConnectNeverRejects guards the one way this hook could do
// harm: mochi-mqtt treats a non-nil error from OnConnect as a reason to
// refuse the connection, and a *reporting* hook must never be able to lock
// a board out.
func TestPresence_OnConnectNeverRejects(t *testing.T) {
	p := NewPresenceHook(presenceTestBoards(), slog.New(&warnCapture{}))

	for _, username := range []string{"alpha", "", "not-a-configured-board"} {
		if err := p.OnConnect(clientNamed(username), packets.Packet{}); err != nil {
			t.Errorf("OnConnect(%q) = %v, want nil", username, err)
		}
	}
}

func TestPresence_CountsAbsentBoardsOnPublish(t *testing.T) {
	p := NewPresenceHook(presenceTestBoards(), slog.New(&warnCapture{}))
	if err := p.OnConnect(clientNamed("alpha"), packets.Packet{}); err != nil {
		t.Fatalf("OnConnect: %v", err)
	}

	// alpha publishes while bravo is offline: bravo missed it.
	p.RecordPublish("alpha")

	missed := p.DownlinkMissed()
	if missed["bravo"] != 1 {
		t.Errorf("DownlinkMissed()[bravo] = %d, want 1", missed["bravo"])
	}
	if _, ok := missed["alpha"]; ok {
		t.Errorf("the publishing board was counted as having missed its own frame: %v", missed)
	}
}

func TestPresence_CountsNothingWhenEveryoneIsConnected(t *testing.T) {
	p := NewPresenceHook(presenceTestBoards(), slog.New(&warnCapture{}))
	for _, u := range []string{"alpha", "bravo"} {
		if err := p.OnConnect(clientNamed(u), packets.Packet{}); err != nil {
			t.Fatalf("OnConnect(%s): %v", u, err)
		}
	}

	p.RecordPublish("alpha")

	if got := p.DownlinkMissed(); len(got) != 0 {
		t.Errorf("DownlinkMissed() = %v with both boards online, want empty", got)
	}
}

// TestPresence_PublisherOfflineIsNotCounted covers the ordering case that
// actually happens: mochi-mqtt dispatches OnPublish for a client whose
// connection is being torn down, or a publish arrives before OnConnect was
// recorded. The publisher demonstrably has the frame, so it must never be
// counted regardless of what presence says about it.
func TestPresence_PublisherOfflineIsNotCounted(t *testing.T) {
	p := NewPresenceHook(presenceTestBoards(), slog.New(&warnCapture{}))

	p.RecordPublish("alpha") // nobody recorded as connected at all

	missed := p.DownlinkMissed()
	if _, ok := missed["alpha"]; ok {
		t.Errorf("publisher counted while absent: %v", missed)
	}
	if missed["bravo"] != 1 {
		t.Errorf("DownlinkMissed()[bravo] = %d, want 1", missed["bravo"])
	}
}

func TestPresence_IgnoresUnknownPublisher(t *testing.T) {
	p := NewPresenceHook(presenceTestBoards(), slog.New(&warnCapture{}))

	// A publisher that is not a configured board (should not happen, since
	// auth precedes publish) must not make every board look like it missed
	// something spurious -- but it also must not panic or skip accounting.
	p.RecordPublish("stranger")

	missed := p.DownlinkMissed()
	if missed["alpha"] != 1 || missed["bravo"] != 1 {
		t.Errorf("DownlinkMissed() = %v, want both configured boards counted", missed)
	}
}

func TestPresence_MissedCountsAreCopied(t *testing.T) {
	p := NewPresenceHook(presenceTestBoards(), slog.New(&warnCapture{}))
	p.RecordPublish("alpha")

	m := p.DownlinkMissed()
	m["bravo"] = 99
	if again := p.DownlinkMissed()["bravo"]; again != 1 {
		t.Errorf("DownlinkMissed() returned an aliased map: got %d after caller mutation, want 1", again)
	}
}

func TestPresence_ProvidesOnlyConnectAndDisconnect(t *testing.T) {
	p := NewPresenceHook(presenceTestBoards(), slog.New(&warnCapture{}))

	for _, b := range []byte{mqtt.OnConnect, mqtt.OnDisconnect} {
		if !p.Provides(b) {
			t.Errorf("Provides(%d) = false, want true", b)
		}
	}
	for _, b := range []byte{mqtt.OnConnectAuthenticate, mqtt.OnACLCheck, mqtt.OnPublish} {
		if p.Provides(b) {
			t.Errorf("Provides(%d) = true; this hook must not take part in auth, ACL or publish handling", b)
		}
	}
}

// TestBroker_PresenceCountsRealPublish drives a real client through a real
// broker: with only one board connected, a publish must leave the other
// board with one missed frame. Without this, PresenceHook could be correct
// in isolation and never consulted -- a failure mode this project has hit
// three times.
func TestBroker_PresenceCountsRealPublish(t *testing.T) {
	sink := &syncBuffer{}
	addr, br := serveTwoBoardBroker(t, sink, "alpha", "correct-horse")

	opts := paho.NewClientOptions().
		AddBroker("tcp://" + addr).
		SetClientID("presence-probe").
		SetUsername("alpha").
		SetPassword("correct-horse").
		SetConnectTimeout(5 * time.Second).
		SetConnectRetry(false).
		SetAutoReconnect(false)
	cl := paho.NewClient(opts)
	if tok := cl.Connect(); tok.WaitTimeout(5*time.Second) && tok.Error() != nil {
		t.Fatalf("connect: %v", tok.Error())
	}
	defer cl.Disconnect(100)

	// Wait for the broker to have seen the connection.
	deadline := time.Now().Add(3 * time.Second)
	for len(br.ConnectedBoards()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := br.ConnectedBoards(); len(got) != 1 || got[0] != "alpha" {
		t.Fatalf("ConnectedBoards() = %v, want [alpha]", got)
	}

	tok := cl.Publish("msh/pvt/2/e/pvt/!11223344", 0, false, []byte{0x01})
	tok.WaitTimeout(2 * time.Second)
	if err := tok.Error(); err != nil {
		t.Fatalf("publish: %v", err)
	}

	deadline = time.Now().Add(3 * time.Second)
	for br.DownlinkMissed()["bravo"] == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	missed := br.DownlinkMissed()
	if missed["bravo"] != 1 {
		t.Errorf("DownlinkMissed()[bravo] = %d, want 1 — the publish path never reached the presence hook", missed["bravo"])
	}
	if _, ok := missed["alpha"]; ok {
		t.Errorf("the connected publisher was counted as missing its own frame: %v", missed)
	}
}

// TestPresence_SessionTakeoverKeepsTheBoardConnected reproduces what changing a
// node's owner name did to the live deployment. Changing the owner reboots a
// Meshtastic node; it reconnects, mochi-mqtt accepts the new session and then
// closes the one it replaced, and the callbacks arrive in that order. Presence
// was a bool keyed by username, so the new session set it and the old session's
// disconnect immediately cleared it: both boards had live TCP connections on
// 8883 and were publishing, while the monitoring page showed none connected.
func TestPresence_SessionTakeoverKeepsTheBoardConnected(t *testing.T) {
	p := NewPresenceHook(presenceTestBoards(), slog.New(&warnCapture{}))
	events := &recordingDispatcher{}
	p.SetHooks(events)

	first := clientNamed("alpha")
	second := clientNamed("alpha") // same board, new session after a reboot

	if err := p.OnConnect(first, packets.Packet{}); err != nil {
		t.Fatalf("OnConnect(first): %v", err)
	}
	if err := p.OnConnect(second, packets.Packet{}); err != nil {
		t.Fatalf("OnConnect(second): %v", err)
	}
	// mochi-mqtt now closes the replaced session.
	p.OnDisconnect(first, errors.New("use of closed network connection"), false)

	if got := p.Connected(); len(got) != 1 || got[0] != "alpha" {
		t.Errorf("Connected() = %v after a session takeover, want [alpha]: the live session is still publishing", got)
	}
	if got := p.SessionTakeovers()["alpha"]; got != 1 {
		t.Errorf("SessionTakeovers()[alpha] = %d, want 1", got)
	}

	// A replaced session must not raise a disconnect notification: whoever
	// wired an outage alert to it would be paged by every reboot.
	for _, e := range events.snapshot() {
		if e.Event == config.HookEventBoardDisconnected {
			t.Error("a board_disconnected event fired for a session that had already been replaced")
		}
	}

	// The live session ending is still reported.
	p.OnDisconnect(second, errors.New("read timeout"), false)
	if got := p.Connected(); len(got) != 0 {
		t.Errorf("Connected() = %v after the live session ended, want empty", got)
	}
	sawDisconnect := false
	for _, e := range events.snapshot() {
		if e.Event == config.HookEventBoardDisconnected {
			sawDisconnect = true
		}
	}
	if !sawDisconnect {
		t.Error("no board_disconnected event when the live session ended")
	}
}

// TestPresence_TakeoverDoesNotCountDownlinkAsMissed: the same bug made every
// frame published while a board was wrongly marked absent count against it, so
// downlink_missed_total was inflated by reconfiguration.
func TestPresence_TakeoverDoesNotCountDownlinkAsMissed(t *testing.T) {
	p := NewPresenceHook(presenceTestBoards(), slog.New(&warnCapture{}))

	first := clientNamed("alpha")
	second := clientNamed("alpha")
	if err := p.OnConnect(first, packets.Packet{}); err != nil {
		t.Fatalf("OnConnect: %v", err)
	}
	if err := p.OnConnect(second, packets.Packet{}); err != nil {
		t.Fatalf("OnConnect: %v", err)
	}
	p.OnDisconnect(first, errors.New("use of closed network connection"), false)

	// bravo publishes; alpha is connected, so nothing is missed for alpha.
	p.RecordPublish("bravo")

	if got := p.DownlinkMissed()["alpha"]; got != 0 {
		t.Errorf("DownlinkMissed()[alpha] = %d after a takeover, want 0", got)
	}
}
