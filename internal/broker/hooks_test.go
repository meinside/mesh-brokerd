package broker

import (
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
	"golang.org/x/crypto/bcrypt"

	"github.com/meinside/mesh-brokerd/internal/auth"
	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
	"github.com/meinside/mesh-brokerd/internal/hook"
	"github.com/meinside/mesh-brokerd/internal/storage"
)

// recordingDispatcher captures what the broker would send to hooks.
type recordingDispatcher struct {
	mu     sync.Mutex
	events []hook.Event
	raws   [][]byte
}

func (r *recordingDispatcher) Dispatch(e hook.Event, raw []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	r.raws = append(r.raws, raw)
}

func (r *recordingDispatcher) snapshot() []hook.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]hook.Event(nil), r.events...)
}

// TestWorker_DispatchesFrameEventAfterStoring proves the real worker path
// reaches the hook dispatcher, and that it does so with the frame's own
// fields rather than a reconstruction.
func TestWorker_DispatchesFrameEventAfterStoring(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	rec := &recordingDispatcher{}
	worker := NewWorker(NewRelayHook(4), store, map[string][decode.PSKSize]byte{},
		map[string]string{"alpha": "alpha"}, nil, nil, nil)
	worker.SetHooks(rec)

	envelope := decode.EncodeServiceEnvelope(
		decode.EncodeMeshPacketDecoded(0x11223344, 0xffffffff, 4242,
			decode.EncodeData(decode.PortNumTextMessage, []byte("hook me"))),
		"pvt", "!11223344")

	worker.processOne(queuedMessage{
		Topic: "msh/pvt/2/e/pvt/!11223344", Payload: envelope,
		Username: "alpha", ReceivedAt: time.Now(),
	})

	events := rec.snapshot()
	if len(events) != 1 {
		t.Fatalf("dispatched %d events, want 1", len(events))
	}
	e := events[0]
	if e.Event != config.HookEventFrame {
		t.Errorf("event = %q, want %q", e.Event, config.HookEventFrame)
	}
	if e.BoardID != "alpha" || e.Portnum != "TEXT_MESSAGE_APP" {
		t.Errorf("board/portnum = %q/%q, want alpha/TEXT_MESSAGE_APP", e.BoardID, e.Portnum)
	}
	// The raw payload travels alongside, for targets that opted into it;
	// the event itself carries it only after that opt-in is applied.
	if string(rec.raws[0]) != "hook me" {
		t.Errorf("raw payload = %q, want %q", rec.raws[0], "hook me")
	}
	if e.RawPayload != "" {
		t.Errorf("RawPayload set before any target opted in: %q", e.RawPayload)
	}
}

// TestWorker_DoesNotDispatchForDecodeFailure keeps a hook from firing for
// something that produced no decoded record: v1's events are about traffic
// brokerd understood.
func TestWorker_DoesNotDispatchForDecodeFailure(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	rec := &recordingDispatcher{}
	worker := NewWorker(NewRelayHook(4), store, map[string][decode.PSKSize]byte{},
		map[string]string{"alpha": "alpha"}, nil, nil, nil)
	worker.SetHooks(rec)

	// An encrypted frame whose channel has no configured PSK.
	mp := decode.EncodeMeshPacket(decode.MeshPacketFields{
		From: 0x11223344, To: 0xffffffff, ID: 7, Encrypted: []byte{0xaa, 0xbb},
	})
	worker.processOne(queuedMessage{
		Topic: "msh/pvt/2/e/unknown/!11223344", Payload: decode.EncodeServiceEnvelope(mp, "unknown", "!11223344"),
		Username: "alpha", ReceivedAt: time.Now(),
	})

	if got := len(rec.snapshot()); got != 0 {
		t.Errorf("dispatched %d events for an undecodable frame, want 0", got)
	}
}

// TestPresenceHook_DispatchesConnectionEvents covers the events that exist
// precisely because a counter was not enough: a board dropping off is the
// event to know about, and the reason string is what distinguishes a clean
// disconnect from a dropped connection.
func TestPresenceHook_DispatchesConnectionEvents(t *testing.T) {
	rec := &recordingDispatcher{}
	h := NewPresenceHook([]config.Board{{ID: "alpha", Username: "alpha-user"}}, nil)
	h.SetHooks(rec)

	cl := &mqtt.Client{Properties: mqtt.ClientProperties{Username: []byte("alpha-user")}}
	if err := h.OnConnect(cl, packets.Packet{}); err != nil {
		t.Fatalf("OnConnect: %v", err)
	}
	h.OnDisconnect(cl, nil, false)
	h.OnDisconnect(cl, errRead{}, false)

	events := rec.snapshot()
	if len(events) != 3 {
		t.Fatalf("dispatched %d events, want 3", len(events))
	}
	if events[0].Event != config.HookEventBoardConnected || events[0].BoardID != "alpha" {
		t.Errorf("connect event = %+v, want board_connected for alpha", events[0])
	}
	if events[1].Event != config.HookEventBoardDisconnected || events[1].Reason != "clean" {
		t.Errorf("clean disconnect = %+v, want reason \"clean\"", events[1])
	}
	if events[2].Reason != "i/o timeout" {
		t.Errorf("dropped disconnect reason = %q, want the underlying error", events[2].Reason)
	}
}

type errRead struct{}

func (errRead) Error() string { return "i/o timeout" }

// TestBroker_RealPublishReachesRealDispatcher exercises the whole path with
// nothing faked but the sink: a paho client connects to a real broker,
// publishes a real encrypted frame, and the real hook.Dispatcher (queue,
// filters, workers) delivers it. The unit tests above prove the worker calls
// a dispatcher; this proves the dispatcher that is actually wired up
// receives traffic that came off the wire.
func TestBroker_RealPublishReachesRealDispatcher(t *testing.T) {
	const username, password = "alpha", "correct-horse"

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	var psk [decode.PSKSize]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	sink := &collectingSink{}
	dispatcher := hook.New(hook.Options{
		Config: config.EventHooks{
			Enabled: true, DryRun: false, QueueSize: 8, MaxConcurrent: 1,
			Targets: []config.HookTarget{{
				Name: "probe", Kind: config.HookKindWebhook, Enabled: true,
				Timeout: 2 * time.Second, QuietFrom: -1, QuietTo: -1,
				Match: config.HookMatch{
					Events:      []string{config.HookEventFrame, config.HookEventBoardConnected},
					IncludeText: true,
				},
			}},
		},
		Boards: []config.Board{{ID: username, Username: username}},
		Logger: slog.New(slog.NewTextHandler(&syncBuffer{}, &slog.HandlerOptions{Level: slog.LevelError})),
		Sinks:  map[config.HookKind]hook.Sink{config.HookKindWebhook: sink},
	})
	ctx, cancel := context.WithCancel(context.Background())
	dispatcher.Run(ctx)
	t.Cleanup(func() { cancel(); dispatcher.Wait() })

	addr := freePort(t)
	br, err := New(Options{
		MQTTAddr: addr,
		Boards: []config.Board{
			{ID: username, Username: username, ACLFilters: []string{"msh/pvt/2/e/#"}},
		},
		ChannelPSKs: map[string][decode.PSKSize]byte{"pvt": psk},
		AuthHook:    auth.New(map[string]string{username: string(hash)}, 5, 30*time.Minute, nil),
		Store:       store,
		Hooks:       dispatcher,
		Log:         slog.New(slog.NewTextHandler(&syncBuffer{}, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("broker.New: %v", err)
	}
	serveCtx, stopBroker := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- br.Serve(serveCtx) }()
	t.Cleanup(func() {
		stopBroker()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("broker did not shut down within 5s")
		}
	})
	waitForListener(t, addr)

	cl := paho.NewClient(paho.NewClientOptions().
		AddBroker("tcp://" + addr).SetClientID("hook-probe").
		SetUsername(username).SetPassword(password).
		SetConnectTimeout(5 * time.Second).SetConnectRetry(false).SetAutoReconnect(false))
	if tok := cl.Connect(); tok.WaitTimeout(5*time.Second) && tok.Error() != nil {
		t.Fatalf("connect: %v", tok.Error())
	}
	defer cl.Disconnect(100)

	const packetID, fromNode = 0xabcd, 0x99aabbcc
	data := decode.EncodeData(decode.PortNumTextMessage, []byte("over the wire"))
	ciphertext, err := decode.CryptCTR(psk[:], decode.DeriveNonce(packetID, fromNode), data)
	if err != nil {
		t.Fatalf("CryptCTR: %v", err)
	}
	envelope := decode.EncodeServiceEnvelope(decode.EncodeMeshPacket(decode.MeshPacketFields{
		From: fromNode, To: 0xffffffff, ID: packetID,
		ChannelHash: decode.ChannelHash("pvt", psk[:]), Encrypted: ciphertext,
	}), "pvt", "!11223344")

	tok := cl.Publish("msh/pvt/2/e/pvt/!11223344", 0, false, envelope)
	tok.WaitTimeout(2 * time.Second)
	if err := tok.Error(); err != nil {
		t.Fatalf("publish: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for sink.frameCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	body, ok := sink.frameBody()
	if !ok {
		t.Fatalf("no frame event delivered; bodies seen: %v", sink.all())
	}
	for _, want := range []string{`"event":"frame"`, `"board_id":"alpha"`, "TEXT_MESSAGE_APP", "over the wire"} {
		if !strings.Contains(body, want) {
			t.Errorf("delivered body %s\n does not contain %q", body, want)
		}
	}

	// The connection itself is also an event, and it arrived from the same
	// dispatcher without the worker being involved.
	if !sink.sawEvent(`"event":"board_connected"`) {
		t.Errorf("no board_connected event delivered; bodies seen: %v", sink.all())
	}
}

// collectingSink records every delivered body.
type collectingSink struct {
	mu     sync.Mutex
	bodies []string
}

func (c *collectingSink) Deliver(_ context.Context, _ config.HookTarget, body []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bodies = append(c.bodies, string(body))
	return nil
}

func (c *collectingSink) Describe(config.HookTarget) string { return "collecting" }

func (c *collectingSink) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.bodies...)
}

func (c *collectingSink) frameCount() int {
	n := 0
	for _, b := range c.all() {
		if strings.Contains(b, `"event":"frame"`) {
			n++
		}
	}
	return n
}

func (c *collectingSink) frameBody() (string, bool) {
	for _, b := range c.all() {
		if strings.Contains(b, `"event":"frame"`) {
			return b, true
		}
	}
	return "", false
}

func (c *collectingSink) sawEvent(fragment string) bool {
	for _, b := range c.all() {
		if strings.Contains(b, fragment) {
			return true
		}
	}
	return false
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("broker never started listening on %s: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestBroker_ShutdownDeliversDisconnectEvent verifies a path that was
// inferred from mochi-mqtt's source and then got the ordering wrong in
// practice: Server.Close() disconnects each client, which ends its read loop
// and fires OnDisconnect, which the presence hook turns into a
// board_disconnected event. brokerd's first version cancelled the hook
// dispatcher with the same context as the broker, so those events were
// enqueued while no worker was left to deliver them, and vanished.
//
// The dispatcher's context therefore has to outlive the broker's, which is
// what main.go now does and what this test pins.
func TestBroker_ShutdownDeliversDisconnectEvent(t *testing.T) {
	const username, password = "alpha", "correct-horse"

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	sink := &collectingSink{}
	dispatcher := hook.New(hook.Options{
		Config: config.EventHooks{
			Enabled: true, DryRun: false, QueueSize: 8, MaxConcurrent: 1,
			Targets: []config.HookTarget{{
				Name: "probe", Kind: config.HookKindWebhook, Enabled: true,
				Timeout: 2 * time.Second, QuietFrom: -1, QuietTo: -1,
				Match: config.HookMatch{Events: []string{config.HookEventBoardDisconnected}},
			}},
		},
		Boards: []config.Board{{ID: username, Username: username}},
		Logger: slog.New(slog.NewTextHandler(&syncBuffer{}, &slog.HandlerOptions{Level: slog.LevelError})),
		Sinks:  map[config.HookKind]hook.Sink{config.HookKindWebhook: sink},
	})

	// Deliberately a separate context from the broker's, in the same order
	// main.go uses it.
	hookCtx, stopHooks := context.WithCancel(context.Background())
	dispatcher.Run(hookCtx)
	defer func() { stopHooks(); dispatcher.Wait() }()

	addr := freePort(t)
	br, err := New(Options{
		MQTTAddr: addr,
		Boards: []config.Board{
			{ID: username, Username: username, ACLFilters: []string{"msh/pvt/2/e/#"}},
		},
		ChannelPSKs: map[string][decode.PSKSize]byte{},
		AuthHook:    auth.New(map[string]string{username: string(hash)}, 5, 30*time.Minute, nil),
		Store:       store,
		Hooks:       dispatcher,
		Log:         slog.New(slog.NewTextHandler(&syncBuffer{}, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("broker.New: %v", err)
	}

	serveCtx, stopBroker := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- br.Serve(serveCtx) }()
	waitForListener(t, addr)

	cl := paho.NewClient(paho.NewClientOptions().
		AddBroker("tcp://" + addr).SetClientID("shutdown-probe").
		SetUsername(username).SetPassword(password).
		SetConnectTimeout(5 * time.Second).SetConnectRetry(false).SetAutoReconnect(false))
	if tok := cl.Connect(); tok.WaitTimeout(5*time.Second) && tok.Error() != nil {
		t.Fatalf("connect: %v", tok.Error())
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(br.ConnectedBoards()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	// Stop the broker while the client is still attached.
	stopBroker()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("broker did not shut down within 10s")
	}

	deadline = time.Now().Add(5 * time.Second)
	for !sink.sawEvent(`"event":"board_disconnected"`) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !sink.sawEvent(`"event":"board_disconnected"`) {
		t.Errorf("no board_disconnected event delivered during shutdown; bodies seen: %v", sink.all())
	}
	// The reason distinguishes this from a board that dropped off by itself,
	// which is the whole point of carrying one.
	for _, body := range sink.all() {
		if strings.Contains(body, `"event":"board_disconnected"`) &&
			!strings.Contains(body, "server shutting down") {
			t.Errorf("disconnect event does not say why: %s", body)
		}
	}
}
