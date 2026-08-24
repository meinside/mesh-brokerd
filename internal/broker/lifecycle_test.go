package broker

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"

	"github.com/meinside/mesh-brokerd/internal/auth"
	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
	"github.com/meinside/mesh-brokerd/internal/storage"
)

func newTestBroker(t *testing.T) (*Broker, *storage.Store) {
	t.Helper()

	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	br, err := New(Options{
		// Port 0 lets the kernel pick a free port, so these tests never
		// collide with a real brokerd or with each other.
		MQTTAddr:    "127.0.0.1:0",
		Boards:      []config.Board{{ID: "alpha", Username: "alpha"}},
		ChannelPSKs: map[string][decode.PSKSize]byte{},
		AuthHook:    auth.New(map[string]string{}, 5, 30*time.Minute, nil),
		Store:       store,
	})
	if err != nil {
		t.Fatalf("broker.New: %v", err)
	}
	return br, store
}

func TestBroker_New(t *testing.T) {
	br, _ := newTestBroker(t)
	if br.server == nil {
		t.Error("broker.server is nil")
	}
	if br.relay == nil {
		t.Error("broker.relay is nil")
	}
	if br.worker == nil {
		t.Error("broker.worker is nil")
	}
}

// TestBroker_ServeBlocksUntilContextCancelled guards a real bug this
// project shipped once: mochi-mqtt's own Server.Serve() only *starts*
// listeners and returns immediately, so an implementation that returns
// whatever Serve() returns exits instantly, taking brokerd down a few
// milliseconds after startup. Serve must block until ctx is cancelled.
func TestBroker_ServeBlocksUntilContextCancelled(t *testing.T) {
	br, _ := newTestBroker(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- br.Serve(ctx) }()

	// Serve must still be running after the broker has had time to come
	// up. If it returned already, the bug is back.
	select {
	case err := <-done:
		t.Fatalf("Serve returned before ctx was cancelled (err=%v) -- it must block", err)
	case <-time.After(300 * time.Millisecond):
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v after cancellation, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s of ctx cancellation (graceful shutdown hung, ADR-6)")
	}
}

func TestBroker_Counters(t *testing.T) {
	br, _ := newTestBroker(t)

	if got := br.DropCount(); got != 0 {
		t.Errorf("DropCount = %d, want 0 on a fresh broker", got)
	}
	if got := br.DecodeStatusCounts(); len(got) != 0 {
		t.Errorf("DecodeStatusCounts = %v, want empty on a fresh broker", got)
	}

	// With no relay engine configured, the counters must be empty but
	// non-nil so callers (internal/monitor) can serialize them without a
	// nil check.
	dryRun, published, failed := br.OutboundRelayCounters()
	for name, m := range map[string]map[string]int64{
		"dryRunTotal": dryRun, "publishedTotal": published, "publishFailuresTotal": failed,
	} {
		if m == nil {
			t.Errorf("%s is nil, want an empty non-nil map when no relay engine is configured", name)
		}
		if len(m) != 0 {
			t.Errorf("%s = %v, want empty", name, m)
		}
	}
}

// TestWorker_RunDrainsQueue covers the Run loop itself (processOne is
// exercised directly elsewhere): a message handed to the RelayHook must
// be picked up and stored without anyone calling processOne by hand.
func TestWorker_RunDrainsQueue(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	var psk [decode.PSKSize]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	relayHook := NewRelayHook(4)
	worker := NewWorker(relayHook, store, map[string][decode.PSKSize]byte{"pvt": psk},
		map[string]string{"alpha": "alpha"}, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go worker.Run(ctx)

	envelope := buildTestTextEnvelope(t, psk, 0x11223344, 777, "via run loop")
	relayHook.queue <- queuedMessage{
		Topic: "msh/pvt/2/e/pvt/!11223344", Payload: envelope,
		Username: "alpha", ReceivedAt: time.Now(),
	}

	deadline := time.After(3 * time.Second)
	for {
		var text string
		err := store.DB().QueryRow(`SELECT text FROM text_messages LIMIT 1;`).Scan(&text)
		if err == nil {
			if text != "via run loop" {
				t.Errorf("stored text = %q, want %q", text, "via run loop")
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("Run did not process the queued message within 3s")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestRelayHook_IDAndProvides(t *testing.T) {
	h := NewRelayHook(1)
	if h.ID() == "" {
		t.Error("ID() is empty")
	}
	if !h.Provides(mqtt.OnPublish) {
		t.Error("Provides(OnPublish) = false, want true")
	}
	if h.Provides(mqtt.OnConnectAuthenticate) {
		t.Error("Provides(OnConnectAuthenticate) = true, want false (relay hook must not claim auth)")
	}
}
