package broker

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
	"golang.org/x/crypto/bcrypt"

	"github.com/meinside/mesh-brokerd/internal/auth"
	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
	"github.com/meinside/mesh-brokerd/internal/storage"
)

// syncBuffer is a goroutine-safe log sink. Both brokerd's own logging and
// mochi-mqtt's happen on connection-handling goroutines, so an unguarded
// bytes.Buffer here would be a data race, not merely untidy.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Reset()
}

// freePort asks the kernel for an unused port and hands it back. Binding
// the broker to :0 would hide which port it actually got, and mochi-mqtt
// does not expose it.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("closing probe listener: %v", err)
	}
	return addr
}

// serveAuthBroker starts a plaintext broker accepting exactly one
// credential pair, with all logging captured in sink.
func serveAuthBroker(t *testing.T, sink *syncBuffer, username, password string) string {
	return serveAuthBrokerAtLevel(t, sink, username, password, slog.LevelInfo)
}

func serveAuthBrokerAtLevel(t *testing.T, sink *syncBuffer, username, password string, level slog.Level) string {
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
		MQTTAddr:    addr,
		Boards:      []config.Board{{ID: username, Username: username, ACLFilters: []string{"msh/pvt/2/e/#"}}},
		ChannelPSKs: map[string][decode.PSKSize]byte{},
		AuthHook:    auth.New(map[string]string{username: string(hash)}, 5, 30*time.Minute, nil),
		Store:       store,
		Log:         slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: level})),
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

	// Wait for the listener rather than sleeping a fixed amount.
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
	return addr
}

func connectMQTT(t *testing.T, addr, clientID, username, password string) error {
	t.Helper()
	opts := paho.NewClientOptions().
		AddBroker("tcp://" + addr).
		SetClientID(clientID).
		SetUsername(username).
		SetPassword(password).
		SetConnectTimeout(5 * time.Second).
		SetConnectRetry(false).
		SetAutoReconnect(false)
	c := paho.NewClient(opts)
	tok := c.Connect()
	if !tok.WaitTimeout(6 * time.Second) {
		return fmt.Errorf("connect timed out")
	}
	if err := tok.Error(); err != nil {
		return err
	}
	t.Cleanup(func() { c.Disconnect(50) })
	return nil
}

// A successful connection must not be reported in the log as a failure.
//
// mochi-mqtt dispatches OnConnectAuthenticate to every hook providing it
// and stops at the first one returning true (an OR). Its own ACL hook
// provides that method but cannot authenticate — brokerd's Ledger holds no
// usable password material by design (internal/auth.BuildLedger) — so it
// returns false and logs "client failed authentication check".
//
// Registered before brokerd's bcrypt hook, it logs that line on every
// *successful* connection. Registered after, the OR short-circuits and it
// is never reached on success. The connection outcome is identical either
// way, which is precisely why this needs a test: only the log differs, and
// a misleading auth log is how a real board's provisioning turned into guesswork
// about whether the board had connected at all.
func TestBroker_SuccessfulAuthIsNotLoggedAsFailure(t *testing.T) {
	const (
		username = "alpha"
		password = "correct-horse-battery-staple"
		mochiMsg = "client failed authentication check"
	)

	var sink syncBuffer
	addr := serveAuthBroker(t, &sink, username, password)

	// First establish that mochi-mqtt's hook logging really reaches the
	// sink. Without this, the assertion below would also pass on a broker
	// that merely routed mochi's output elsewhere, making it worthless.
	if err := connectMQTT(t, addr, "bad", username, "wrong-password"); err == nil {
		t.Fatal("connect with a wrong password succeeded, want rejection")
	}
	if !strings.Contains(sink.String(), mochiMsg) {
		t.Fatalf("mochi-mqtt's hook logging is not captured, so this test cannot detect the bug; got %q", sink.String())
	}

	sink.Reset()

	if err := connectMQTT(t, addr, "good", username, password); err != nil {
		t.Fatalf("connect with correct credentials failed: %v", err)
	}
	// The accept path logs from a different goroutine than the test.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(sink.String(), "auth: accepted") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	out := sink.String()
	if !strings.Contains(out, "auth: accepted") {
		t.Errorf("successful connection produced no success line; log: %s", out)
	}
	if strings.Contains(out, mochiMsg) {
		t.Errorf("successful connection logged %q; the ACL hook must be registered after the auth hook so the OR short-circuits before reaching it.\nlog: %s", mochiMsg, out)
	}
}

// A board publishing outside its ACL must be diagnosable.
//
// mochi-mqtt logs ACL denials at DEBUG (hooks/auth/auth.go's OnACLCheck),
// so at brokerd's default INFO level a board with, say, the wrong
// mqtt.root connects and authenticates normally and then has every
// publish dropped in complete silence. That is the worst possible failure
// shape: the operator sees a healthy connection and no data, with nothing
// in the log to distinguish it from a board that simply has nothing to
// send. brokerd's -log-level flag exists for exactly this, so assert both
// halves: debug shows the denial, info hides it.
func TestBroker_ACLDenialIsVisibleAtDebugOnly(t *testing.T) {
	const (
		username = "alpha"
		password = "correct-horse-battery-staple"
		// A topic outside the board's acl_filters ("msh/pvt/2/e/#"),
		// which is what a misconfigured mqtt.root produces.
		deniedTopic = "msh/2/e/SomeChannel/!deadbeef"
		aclMsg      = "failed allowed ACL check"
	)

	publishDenied := func(t *testing.T, level slog.Level) string {
		t.Helper()
		var sink syncBuffer
		addr := serveAuthBrokerAtLevel(t, &sink, username, password, level)
		if err := connectMQTT(t, addr, "pub", username, password); err != nil {
			t.Fatalf("connect: %v", err)
		}
		// Reconnect a client we can publish with, then wait for the log.
		opts := paho.NewClientOptions().AddBroker("tcp://" + addr).
			SetClientID("pub2").SetUsername(username).SetPassword(password).
			SetConnectTimeout(5 * time.Second).SetAutoReconnect(false)
		c := paho.NewClient(opts)
		tok := c.Connect()
		if !tok.WaitTimeout(6*time.Second) || tok.Error() != nil {
			t.Fatalf("second connect failed: %v", tok.Error())
		}
		defer c.Disconnect(50)
		pt := c.Publish(deniedTopic, 0, false, []byte("x"))
		pt.WaitTimeout(5 * time.Second)

		// Generous budget on purpose: this ran with 2s and passed in
		// isolation while failing under `make check`, where every package
		// competes for the machine. A log-timing test that only holds on
		// an idle box is worse than no test, because the failure looks
		// like the behaviour regressed.
		//
		// At debug level this loop exits as soon as the line appears. At
		// info level nothing will ever appear, so it necessarily waits out
		// the whole window -- that is the cost of asserting a negative
		// about logging, and the window is what bounds the confidence.
		deadline := time.Now().Add(10 * time.Second)
		for !strings.Contains(sink.String(), aclMsg) && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		return sink.String()
	}

	if out := publishDenied(t, slog.LevelDebug); !strings.Contains(out, aclMsg) {
		t.Errorf("at debug level, a denied publish left no %q line; the -log-level flag would not help diagnose a wrong mqtt.root.\nlog: %s", aclMsg, out)
	}
	if out := publishDenied(t, slog.LevelInfo); strings.Contains(out, aclMsg) {
		t.Errorf("at info level the denial was logged after all, so -log-level debug is not needed for this; update the flag's documentation.\nlog: %s", out)
	}
}
