package broker

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
	mqtt "github.com/mochi-mqtt/server/v2"
)

// TestACLDenialLogger_NeverGrants is the safety property this hook lives
// or dies by. mochi-mqtt combines OnACLCheck across hooks as an OR that
// stops at the first `true` (server/hooks.go, OnACLCheck), so a hook that
// ever returned true would silently grant access the ACL ledger had just
// refused. It must always return false, for every input.
func TestACLDenialLogger_NeverGrants(t *testing.T) {
	l := NewACLDenialLogger(slog.New(&warnCapture{}))

	for _, tc := range []struct {
		topic string
		write bool
	}{
		{"msh/pvt/2/e/pvt/!11223344", true},
		{"msh/pvt/2/e/pvt/!11223344", false},
		{"#", true},
		{"$SYS/broker/uptime", false},
		{"", true},
	} {
		if l.OnACLCheck(&mqtt.Client{}, tc.topic, tc.write) {
			t.Errorf("OnACLCheck(%q, write=%v) = true; this hook must never grant access", tc.topic, tc.write)
		}
	}
}

// TestACLDenialLogger_ProvidesOnlyACLCheck keeps the hook from taking part
// in authentication: mochi dispatches OnConnectAuthenticate as the same
// kind of first-true-wins OR, and a hook that answered it would let
// anyone in.
func TestACLDenialLogger_ProvidesOnlyACLCheck(t *testing.T) {
	l := NewACLDenialLogger(slog.New(&warnCapture{}))

	if !l.Provides(mqtt.OnACLCheck) {
		t.Error("Provides(OnACLCheck) = false; the hook would never be consulted")
	}
	for _, b := range []byte{mqtt.OnConnectAuthenticate, mqtt.OnPublish, mqtt.OnConnect} {
		if l.Provides(b) {
			t.Errorf("Provides(%d) = true; this hook must only answer OnACLCheck", b)
		}
	}
}

func TestACLDenialLogger_LogsOncePerKeyButCountsEvery(t *testing.T) {
	cap := &warnCapture{}
	l := NewACLDenialLogger(slog.New(cap))
	cl := &mqtt.Client{}
	cl.Properties.Username = []byte("alpha")

	for range 4 {
		l.OnACLCheck(cl, "msh/other/2/e/x/!11223344", true)
	}

	if len(cap.lines) != 1 {
		t.Fatalf("logged %d times for the same denial, want 1: %v", len(cap.lines), cap.lines)
	}
	if !strings.Contains(cap.lines[0], "msh/other/2/e/x/!11223344") {
		t.Errorf("log line does not name the refused topic: %q", cap.lines[0])
	}
	if got := l.Denials()["alpha"]; got != 4 {
		t.Errorf("Denials()[alpha] = %d, want 4 (every denial counted)", got)
	}
}

func TestACLDenialLogger_SeparatesReadFromWrite(t *testing.T) {
	cap := &warnCapture{}
	l := NewACLDenialLogger(slog.New(cap))
	cl := &mqtt.Client{}
	cl.Properties.Username = []byte("alpha")

	l.OnACLCheck(cl, "msh/other/#", true)  // publish
	l.OnACLCheck(cl, "msh/other/#", false) // subscribe/read

	if len(cap.lines) != 2 {
		t.Fatalf("got %d log lines for a write and a read denial, want 2: %v", len(cap.lines), cap.lines)
	}
	joined := strings.Join(cap.lines, "\n")
	if !strings.Contains(joined, "publish") || !strings.Contains(joined, "subscribe") {
		t.Errorf("log lines do not distinguish publish from subscribe: %q", joined)
	}
}

func TestACLDenialLogger_CountsAreCopied(t *testing.T) {
	l := NewACLDenialLogger(slog.New(&warnCapture{}))
	cl := &mqtt.Client{}
	cl.Properties.Username = []byte("alpha")
	l.OnACLCheck(cl, "msh/other/#", true)

	d := l.Denials()
	d["alpha"] = 99
	if again := l.Denials()["alpha"]; again != 1 {
		t.Errorf("Denials() returned an aliased map: got %d after caller mutation, want 1", again)
	}
}

// TestBroker_ACLDenialIsObservable is the test that justifies the whole
// hook. mochi-mqtt answers a QoS 0 publish that fails the ACL with a bare
// `return nil` (server.go: `if pk.FixedHeader.Qos == 0 { return nil }`) --
// no log, no counter, no disconnect -- and Meshtastic publishes at QoS 0.
// A real investigation could not tell "the board never
// published" from "the board published and was silently refused" because
// of exactly that. This test drives a real client through a real broker
// and proves the denial is now visible.
func TestBroker_ACLDenialIsObservable(t *testing.T) {
	sink := &syncBuffer{}
	addr := serveAuthBroker(t, sink, "alpha", "correct-horse")

	// serveAuthBroker grants ACL only on msh/pvt/2/e/# .
	opts := paho.NewClientOptions().
		AddBroker("tcp://" + addr).
		SetClientID("acl-denial-probe").
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

	// QoS 0 publish outside the ACL: the client is told nothing, exactly as
	// a board would be.
	tok := cl.Publish("msh/elsewhere/2/e/pvt/!11223344", 0, false, []byte{0x01})
	tok.WaitTimeout(2 * time.Second)
	if err := tok.Error(); err != nil {
		t.Fatalf("publish returned an error, so this is no longer the silent path: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(sink.String(), "acl: refused") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	logged := sink.String()
	if !strings.Contains(logged, "acl: refused") {
		t.Fatalf("a silently-refused QoS 0 publish left no log line; log was:\n%s", logged)
	}
	if !strings.Contains(logged, "msh/elsewhere/2/e/pvt/!11223344") {
		t.Errorf("log line does not name the refused topic; log was:\n%s", logged)
	}
	if !strings.Contains(logged, "alpha") {
		t.Errorf("log line does not name the client; log was:\n%s", logged)
	}
}

// TestBroker_AllowedPublishIsNotLoggedAsDenial is the other half of the
// registration-order assumption, and the half that would hurt if wrong:
// if this hook were consulted before the ACL ledger (or for every check
// rather than only refused ones), every legitimate frame from every board
// would log "acl: refused" and the log would be worse than before the
// hook existed.
func TestBroker_AllowedPublishIsNotLoggedAsDenial(t *testing.T) {
	sink := &syncBuffer{}
	addr := serveAuthBroker(t, sink, "alpha", "correct-horse")

	opts := paho.NewClientOptions().
		AddBroker("tcp://" + addr).
		SetClientID("acl-allowed-probe").
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

	// Inside serveAuthBroker's granted filter (msh/pvt/2/e/#).
	tok := cl.Publish("msh/pvt/2/e/pvt/!11223344", 0, false, []byte{0x01})
	tok.WaitTimeout(2 * time.Second)
	if err := tok.Error(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// Also exercise a subscribe, which mochi ACL-checks on its own path.
	if stok := cl.Subscribe("msh/pvt/2/e/#", 0, nil); stok.WaitTimeout(2*time.Second) && stok.Error() != nil {
		t.Fatalf("subscribe: %v", stok.Error())
	}

	time.Sleep(200 * time.Millisecond) // give any stray log line time to appear
	if logged := sink.String(); strings.Contains(logged, "acl: refused") {
		t.Errorf("an allowed publish/subscribe was logged as an ACL denial; log was:\n%s", logged)
	}
}

// TestACLDenialLogger_LogTableIsBounded covers a slow leak in the component
// that must not fall over: the log-once table is keyed by topic, so a client
// refused across many topics would grow it without limit. Past the cap it
// stops growing, warns once, and keeps counting per username -- which is what
// the monitoring API reads.
func TestACLDenialLogger_LogTableIsBounded(t *testing.T) {
	var logs syncBuffer
	h := NewACLDenialLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cl := &mqtt.Client{Properties: mqtt.ClientProperties{Username: []byte("alpha")}}
	const attempts = maxLoggedACLKeys + 500
	for i := 0; i < attempts; i++ {
		h.OnACLCheck(cl, fmt.Sprintf("msh/pvt/2/e/pvt/!%08x", i), true)
	}

	h.mu.Lock()
	tracked := len(h.logged)
	h.mu.Unlock()
	if tracked > maxLoggedACLKeys {
		t.Errorf("log table holds %d keys, want at most %d", tracked, maxLoggedACLKeys)
	}

	// Every refusal is still counted, which is the number that matters.
	if got := h.Denials()["alpha"]; got != int64(attempts) {
		t.Errorf("acl_denials_total[alpha] = %d, want %d", got, attempts)
	}

	if !strings.Contains(logs.String(), "too many distinct refusals") {
		t.Errorf("no warning when the log table filled up")
	}
	if got := strings.Count(logs.String(), "too many distinct refusals"); got != 1 {
		t.Errorf("cap warning logged %d times, want exactly 1", got)
	}
}
