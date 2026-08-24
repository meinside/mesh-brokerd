package auth

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
	"golang.org/x/crypto/bcrypt"
)

func hashFor(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	return string(h)
}

func newTestClient(remote string) *mqtt.Client {
	cl := &mqtt.Client{}
	cl.Net.Remote = remote
	return cl
}

func connectPacket(username, password string) packets.Packet {
	return packets.Packet{
		Connect: packets.ConnectParams{
			Username: []byte(username),
			Password: []byte(password),
		},
	}
}

func TestOnConnectAuthenticate_CorrectPassword(t *testing.T) {
	h := New(map[string]string{"alpha": hashFor(t, "correct-password")}, 5, 30*time.Minute, nil)
	cl := newTestClient("203.0.113.1:5555")

	if !h.OnConnectAuthenticate(cl, connectPacket("alpha", "correct-password")) {
		t.Fatal("expected authentication to succeed with the correct password")
	}
}

func TestOnConnectAuthenticate_WrongPassword(t *testing.T) {
	h := New(map[string]string{"alpha": hashFor(t, "correct-password")}, 5, 30*time.Minute, nil)
	cl := newTestClient("203.0.113.2:5555")

	if h.OnConnectAuthenticate(cl, connectPacket("alpha", "wrong-password")) {
		t.Fatal("expected authentication to fail with the wrong password")
	}
}

func TestOnConnectAuthenticate_UnknownUsername(t *testing.T) {
	h := New(map[string]string{"alpha": hashFor(t, "correct-password")}, 5, 30*time.Minute, nil)
	cl := newTestClient("203.0.113.3:5555")

	if h.OnConnectAuthenticate(cl, connectPacket("board_intruder", "anything")) {
		t.Fatal("expected authentication to fail for an unknown username")
	}
}

func TestOnConnectAuthenticate_BansAfterThreshold(t *testing.T) {
	h := New(map[string]string{"alpha": hashFor(t, "correct-password")}, 3, 30*time.Minute, nil)
	cl := newTestClient("203.0.113.4:5555")

	for i := 0; i < 3; i++ {
		if h.OnConnectAuthenticate(cl, connectPacket("alpha", "wrong")) {
			t.Fatalf("attempt %d: expected failure", i)
		}
	}

	// The account is now banned — even the *correct* password must be
	// rejected while banned (ADR-5).
	if h.OnConnectAuthenticate(cl, connectPacket("alpha", "correct-password")) {
		t.Fatal("expected the correct password to still be rejected while the IP is banned")
	}

	bans := h.ActiveBans()
	if len(bans) != 1 || bans[0].IP != "203.0.113.4" {
		t.Fatalf("ActiveBans() = %+v, want one ban for 203.0.113.4", bans)
	}
}

func TestOnConnectAuthenticate_SuccessResetsFailureCount(t *testing.T) {
	h := New(map[string]string{"alpha": hashFor(t, "correct-password")}, 3, 30*time.Minute, nil)
	cl := newTestClient("203.0.113.5:5555")

	h.OnConnectAuthenticate(cl, connectPacket("alpha", "wrong"))
	h.OnConnectAuthenticate(cl, connectPacket("alpha", "wrong"))
	if !h.OnConnectAuthenticate(cl, connectPacket("alpha", "correct-password")) {
		t.Fatal("expected the correct password to succeed before the threshold is reached")
	}

	// Failure state should be cleared, so a fresh failure doesn't
	// immediately ban (threshold is 3, this is only the 1st since reset).
	h.OnConnectAuthenticate(cl, connectPacket("alpha", "wrong"))
	if banned, _ := h.isBanned("203.0.113.5"); banned {
		t.Fatal("expected no ban immediately after a success reset the failure count")
	}
}

func TestOnConnectAuthenticate_IPAllowlistExempt(t *testing.T) {
	h := New(map[string]string{"alpha": hashFor(t, "correct-password")}, 1, 30*time.Minute, []string{"203.0.113.6"})
	cl := newTestClient("203.0.113.6:5555")

	// Threshold is 1, but this IP is allowlisted, so repeated failures
	// must never result in a ban.
	for i := 0; i < 5; i++ {
		h.OnConnectAuthenticate(cl, connectPacket("alpha", "wrong"))
	}
	if !h.OnConnectAuthenticate(cl, connectPacket("alpha", "correct-password")) {
		t.Fatal("expected the correct password to still succeed for an allowlisted IP")
	}
}

func TestFailuresTotal(t *testing.T) {
	h := New(map[string]string{"alpha": hashFor(t, "correct-password")}, 5, 30*time.Minute, nil)
	cl := newTestClient("203.0.113.7:5555")

	h.OnConnectAuthenticate(cl, connectPacket("alpha", "wrong"))
	h.OnConnectAuthenticate(cl, connectPacket("alpha", "wrong"))
	if got := h.FailuresTotal(); got != 2 {
		t.Errorf("FailuresTotal() = %d, want 2", got)
	}
}

// A successful connection must leave a positive trace in the log.
//
// Without one, the only server-side evidence that a board authenticated is
// the absence of a rejection line — and mochi-mqtt's own ACL hook logs
// "client failed authentication check" for every successful connection too
// (it is consulted for ACL purposes and declines to authenticate), so an
// operator reading the log sees a failure message and no success message.
// Diagnosing a real board this way cost time while provisioning the second
// gateway.
func TestOnConnectAuthenticate_LogsAcceptedConnection(t *testing.T) {
	const password = "correct-horse-battery-staple"
	hash := hashFor(t, password)

	var buf bytes.Buffer
	h := New(map[string]string{"alpha": hash}, 5, 30*time.Minute, nil)
	h.Log = slog.New(slog.NewTextHandler(&buf, nil))

	if !h.OnConnectAuthenticate(newTestClient("203.0.113.9:1234"), connectPacket("alpha", password)) {
		t.Fatal("OnConnectAuthenticate = false, want true for correct credentials")
	}

	out := buf.String()
	if !strings.Contains(out, "auth: accepted") {
		t.Errorf("accepted connection produced no success log line; got %q", out)
	}
	if !strings.Contains(out, "alpha") {
		t.Errorf("success log line omits the username, which is what identifies the board; got %q", out)
	}
	if !strings.Contains(out, "203.0.113.9") {
		t.Errorf("success log line omits the remote IP; got %q", out)
	}
	// docs/security.md §7: credentials must never reach the log, on any path.
	if strings.Contains(out, password) {
		t.Error("success log line contains the plaintext password")
	}
	if strings.Contains(out, hash) {
		t.Error("success log line contains the bcrypt hash")
	}
}

// The rejection path must stay silent about credentials too.
func TestOnConnectAuthenticate_RejectionLogsNoCredentials(t *testing.T) {
	const password = "correct-horse-battery-staple"

	var buf bytes.Buffer
	h := New(map[string]string{"alpha": hashFor(t, password)}, 5, 30*time.Minute, nil)
	h.Log = slog.New(slog.NewTextHandler(&buf, nil))

	if h.OnConnectAuthenticate(newTestClient("203.0.113.9:1234"), connectPacket("alpha", "wrong-password")) {
		t.Fatal("OnConnectAuthenticate = true, want false for a wrong password")
	}

	out := buf.String()
	if !strings.Contains(out, "auth: rejected") {
		t.Errorf("rejected connection produced no rejection log line; got %q", out)
	}
	if strings.Contains(out, "wrong-password") {
		t.Error("rejection log line contains the attempted password")
	}
}
