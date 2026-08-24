package broker

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
	"github.com/meinside/mesh-brokerd/internal/storage"
)

// warnCapture collects formatted warning text so a test can assert both
// "was a warning emitted" and "how many times".
type warnCapture struct {
	lines []string
}

func (c *warnCapture) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelWarn }

func (c *warnCapture) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString(" " + a.Key + "=" + a.Value.String())
		return true
	})
	c.lines = append(c.lines, b.String())
	return nil
}

func (c *warnCapture) WithAttrs(_ []slog.Attr) slog.Handler { return c }
func (c *warnCapture) WithGroup(_ string) slog.Handler      { return c }

// anonymised board set: real node IDs are never committed
func testBoards() []config.Board {
	return []config.Board{
		{ID: "alpha", Username: "alpha", NodeID: "!11223344", NodeIDDec: 0x11223344, HasNodeID: true},
		{ID: "bravo", Username: "bravo"}, // no node_id declared
	}
}

func newTestChecker() (*NodeIDChecker, *warnCapture, *slog.Logger) {
	cap := &warnCapture{}
	return NewNodeIDChecker(testBoards()), cap, slog.New(cap)
}

func TestNodeIDChecker_SilentWhenGatewayMatchesDeclared(t *testing.T) {
	c, cap, log := newTestChecker()

	c.Check("alpha", "!11223344", log)

	if len(cap.lines) != 0 {
		t.Errorf("warned on a matching gateway_id: %v", cap.lines)
	}
	if len(c.Mismatches()) != 0 {
		t.Errorf("counted a mismatch for a matching gateway_id: %v", c.Mismatches())
	}
}

func TestNodeIDChecker_MatchIsCaseInsensitive(t *testing.T) {
	c, cap, log := newTestChecker()

	c.Check("alpha", "!11223344", log)
	c.Check("alpha", "!11223344", log) // same value, different case would be equivalent

	if len(cap.lines) != 0 {
		t.Errorf("warned on a matching gateway_id: %v", cap.lines)
	}
}

// TestNodeIDChecker_WarnsOncePerObservedValue encodes the decision: warn
// once (an operator does not need the same line on every frame), but keep
// counting, so the monitoring API shows it is still happening.
func TestNodeIDChecker_WarnsOncePerObservedValue(t *testing.T) {
	c, cap, log := newTestChecker()

	for range 5 {
		c.Check("alpha", "!99aabbcc", log)
	}

	if len(cap.lines) != 1 {
		t.Fatalf("emitted %d warnings for the same mismatch, want exactly 1: %v", len(cap.lines), cap.lines)
	}
	if !strings.Contains(cap.lines[0], "alpha") {
		t.Errorf("warning does not name the board: %q", cap.lines[0])
	}
	if got := c.Mismatches()["alpha"]; got != 5 {
		t.Errorf("Mismatches()[alpha] = %d, want 5 (every occurrence counted)", got)
	}
}

func TestNodeIDChecker_WarnsAgainForADifferentObservedValue(t *testing.T) {
	c, cap, log := newTestChecker()

	c.Check("alpha", "!99aabbcc", log)
	c.Check("alpha", "!55667788", log)

	if len(cap.lines) != 2 {
		t.Errorf("got %d warnings for two distinct mismatching IDs, want 2: %v", len(cap.lines), cap.lines)
	}
}

// TestNodeIDChecker_IgnoresBoardWithoutDeclaredNodeID matters because
// node_id is optional in config (docs/brokerd-config.md): a board that
// declares nothing cannot be said to have drifted from anything.
func TestNodeIDChecker_IgnoresBoardWithoutDeclaredNodeID(t *testing.T) {
	c, cap, log := newTestChecker()

	c.Check("bravo", "!99aabbcc", log)

	if len(cap.lines) != 0 {
		t.Errorf("warned about a board with no declared node_id: %v", cap.lines)
	}
	if len(c.Mismatches()) != 0 {
		t.Errorf("counted a mismatch for a board with no declared node_id: %v", c.Mismatches())
	}
}

func TestNodeIDChecker_IgnoresEmptyInputs(t *testing.T) {
	c, cap, log := newTestChecker()

	c.Check("", "!99aabbcc", log) // unknown/unmapped username
	c.Check("alpha", "", log)     // frame carried no gateway_id
	c.Check("unknown", "!1", log) // board id not in config

	if len(cap.lines) != 0 {
		t.Errorf("warned on empty/unknown input: %v", cap.lines)
	}
	if len(c.Mismatches()) != 0 {
		t.Errorf("counted a mismatch on empty/unknown input: %v", c.Mismatches())
	}
}

func TestNodeIDChecker_MismatchesAreCopied(t *testing.T) {
	c, _, log := newTestChecker()
	c.Check("alpha", "!99aabbcc", log)

	m := c.Mismatches()
	m["alpha"] = 99
	if again := c.Mismatches()["alpha"]; again != 1 {
		t.Errorf("Mismatches() returned an aliased map: got %d after caller mutation, want 1", again)
	}
}

// TestWorker_InvokesNodeIDChecker proves the checker is actually reached
// from the storage worker's real path, not merely correct in isolation.
// This project has been bitten three times by a correct predicate that
// no caller ever consulted, so the wiring gets its own test.
func TestWorker_InvokesNodeIDChecker(t *testing.T) {
	store, openErr := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if openErr != nil {
		t.Fatalf("storage.Open: %v", openErr)
	}
	defer func() { _ = store.Close() }()

	var psk [decode.PSKSize]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}

	// Board "alpha" declares !11223344 but its frames arrive with a
	// gateway_id of !99aabbcc -- the drift this check exists to catch.
	checker := NewNodeIDChecker([]config.Board{
		{ID: "alpha", Username: "alpha", NodeID: "!11223344", NodeIDDec: 0x11223344, HasNodeID: true},
	})
	cap := &warnCapture{}
	worker := NewWorker(NewRelayHook(4), store, map[string][decode.PSKSize]byte{"pvt": psk},
		map[string]string{"alpha": "alpha"}, nil, checker, slog.New(cap))

	// Built here rather than with buildTestTextEnvelope, which hardcodes a
	// gateway_id of !11223344: the point of this test is a *differing*
	// gateway_id, and the check keys on that field (the publishing
	// gateway's own ID), not on from_node.
	data := decode.EncodeData(decode.PortNumTextMessage, []byte("drifted"))
	ciphertext, err := decode.CryptCTR(psk[:], decode.DeriveNonce(4242, 0x99aabbcc), data)
	if err != nil {
		t.Fatalf("CryptCTR: %v", err)
	}
	mp := decode.EncodeMeshPacket(decode.MeshPacketFields{
		From: 0x99aabbcc, To: 0xffffffff, ID: 4242,
		ChannelHash: decode.ChannelHash("pvt", psk[:]), Encrypted: ciphertext,
	})
	envelope := decode.EncodeServiceEnvelope(mp, "pvt", "!99aabbcc")
	worker.processOne(queuedMessage{
		Topic: "msh/pvt/2/e/pvt/!99aabbcc", Payload: envelope,
		Username: "alpha", ReceivedAt: time.Now(),
	})

	if got := checker.Mismatches()["alpha"]; got != 1 {
		t.Errorf("Mismatches()[alpha] = %d, want 1 — the worker never called the checker", got)
	}
	if len(cap.lines) == 0 {
		t.Error("no warning logged for a drifted node_id reaching the real worker path")
	}
}
