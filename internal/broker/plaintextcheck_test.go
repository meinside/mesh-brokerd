package broker

import (
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/meinside/mesh-brokerd/internal/decode"
	"github.com/meinside/mesh-brokerd/internal/storage"
)

func testPSK() [decode.PSKSize]byte {
	var psk [decode.PSKSize]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	return psk
}

func newTestPlaintextChecker() (*PlaintextChecker, *warnCapture, *slog.Logger) {
	cap := &warnCapture{}
	return NewPlaintextChecker(map[string][decode.PSKSize]byte{"pvt": testPSK()}), cap, slog.New(cap)
}

func TestPlaintextChecker_SilentOnAnEncryptedFrame(t *testing.T) {
	c, cap, log := newTestPlaintextChecker()

	c.Check("alpha", &decode.Result{ChannelSegment: "pvt", ArrivedPlaintext: false}, log)

	if len(cap.lines) != 0 {
		t.Errorf("warned about a frame that arrived encrypted: %v", cap.lines)
	}
	if len(c.PlaintextUplinks()) != 0 {
		t.Errorf("counted a frame that arrived encrypted: %v", c.PlaintextUplinks())
	}
}

// TestPlaintextChecker_IgnoresMapReports encodes the one legitimate case:
// a map report is unencrypted by design (docs/firmware-config.md §14), so
// flagging it would make the counter useless noise on any deployment that
// relays them.
func TestPlaintextChecker_IgnoresMapReports(t *testing.T) {
	c, cap, log := newTestPlaintextChecker()

	c.Check("alpha", &decode.Result{ChannelSegment: "pvt", ArrivedPlaintext: true, MapReport: true}, log)

	if len(cap.lines) != 0 {
		t.Errorf("warned about a map report: %v", cap.lines)
	}
	if len(c.PlaintextUplinks()) != 0 {
		t.Errorf("counted a map report: %v", c.PlaintextUplinks())
	}
}

// A channel brokerd holds no PSK for gives no basis to say encryption was
// expected -- that frame is already reported as unknown_channel.
func TestPlaintextChecker_IgnoresChannelWithNoConfiguredPSK(t *testing.T) {
	c, cap, log := newTestPlaintextChecker()

	c.Check("alpha", &decode.Result{ChannelSegment: "LongFast", ArrivedPlaintext: true}, log)

	if len(cap.lines) != 0 {
		t.Errorf("warned about a channel with no configured PSK: %v", cap.lines)
	}
	if len(c.PlaintextUplinks()) != 0 {
		t.Errorf("counted a channel with no configured PSK: %v", c.PlaintextUplinks())
	}
}

// Same policy as NodeIDChecker: one log line per (board, channel), but every
// occurrence counted, so the monitoring API shows it is ongoing.
func TestPlaintextChecker_WarnsOncePerBoardChannelButKeepsCounting(t *testing.T) {
	c, cap, log := newTestPlaintextChecker()

	for range 5 {
		c.Check("alpha", &decode.Result{ChannelSegment: "pvt", ArrivedPlaintext: true}, log)
	}

	if len(cap.lines) != 1 {
		t.Fatalf("emitted %d warnings, want exactly 1: %v", len(cap.lines), cap.lines)
	}
	if !strings.Contains(cap.lines[0], "alpha") || !strings.Contains(cap.lines[0], "pvt") {
		t.Errorf("warning names neither the board nor the channel: %q", cap.lines[0])
	}
	if !strings.Contains(cap.lines[0], "encryption_enabled") {
		t.Errorf("warning does not name the setting an operator has to change: %q", cap.lines[0])
	}
	if got := c.PlaintextUplinks()["alpha"]; got != 5 {
		t.Errorf("PlaintextUplinks()[alpha] = %d, want 5 (every occurrence counted)", got)
	}
}

// An MQTT account with no boards[] entry still publishes frames, and
// plaintext arriving from it is exactly as serious. Counting it under a
// placeholder keeps the evidence rather than discarding it.
func TestPlaintextChecker_CountsFramesFromAnUnmappedAccount(t *testing.T) {
	c, cap, log := newTestPlaintextChecker()

	c.Check("", &decode.Result{ChannelSegment: "pvt", ArrivedPlaintext: true}, log)

	if len(cap.lines) != 1 {
		t.Fatalf("emitted %d warnings for an unmapped account, want 1: %v", len(cap.lines), cap.lines)
	}
	if got := c.PlaintextUplinks()["(unknown board)"]; got != 1 {
		t.Errorf("PlaintextUplinks()[(unknown board)] = %d, want 1", got)
	}
}

func TestPlaintextChecker_CountersAreCopied(t *testing.T) {
	c, _, log := newTestPlaintextChecker()
	c.Check("alpha", &decode.Result{ChannelSegment: "pvt", ArrivedPlaintext: true}, log)

	m := c.PlaintextUplinks()
	m["alpha"] = 99
	if again := c.PlaintextUplinks()["alpha"]; again != 1 {
		t.Errorf("PlaintextUplinks() returned an aliased map: got %d after caller mutation, want 1", again)
	}
}

// TestWorker_FlagsPlaintextFrameOnPSKChannel is the wiring test, and the
// regression test for the misconfiguration itself: before this check, a board
// with mqtt.encryption_enabled = false stored readable text with every
// counter healthy, so nothing distinguished it from a correctly configured
// one.
func TestWorker_FlagsPlaintextFrameOnPSKChannel(t *testing.T) {
	store, openErr := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if openErr != nil {
		t.Fatalf("storage.Open: %v", openErr)
	}
	defer func() { _ = store.Close() }()

	psk := testPSK()
	cap := &warnCapture{}
	worker := NewWorker(NewRelayHook(4), store, map[string][decode.PSKSize]byte{"pvt": psk},
		map[string]string{"alpha": "alpha"}, nil, nil, slog.New(cap))

	// A gateway with mqtt.encryption_enabled = false publishes the Data in
	// the `decoded` variant: the channel PSK is configured on both sides and
	// simply not applied on the MQTT hop.
	data := decode.EncodeData(decode.PortNumTextMessage, []byte("in the clear"))
	envelope := decode.EncodeServiceEnvelope(
		decode.EncodeMeshPacketDecoded(0x11223344, 0xffffffff, 4242, data),
		"pvt", "!11223344")

	worker.processOne(queuedMessage{
		Topic: "msh/pvt/2/e/pvt/!11223344", Payload: envelope,
		Username: "alpha", ReceivedAt: time.Now(),
	})

	if got := worker.PlaintextUplinks()["alpha"]; got != 1 {
		t.Errorf("PlaintextUplinks()[alpha] = %d, want 1 — the worker never ran the check", got)
	}
	if len(cap.lines) == 0 {
		t.Error("no warning logged for a plaintext frame reaching the real worker path")
	}
	// The frame is still stored and still decoded: warn, never act. Dropping
	// it would destroy the only evidence of the misconfiguration.
	if counts := worker.DecodeStatusCounts(); counts[string(decode.StatusDecoded)] != 1 {
		t.Errorf("DecodeStatusCounts() = %v, want decoded=1 (the frame must not be refused)", counts)
	}
}

// The mirror case: a properly encrypted frame on the same channel must leave
// the counter at zero, or the check would fire on every healthy deployment.
func TestWorker_DoesNotFlagAnEncryptedFrame(t *testing.T) {
	store, openErr := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if openErr != nil {
		t.Fatalf("storage.Open: %v", openErr)
	}
	defer func() { _ = store.Close() }()

	psk := testPSK()
	cap := &warnCapture{}
	worker := NewWorker(NewRelayHook(4), store, map[string][decode.PSKSize]byte{"pvt": psk},
		map[string]string{"alpha": "alpha"}, nil, nil, slog.New(cap))

	data := decode.EncodeData(decode.PortNumTextMessage, []byte("encrypted"))
	ciphertext, err := decode.CryptCTR(psk[:], decode.DeriveNonce(4242, 0x11223344), data)
	if err != nil {
		t.Fatalf("CryptCTR: %v", err)
	}
	mp := decode.EncodeMeshPacket(decode.MeshPacketFields{
		From: 0x11223344, To: 0xffffffff, ID: 4242,
		ChannelHash: decode.ChannelHash("pvt", psk[:]), Encrypted: ciphertext,
	})
	worker.processOne(queuedMessage{
		Topic: "msh/pvt/2/e/pvt/!11223344", Payload: decode.EncodeServiceEnvelope(mp, "pvt", "!11223344"),
		Username: "alpha", ReceivedAt: time.Now(),
	})

	if got := worker.PlaintextUplinks(); len(got) != 0 {
		t.Errorf("PlaintextUplinks() = %v, want empty for a correctly encrypted frame", got)
	}
	if len(cap.lines) != 0 {
		t.Errorf("warned about a correctly encrypted frame: %v", cap.lines)
	}
}
