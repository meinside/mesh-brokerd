package broker

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

// captureHandler records everything it is handed, at a fixed level, so a
// test can assert both "did this reach the real log" and "at what level".
type captureHandler struct {
	level   slog.Level
	records []slog.Record
}

func (h *captureHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}

func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler      { return h }

// warnWithError builds the shape mochi-mqtt actually logs: an empty
// message plus listener/error attributes (verified against journald
// output from the live deployment, docs/runbook.md section 8).
func warnWithError(errText string) slog.Record {
	r := slog.NewRecord(time.Now(), slog.LevelWarn, "", 0)
	r.AddAttrs(slog.String("listener", "mqtt-tls"), slog.String("error", errText))
	return r
}

func TestNoiseFilter_DemotesTLSHandshakeNoise(t *testing.T) {
	inner := &captureHandler{level: slog.LevelInfo}
	f := NewNoiseFilter(inner)

	err := f.Handle(context.Background(), warnWithError(
		"read connection: tls: no cipher suite supported by both client and server; client offered: [16 33 67]"))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if len(inner.records) != 0 {
		t.Errorf("scanner TLS noise reached an Info-level log: %+v", inner.records)
	}
	if got := f.Counts()["tls_handshake"]; got != 1 {
		t.Errorf("Counts()[tls_handshake] = %d, want 1", got)
	}
}

func TestNoiseFilter_DemotesMalformedPacket(t *testing.T) {
	inner := &captureHandler{level: slog.LevelInfo}
	f := NewNoiseFilter(inner)

	if err := f.Handle(context.Background(), warnWithError("malformed packet: flags")); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if len(inner.records) != 0 {
		t.Errorf("malformed-packet noise reached an Info-level log: %+v", inner.records)
	}
	if got := f.Counts()["malformed_packet"]; got != 1 {
		t.Errorf("Counts()[malformed_packet] = %d, want 1", got)
	}
}

// TestNoiseFilter_KeepsTransportErrors is the guard that matters most.
// A flaky uplink is diagnosed purely by counting
// "i/o timeout" and reset/closed-connection lines for a real board, so
// demoting those would destroy the only evidence there is --
// and unlike the TLS garbage above, these come from *our* boards.
func TestNoiseFilter_KeepsTransportErrors(t *testing.T) {
	for _, errText := range []string{
		"read tcp 10.0.0.1:8883->198.51.100.7:53405: i/o timeout",
		"read tcp 10.0.0.1:8883->198.51.100.7:61566: read: connection reset by peer",
		"read tcp 10.0.0.1:8883->198.51.100.7:64660: use of closed network connection",
		"bad username or password",
	} {
		inner := &captureHandler{level: slog.LevelInfo}
		f := NewNoiseFilter(inner)

		if err := f.Handle(context.Background(), warnWithError(errText)); err != nil {
			t.Fatalf("Handle(%q): %v", errText, err)
		}

		if len(inner.records) != 1 {
			t.Fatalf("%q: reached inner handler %d times, want 1", errText, len(inner.records))
		}
		if lvl := inner.records[0].Level; lvl != slog.LevelWarn {
			t.Errorf("%q: level = %v, want Warn (unchanged)", errText, lvl)
		}
		if len(f.Counts()) != 0 {
			t.Errorf("%q: counted as noise: %v", errText, f.Counts())
		}
	}
}

func TestNoiseFilter_PassesUnrelatedMessagesThrough(t *testing.T) {
	inner := &captureHandler{level: slog.LevelInfo}
	f := NewNoiseFilter(inner)

	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "auth: accepted", 0)
	rec.AddAttrs(slog.String("username", "alpha"))
	if err := f.Handle(context.Background(), rec); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if len(inner.records) != 1 || inner.records[0].Message != "auth: accepted" {
		t.Errorf("unrelated record did not pass through unchanged: %+v", inner.records)
	}
}

// TestNoiseFilter_StillVisibleAtDebug proves the noise is suppressed,
// not deleted: an operator who needs it can raise -log-level to debug
// (docs/runbook.md section 8) and see every line again.
func TestNoiseFilter_StillVisibleAtDebug(t *testing.T) {
	inner := &captureHandler{level: slog.LevelDebug}
	f := NewNoiseFilter(inner)

	if err := f.Handle(context.Background(), warnWithError("read connection: tls: unknown certificate")); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if len(inner.records) != 1 {
		t.Fatalf("reached inner handler %d times at debug level, want 1", len(inner.records))
	}
	if lvl := inner.records[0].Level; lvl != slog.LevelDebug {
		t.Errorf("level = %v, want Debug (demoted, not dropped)", lvl)
	}
}

// TestNoiseFilter_EnabledFollowsInnerForWarn makes sure suppression
// happens in Handle and not by refusing Warn outright -- if Enabled said
// no, records would never arrive and nothing could be counted.
func TestNoiseFilter_EnabledFollowsInnerForWarn(t *testing.T) {
	f := NewNoiseFilter(&captureHandler{level: slog.LevelInfo})
	if !f.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("Enabled(Warn) = false; noise records would never reach Handle to be counted")
	}
}

func TestNoiseFilter_CountsAreCumulativeAndCopied(t *testing.T) {
	inner := &captureHandler{level: slog.LevelInfo}
	f := NewNoiseFilter(inner)

	for range 3 {
		if err := f.Handle(context.Background(), warnWithError("read connection: tls: bad record MAC")); err != nil {
			t.Fatalf("Handle: %v", err)
		}
	}

	counts := f.Counts()
	if counts["tls_handshake"] != 3 {
		t.Errorf("Counts()[tls_handshake] = %d, want 3", counts["tls_handshake"])
	}

	counts["tls_handshake"] = 99 // mutating the returned map must not affect the filter
	if again := f.Counts()["tls_handshake"]; again != 3 {
		t.Errorf("Counts() returned an aliased map: got %d after caller mutation, want 3", again)
	}
}
