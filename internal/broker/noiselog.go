package broker

import (
	"context"
	"log/slog"
	"strings"
	"sync"
)

// NoiseFilter wraps the slog.Handler that mochi-mqtt's own logger writes
// through, demoting the classes of listener error that internet
// background noise produces -- TLS handshakes from port scanners, and
// non-MQTT bytes -- from WARN to DEBUG, and counting them instead.
//
// Why this exists: those lines are emitted before a client ever sends
// CONNECT, so the auth hook's per-IP ban (ADR-5) never sees them and can
// never stop them. Left at WARN they bury the diagnostics an operator
// actually needs; this project already lost three hours to an ERROR line
// nobody read: no signal is a claim that needs its own evidence.
//
// What it deliberately does NOT touch: transport errors on an
// established connection ("i/o timeout", "connection reset by peer",
// "use of closed network connection") and authentication failures. Those
// come from our own boards, and counting them is exactly how a flaky
// uplink at one site is measured. Guarded by
// TestNoiseFilter_KeepsTransportErrors.
//
// Suppressed lines stay reachable: they are demoted, not dropped, so
// running brokerd with -log-level debug shows every one of them again.
//
// Note on granularity: mochi-mqtt's listener errors carry no remote
// address for the pre-CONNECT cases (verified against journald: the line
// is `listener=mqtt-tls error="read connection: tls: ..."` with no
// remote attribute), so counts are per category, not per IP. A per-IP
// breakdown would need mochi-mqtt to log the address it never logs.
type NoiseFilter struct {
	inner slog.Handler

	mu     sync.Mutex
	counts map[string]int64
}

// noiseCategories maps a substring of the logged error to the counter
// name it is recorded under. Matching is on the error text because
// mochi-mqtt logs these with an empty message and the detail in an
// `error` attribute.
var noiseCategories = []struct {
	substr   string
	category string
}{
	// Every crypto/tls handshake rejection: unsupported cipher suites or
	// versions, "first record does not look like a TLS handshake",
	// certificate complaints, bad record MAC.
	{"tls: ", "tls_handshake"},
	// Bytes that reached the MQTT codec but are not a valid packet.
	{"malformed packet", "malformed_packet"},
}

// NewNoiseFilter wraps inner. A nil inner is replaced by the default
// handler so a caller cannot accidentally silence everything.
func NewNoiseFilter(inner slog.Handler) *NoiseFilter {
	if inner == nil {
		inner = slog.Default().Handler()
	}
	return &NoiseFilter{inner: inner, counts: make(map[string]int64)}
}

// Enabled delegates to the wrapped handler. It must not refuse WARN:
// records have to reach Handle for classification to happen at all
// (TestNoiseFilter_EnabledFollowsInnerForWarn).
func (f *NoiseFilter) Enabled(ctx context.Context, l slog.Level) bool {
	return f.inner.Enabled(ctx, l)
}

// Handle classifies the record. Known background noise is counted and
// re-emitted at DEBUG (which normally means "not emitted at all", since
// the default level is INFO); everything else passes through untouched.
func (f *NoiseFilter) Handle(ctx context.Context, rec slog.Record) error {
	category, isNoise := classifyNoise(rec)
	if !isNoise {
		return f.inner.Handle(ctx, rec)
	}

	f.mu.Lock()
	f.counts[category]++
	f.mu.Unlock()

	if !f.inner.Enabled(ctx, slog.LevelDebug) {
		return nil
	}
	demoted := rec.Clone()
	demoted.Level = slog.LevelDebug
	return f.inner.Handle(ctx, demoted)
}

func (f *NoiseFilter) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &NoiseFilter{inner: f.inner.WithAttrs(attrs), counts: f.counts, mu: sync.Mutex{}}
}

func (f *NoiseFilter) WithGroup(name string) slog.Handler {
	return &NoiseFilter{inner: f.inner.WithGroup(name), counts: f.counts, mu: sync.Mutex{}}
}

// Counts returns a copy of the per-category suppression counters
// (docs/monitoring-api.md's listener_noise_suppressed_total).
func (f *NoiseFilter) Counts() map[string]int64 {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make(map[string]int64, len(f.counts))
	for k, v := range f.counts {
		out[k] = v
	}
	return out
}

// classifyNoise reports which noise category a record belongs to, if
// any. Only WARN-and-below records are considered: an ERROR is never
// suppressed regardless of its text.
func classifyNoise(rec slog.Record) (string, bool) {
	if rec.Level > slog.LevelWarn {
		return "", false
	}

	var category string
	var found bool
	rec.Attrs(func(a slog.Attr) bool {
		if a.Key != "error" {
			return true
		}
		text := a.Value.String()
		for _, c := range noiseCategories {
			if strings.Contains(text, c.substr) {
				category, found = c.category, true
				return false
			}
		}
		return false
	})
	return category, found
}
