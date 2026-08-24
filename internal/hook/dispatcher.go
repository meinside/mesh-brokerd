package hook

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/meinside/mesh-brokerd/internal/config"
)

// Sink delivers one rendered payload to one target.
type Sink interface {
	Deliver(ctx context.Context, t config.HookTarget, body []byte) error
	// Describe is what dry_run logs instead of delivering: for a command,
	// the argv that would run; for a webhook, the method and URL.
	Describe(t config.HookTarget) string
}

type queued struct {
	target config.HookTarget
	body   []byte
	event  string
}

// targetState is the per-target mutable state: rate limiting, dedup and
// the consecutive-failure counter that can disable a target. It is
// deliberately in memory only -- a restart re-enables everything, which is
// the behaviour an operator expects after fixing an endpoint.
type targetState struct {
	lastDelivery time.Time
	lastHash     [sha256.Size]byte
	lastHashAt   time.Time
	failures     int
	disabled     bool
}

// Dispatcher fans events out to the configured targets.
type Dispatcher struct {
	cfg   config.EventHooks
	log   *slog.Logger
	now   func() time.Time
	sinks map[config.HookKind]Sink

	// boardNodes maps a board's node id (as the "0x…" string an event
	// carries) to its board id, for match.exclude_own_boards.
	boardNodes map[string]string

	queue chan queued
	wg    sync.WaitGroup

	// inFlight counts deliveries currently in a sink, so Shutdown can tell
	// "queue empty" from "queue empty and nothing still running". A child
	// process killed halfway is a hook that did not run.
	inFlight atomic.Int64

	mu       sync.Mutex
	state    map[string]*targetState
	counters Counters
}

// Counters are the report-only totals surfaced by the monitoring API.
type Counters struct {
	Fired       map[string]int64 `json:"fired_total"`
	Failed      map[string]int64 `json:"failed_total"`
	Dropped     map[string]int64 `json:"dropped_total"`
	RateLimited map[string]int64 `json:"ratelimited_total"`
	Suppressed  map[string]int64 `json:"suppressed_total"`
	DryRun      map[string]int64 `json:"dry_run_total"`
	Disabled    []string         `json:"disabled_targets"`
}

// Options configures a Dispatcher.
type Options struct {
	Config config.EventHooks
	Boards []config.Board
	Logger *slog.Logger
	// Now is injectable so quiet hours, rate limiting and dedup windows
	// are testable without sleeping.
	Now func() time.Time
	// Sinks overrides the real sinks; nil uses webhook + command.
	Sinks map[config.HookKind]Sink
}

// New builds a Dispatcher. Call Run to start its workers.
func New(opts Options) *Dispatcher {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	sinks := opts.Sinks
	if sinks == nil {
		commandSink := NewCommandSink()
		commandSink.Log = log
		sinks = map[config.HookKind]Sink{
			config.HookKindWebhook: NewWebhookSink(),
			config.HookKindCommand: commandSink,
		}
	}

	boardNodes := make(map[string]string, len(opts.Boards))
	for _, b := range opts.Boards {
		if b.NodeID != "" {
			boardNodes[normalizeNodeID(b.NodeID)] = b.ID
		}
	}

	d := &Dispatcher{
		cfg:        opts.Config,
		log:        log,
		now:        now,
		sinks:      sinks,
		boardNodes: boardNodes,
		queue:      make(chan queued, opts.Config.QueueSize),
		state:      make(map[string]*targetState),
		counters: Counters{
			Fired:       map[string]int64{},
			Failed:      map[string]int64{},
			Dropped:     map[string]int64{},
			RateLimited: map[string]int64{},
			Suppressed:  map[string]int64{},
			DryRun:      map[string]int64{},
		},
	}
	for _, t := range opts.Config.Targets {
		d.state[t.Name] = &targetState{}
	}
	return d
}

// Run starts MaxConcurrent workers and returns. They stop when ctx is
// cancelled and the queue is drained.
func (d *Dispatcher) Run(ctx context.Context) {
	if !d.cfg.Enabled {
		return
	}
	for i := 0; i < d.cfg.MaxConcurrent; i++ {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			for {
				select {
				case q := <-d.queue:
					d.deliver(ctx, q)
				case <-ctx.Done():
					// Drain what is already queued, then stop: the events
					// are cheap and the alternative is losing the one
					// notification that explains a shutdown.
					for {
						select {
						case q := <-d.queue:
							d.deliver(context.WithoutCancel(ctx), q)
						default:
							return
						}
					}
				}
			}
		}()
	}
}

// Wait blocks until the workers have stopped.
func (d *Dispatcher) Wait() { d.wg.Wait() }

// Shutdown waits, up to timeout, for the queue to empty and for every
// in-flight delivery to finish. Call it *before* cancelling the context given
// to Run.
//
// Without it, cancelling that context kills a running child process
// mid-delivery: brokerd's own shutdown produces a board_disconnected event per
// board, and the first real run of this ended with two "context canceled" and
// "signal: killed" failures -- the events were queued and picked up, then the
// program running them was killed. Queuing an event and then killing its
// delivery is a more confusing failure than never queuing it.
func (d *Dispatcher) Shutdown(timeout time.Duration) {
	if !d.cfg.Enabled {
		return
	}
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		if len(d.queue) == 0 && d.inFlight.Load() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	d.log.Warn("hook: still delivering at shutdown deadline",
		"queued", len(d.queue), "in_flight", d.inFlight.Load(), "timeout", timeout)
}

// Dispatch evaluates every target against the event and enqueues the ones
// that match. It never blocks: a full queue drops its oldest entry.
// rawPayload is the decrypted Data.payload, used only by targets that
// opted into include_raw_payload.
func (d *Dispatcher) Dispatch(e Event, rawPayload []byte) {
	if !d.cfg.Enabled {
		return
	}
	for _, t := range d.cfg.Targets {
		if !t.Enabled || d.isDisabled(t.Name) {
			continue
		}
		if !d.matches(t, e) {
			continue
		}

		body, err := d.render(t, e, rawPayload)
		if err != nil {
			d.log.Error("hook: rendering payload failed", "target", t.Name, "event", e.Event, "error", err)
			d.bump(d.counters.Failed, t.Name)
			continue
		}

		if reason, skip := d.shouldSkip(t, body); skip {
			d.log.Debug("hook: skipped", "target", t.Name, "event", e.Event, "reason", reason)
			continue
		}

		select {
		case d.queue <- queued{target: t, body: body, event: e.Event}:
		default:
			// Oldest first: the newest event is the one most likely still
			// worth acting on.
			select {
			case <-d.queue:
				d.bump(d.counters.Dropped, t.Name)
			default:
			}
			select {
			case d.queue <- queued{target: t, body: body, event: e.Event}:
			default:
				d.bump(d.counters.Dropped, t.Name)
			}
		}
	}
}

// matches applies the target's filters. An empty list means "no filter",
// except events, which the loader defaults to frame-only.
func (d *Dispatcher) matches(t config.HookTarget, e Event) bool {
	if !contains(t.Match.Events, e.Event) {
		return false
	}
	if e.Event == config.HookEventFrame {
		if len(t.Match.Portnums) > 0 && !contains(t.Match.Portnums, e.Portnum) {
			return false
		}
		if len(t.Match.Channels) > 0 && !contains(t.Match.Channels, e.Channel) {
			return false
		}
		if t.Match.ExcludeOwnBoards && e.FromNode != "" {
			if _, own := d.boardNodes[normalizeNodeID(e.FromNode)]; own {
				return false
			}
		}
	}
	if len(t.Match.Boards) > 0 && !contains(t.Match.Boards, e.BoardID) {
		return false
	}
	return true
}

// shouldSkip applies quiet hours, the rate limit and the dedup window,
// counting each so a missing notification is explainable afterwards.
func (d *Dispatcher) shouldSkip(t config.HookTarget, body []byte) (string, bool) {
	now := d.now()

	if inQuietHours(now, t.QuietFrom, t.QuietTo) {
		d.bump(d.counters.Suppressed, t.Name)
		return "quiet_hours", true
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.state[t.Name]
	if st == nil {
		st = &targetState{}
		d.state[t.Name] = st
	}

	if t.MinInterval > 0 && !st.lastDelivery.IsZero() && now.Sub(st.lastDelivery) < t.MinInterval {
		d.counters.RateLimited[t.Name]++
		return "rate_limited", true
	}
	if t.DedupeWindow > 0 {
		sum := sha256.Sum256(body)
		if sum == st.lastHash && now.Sub(st.lastHashAt) < t.DedupeWindow {
			d.counters.Suppressed[t.Name]++
			return "duplicate_payload", true
		}
		st.lastHash, st.lastHashAt = sum, now
	}
	st.lastDelivery = now
	return "", false
}

func (d *Dispatcher) deliver(ctx context.Context, q queued) {
	d.inFlight.Add(1)
	defer d.inFlight.Add(-1)

	t := q.target

	if d.cfg.DryRun {
		d.log.Info("hook: dry run", "target", t.Name, "event", q.event,
			"would", d.describe(t), "bytes", len(q.body))
		d.bump(d.counters.DryRun, t.Name)
		return
	}

	sink, ok := d.sinks[t.Kind]
	if !ok {
		d.log.Error("hook: no sink for kind", "target", t.Name, "kind", t.Kind)
		d.bump(d.counters.Failed, t.Name)
		return
	}

	var err error
	attempts := t.Retries + 1
	for attempt := 1; attempt <= attempts; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, t.Timeout)
		err = sink.Deliver(callCtx, t, q.body)
		cancel()
		if err == nil {
			break
		}
		if attempt < attempts {
			// Linear backoff on the target's own timeout scale; the event
			// rate here is a few per hour, so nothing needs jitter.
			select {
			case <-time.After(time.Duration(attempt) * time.Second):
			case <-ctx.Done():
			}
		}
	}

	if err != nil {
		d.log.Warn("hook: delivery failed", "target", t.Name, "event", q.event,
			"attempts", attempts, "error", err)
		d.recordFailure(t)
		return
	}

	d.log.Info("hook: delivered", "target", t.Name, "event", q.event, "kind", t.Kind)
	d.mu.Lock()
	d.counters.Fired[t.Name]++
	if st := d.state[t.Name]; st != nil {
		st.failures = 0
	}
	d.mu.Unlock()
}

// recordFailure counts the failure and disables the target once it has
// failed DisableAfterFailures times in a row, so a dead endpoint is not
// retried forever. The one log line at that moment is the only notice.
func (d *Dispatcher) recordFailure(t config.HookTarget) {
	d.mu.Lock()
	d.counters.Failed[t.Name]++
	st := d.state[t.Name]
	if st == nil {
		st = &targetState{}
		d.state[t.Name] = st
	}
	st.failures++
	shouldDisable := t.DisableAfterFailures > 0 && st.failures >= t.DisableAfterFailures && !st.disabled
	if shouldDisable {
		st.disabled = true
		d.counters.Disabled = append(d.counters.Disabled, t.Name)
	}
	failures := st.failures
	d.mu.Unlock()

	if shouldDisable {
		d.log.Warn("hook: target disabled after consecutive failures",
			"target", t.Name, "failures", failures,
			"note", "re-enabled on restart; nothing is retried until then")
	}
}

func (d *Dispatcher) isDisabled(name string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.state[name]
	return st != nil && st.disabled
}

func (d *Dispatcher) describe(t config.HookTarget) string {
	if sink, ok := d.sinks[t.Kind]; ok {
		return sink.Describe(t)
	}
	return string(t.Kind)
}

func (d *Dispatcher) bump(m map[string]int64, name string) {
	d.mu.Lock()
	m[name]++
	d.mu.Unlock()
}

// Snapshot returns a copy of the counters for the monitoring API.
func (d *Dispatcher) Snapshot() Counters {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := Counters{
		Fired:       copyCounts(d.counters.Fired),
		Failed:      copyCounts(d.counters.Failed),
		Dropped:     copyCounts(d.counters.Dropped),
		RateLimited: copyCounts(d.counters.RateLimited),
		Suppressed:  copyCounts(d.counters.Suppressed),
		DryRun:      copyCounts(d.counters.DryRun),
	}
	out.Disabled = append([]string{}, d.counters.Disabled...)
	return out
}

func copyCounts(in map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// inQuietHours reports whether now (in local time, deliberately: the
// operator configures the hours they sleep) falls inside the window. A
// window whose start is after its end wraps midnight.
func inQuietHours(now time.Time, from, to int) bool {
	if from < 0 || to < 0 {
		return false
	}
	// Equal bounds are a window of zero length, so nothing is quiet. That
	// reading matters because it makes the struct's zero value harmless:
	// (0, 0) used to mean "minutes >= 0 or minutes < 0", which is every
	// minute of every day, so a HookTarget built in code rather than loaded
	// from config silently discarded everything. A target's most dangerous
	// setting must not be the one you get by not choosing.
	//
	// A target meant to deliver nothing is spelled `enabled: false`.
	if from == to {
		return false
	}
	minutes := now.Hour()*60 + now.Minute()
	if from < to {
		return minutes >= from && minutes < to
	}
	return minutes >= from || minutes < to
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// normalizeNodeID makes "!a1b2c3d4", "0xa1b2c3d4" and "A1B2C3D4"
// comparable: config states a board's node id in the "!hex" form the
// firmware uses, while an event carries the "0x" form.
func normalizeNodeID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "!")
	s = strings.TrimPrefix(s, "0x")
	return strings.TrimLeft(s, "0")
}

// ReportUndelivered logs anything still queued once the workers have
// stopped. Called after Wait(), it is the last chance to say that an event
// was produced and never delivered -- otherwise a shutdown race is invisible
// by construction, since a queue with no consumer accepts writes silently.
func (d *Dispatcher) ReportUndelivered() {
	remaining := len(d.queue)
	if remaining == 0 {
		return
	}
	byTarget := map[string]int{}
	for {
		select {
		case q := <-d.queue:
			byTarget[q.target.Name]++
		default:
			d.log.Warn("hook: events left undelivered at shutdown",
				"count", remaining, "by_target", byTarget)
			return
		}
	}
}

// TargetInfo is what is configured, as opposed to what has happened. The
// monitoring page needs both: a target that has fired nothing has to be
// distinguishable from a target that does not exist, and counters alone cannot
// tell the two apart.
type TargetInfo struct {
	Name    string
	Kind    string
	Enabled bool
}

// ConfiguredTargets lists every target in the configuration, enabled or not.
func (d *Dispatcher) ConfiguredTargets() []TargetInfo {
	out := make([]TargetInfo, 0, len(d.cfg.Targets))
	for _, t := range d.cfg.Targets {
		out = append(out, TargetInfo{Name: t.Name, Kind: string(t.Kind), Enabled: t.Enabled})
	}
	return out
}
