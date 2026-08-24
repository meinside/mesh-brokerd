package hook

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
)

// fakeSink records what it was asked to deliver and can be made to fail.
type fakeSink struct {
	mu       sync.Mutex
	bodies   [][]byte
	failWith error
}

func (f *fakeSink) Deliver(_ context.Context, _ config.HookTarget, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return f.failWith
	}
	f.bodies = append(f.bodies, append([]byte(nil), body...))
	return nil
}

func (f *fakeSink) Describe(config.HookTarget) string { return "fake" }

func (f *fakeSink) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func testDispatcher(t *testing.T, target config.HookTarget, sink Sink, now func() time.Time) *Dispatcher {
	t.Helper()
	d := New(Options{
		Config: config.EventHooks{
			Enabled: true, DryRun: false, QueueSize: 8, MaxConcurrent: 1,
			Targets: []config.HookTarget{target},
		},
		Boards: []config.Board{{ID: "alpha", NodeID: "!11223344"}},
		Logger: quietLogger(),
		Now:    now,
		Sinks:  map[config.HookKind]Sink{target.Kind: sink},
	})
	ctx, cancel := context.WithCancel(context.Background())
	d.Run(ctx)
	t.Cleanup(func() { cancel(); d.Wait() })
	return d
}

func frameTarget() config.HookTarget {
	return config.HookTarget{
		Name: "t", Kind: config.HookKindWebhook, Enabled: true,
		Timeout: time.Second, QuietFrom: -1, QuietTo: -1,
		Match: config.HookMatch{Events: []string{config.HookEventFrame}},
	}
}

func testFrame(text string) (Event, []byte) {
	res := &decode.Result{
		Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt",
		GatewayID: "!11223344", PacketID: 0x1234, FromNode: 0x99aabbcc, ToNode: 0xffffffff,
		Status: decode.StatusDecoded, Portnum: decode.PortNumTextMessage, PacketParsed: true,
		HasRxSnr: true, RxSnr: 6.0,
		TextMessage: &decode.TextMessage{Text: text},
	}
	return FrameEvent(res, "alpha", time.Now()), []byte(text)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within 2s")
}

// TestDispatch_TextIsOmittedUnlessOptedIn is the privacy contract: the
// message body is the one field whose exposure to a third-party endpoint
// cannot be undone, so it must require an explicit opt-in.
func TestDispatch_TextIsOmittedUnlessOptedIn(t *testing.T) {
	sink := &fakeSink{}
	d := testDispatcher(t, frameTarget(), sink, time.Now)

	e, raw := testFrame("secret words")
	d.Dispatch(e, raw)
	waitFor(t, func() bool { return sink.count() == 1 })

	body := string(sink.bodies[0])
	if strings.Contains(body, "secret words") {
		t.Errorf("message text delivered without include_text: %s", body)
	}
	// The rest of the event must still be there.
	if !strings.Contains(body, "TEXT_MESSAGE_APP") {
		t.Errorf("portnum missing from payload: %s", body)
	}

	// And with the opt-in, it is included.
	target := frameTarget()
	target.Match.IncludeText = true
	sink2 := &fakeSink{}
	d2 := testDispatcher(t, target, sink2, time.Now)
	d2.Dispatch(e, raw)
	waitFor(t, func() bool { return sink2.count() == 1 })
	if !strings.Contains(string(sink2.bodies[0]), "secret words") {
		t.Errorf("include_text = true but text is missing: %s", sink2.bodies[0])
	}
}

// TestDispatch_StrippingTextDoesNotMutateTheSharedMap catches a bug this
// design invites: Event.Fields is the same map the decode result holds, so
// deleting from it would strip the text for every later target -- and for
// storage, if the order ever changed.
func TestDispatch_StrippingTextDoesNotMutateTheSharedMap(t *testing.T) {
	e, raw := testFrame("keep me")
	before, ok := e.Fields["text"]
	if !ok {
		t.Fatal("fixture has no text field")
	}
	_ = e.applyMatchOptions(config.HookMatch{IncludeText: false}, raw)
	if got := e.Fields["text"]; got != before {
		t.Errorf("original Fields mutated: text = %v, want %v", got, before)
	}
}

// TestDispatch_AbsentMeasurementsAreOmitted keeps ADR-15's rule at the
// edge of the system: a consumer must not read a missing rx_rssi as 0 dBm.
func TestDispatch_AbsentMeasurementsAreOmitted(t *testing.T) {
	sink := &fakeSink{}
	d := testDispatcher(t, frameTarget(), sink, time.Now)
	e, raw := testFrame("x")
	d.Dispatch(e, raw)
	waitFor(t, func() bool { return sink.count() == 1 })

	var decoded map[string]any
	if err := json.Unmarshal(sink.bodies[0], &decoded); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if _, present := decoded["rx_rssi"]; present {
		t.Errorf("rx_rssi present though the frame never stated it: %v", decoded)
	}
	if got, want := decoded["rx_snr"], 6.0; got != want {
		t.Errorf("rx_snr = %v, want %v", got, want)
	}
}

func TestDispatch_QuietHours(t *testing.T) {
	target := frameTarget()
	// 23:00-07:00, i.e. a window that wraps midnight.
	target.QuietFrom, target.QuietTo = 23*60, 7*60

	at := func(h, m int) func() time.Time {
		return func() time.Time { return time.Date(2026, 1, 2, h, m, 0, 0, time.Local) }
	}
	for _, tc := range []struct {
		name string
		now  func() time.Time
		want int
	}{
		{"inside, before midnight", at(23, 30), 0},
		{"inside, after midnight", at(2, 0), 0},
		{"boundary start is quiet", at(23, 0), 0},
		{"boundary end is not quiet", at(7, 0), 1},
		{"outside", at(12, 0), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &fakeSink{}
			d := testDispatcher(t, target, sink, tc.now)
			e, raw := testFrame("x")
			d.Dispatch(e, raw)
			if tc.want > 0 {
				waitFor(t, func() bool { return sink.count() == tc.want })
				return
			}
			time.Sleep(50 * time.Millisecond)
			if got := sink.count(); got != 0 {
				t.Errorf("delivered %d during quiet hours, want 0", got)
			}
			if d.Snapshot().Suppressed["t"] != 1 {
				t.Errorf("suppressed counter = %v, want 1", d.Snapshot().Suppressed)
			}
		})
	}
}

func TestDispatch_RateLimit(t *testing.T) {
	target := frameTarget()
	target.MinInterval = time.Minute

	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.Local)
	clock := func() time.Time { return now }
	sink := &fakeSink{}
	d := testDispatcher(t, target, sink, clock)

	e, raw := testFrame("first")
	d.Dispatch(e, raw)
	waitFor(t, func() bool { return sink.count() == 1 })

	e2, raw2 := testFrame("second")
	d.Dispatch(e2, raw2)
	time.Sleep(50 * time.Millisecond)
	if got := sink.count(); got != 1 {
		t.Errorf("delivered %d, want 1 (second event is inside min_interval)", got)
	}
	if d.Snapshot().RateLimited["t"] != 1 {
		t.Errorf("ratelimited counter = %v, want 1", d.Snapshot().RateLimited)
	}

	now = now.Add(2 * time.Minute)
	d.Dispatch(e2, raw2)
	waitFor(t, func() bool { return sink.count() == 2 })
}

func TestDispatch_DedupeWindowSuppressesIdenticalPayload(t *testing.T) {
	target := frameTarget()
	target.DedupeWindow = 5 * time.Minute
	target.Match.IncludeText = true

	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.Local)
	sink := &fakeSink{}
	d := testDispatcher(t, target, sink, func() time.Time { return now })

	e, raw := testFrame("same words")
	d.Dispatch(e, raw)
	waitFor(t, func() bool { return sink.count() == 1 })

	// A different packet carrying identical content: storage keeps both
	// (ADR-14), a notification does not need to.
	d.Dispatch(e, raw)
	time.Sleep(50 * time.Millisecond)
	if got := sink.count(); got != 1 {
		t.Errorf("delivered %d, want 1 for an identical payload inside the window", got)
	}

	other, otherRaw := testFrame("different words")
	d.Dispatch(other, otherRaw)
	waitFor(t, func() bool { return sink.count() == 2 })
}

func TestDispatch_ExcludeOwnBoards(t *testing.T) {
	target := frameTarget()
	target.Match.ExcludeOwnBoards = true

	sink := &fakeSink{}
	d := testDispatcher(t, target, sink, time.Now)

	// from = 0x11223344, which is the configured board's node id.
	res := &decode.Result{
		Topic: "msh/pvt/2/e/pvt/!11223344", ChannelSegment: "pvt",
		FromNode: 0x11223344, ToNode: 0xffffffff, PacketParsed: true,
		Status: decode.StatusDecoded, Portnum: decode.PortNumTextMessage,
		TextMessage: &decode.TextMessage{Text: "from my own gateway"},
	}
	d.Dispatch(FrameEvent(res, "alpha", time.Now()), nil)
	time.Sleep(50 * time.Millisecond)
	if got := sink.count(); got != 0 {
		t.Errorf("delivered %d for a frame from a configured board, want 0", got)
	}

	third, raw := testFrame("from someone else") // from = 0x99aabbcc
	d.Dispatch(third, raw)
	waitFor(t, func() bool { return sink.count() == 1 })
}

func TestDispatch_DisablesTargetAfterConsecutiveFailures(t *testing.T) {
	target := frameTarget()
	target.DisableAfterFailures = 2
	target.Retries = 0

	sink := &fakeSink{failWith: context.DeadlineExceeded}
	d := testDispatcher(t, target, sink, time.Now)

	e, raw := testFrame("x")
	d.Dispatch(e, raw)
	d.Dispatch(e, raw)
	waitFor(t, func() bool { return d.Snapshot().Failed["t"] == 2 })
	waitFor(t, func() bool { return len(d.Snapshot().Disabled) == 1 })

	// Once disabled, nothing further is even queued.
	failedBefore := d.Snapshot().Failed["t"]
	d.Dispatch(e, raw)
	time.Sleep(50 * time.Millisecond)
	if got := d.Snapshot().Failed["t"]; got != failedBefore {
		t.Errorf("failed counter moved to %d after the target was disabled, want %d", got, failedBefore)
	}
}

func TestDispatch_DryRunDeliversNothing(t *testing.T) {
	sink := &fakeSink{}
	d := New(Options{
		Config: config.EventHooks{
			Enabled: true, DryRun: true, QueueSize: 4, MaxConcurrent: 1,
			Targets: []config.HookTarget{frameTarget()},
		},
		Logger: quietLogger(),
		Sinks:  map[config.HookKind]Sink{config.HookKindWebhook: sink},
	})
	ctx, cancel := context.WithCancel(context.Background())
	d.Run(ctx)
	defer func() { cancel(); d.Wait() }()

	e, raw := testFrame("x")
	d.Dispatch(e, raw)
	waitFor(t, func() bool { return d.Snapshot().DryRun["t"] == 1 })
	if got := sink.count(); got != 0 {
		t.Errorf("dry run delivered %d payloads, want 0", got)
	}
}

func TestDispatch_DisabledConfigDeliversNothing(t *testing.T) {
	sink := &fakeSink{}
	d := New(Options{
		Config: config.EventHooks{Enabled: false, QueueSize: 4, MaxConcurrent: 1,
			Targets: []config.HookTarget{frameTarget()}},
		Logger: quietLogger(),
		Sinks:  map[config.HookKind]Sink{config.HookKindWebhook: sink},
	})
	d.Run(context.Background())
	e, raw := testFrame("x")
	d.Dispatch(e, raw)
	time.Sleep(50 * time.Millisecond)
	if got := sink.count(); got != 0 {
		t.Errorf("delivered %d with event_hooks.enabled = false, want 0", got)
	}
}

func TestDispatch_BoardEventsOnlyReachSubscribedTargets(t *testing.T) {
	frameOnly := frameTarget()
	sink := &fakeSink{}
	d := testDispatcher(t, frameOnly, sink, time.Now)

	d.Dispatch(BoardEvent(config.HookEventBoardDisconnected, "alpha", "read timeout"), nil)
	time.Sleep(50 * time.Millisecond)
	if got := sink.count(); got != 0 {
		t.Errorf("frame-only target received a connection event (%d deliveries)", got)
	}

	connTarget := frameTarget()
	connTarget.Match.Events = []string{config.HookEventBoardDisconnected}
	sink2 := &fakeSink{}
	d2 := testDispatcher(t, connTarget, sink2, time.Now)
	d2.Dispatch(BoardEvent(config.HookEventBoardDisconnected, "alpha", "read timeout"), nil)
	waitFor(t, func() bool { return sink2.count() == 1 })
	if !strings.Contains(string(sink2.bodies[0]), "read timeout") {
		t.Errorf("reason missing: %s", sink2.bodies[0])
	}
}

func TestRender_Template(t *testing.T) {
	target := frameTarget()
	target.Template = "{{.BoardID}} {{.Portnum}}: {{index .Fields \"text\"}}"
	target.Match.IncludeText = true

	sink := &fakeSink{}
	d := testDispatcher(t, target, sink, time.Now)
	e, raw := testFrame("hello mesh")
	d.Dispatch(e, raw)
	waitFor(t, func() bool { return sink.count() == 1 })

	if got, want := string(sink.bodies[0]), "alpha TEXT_MESSAGE_APP: hello mesh"; got != want {
		t.Errorf("rendered %q, want %q", got, want)
	}
}

// TestRender_TemplateCannotSeeTextWithoutOptIn closes the obvious way
// around the privacy switch.
func TestRender_TemplateCannotSeeTextWithoutOptIn(t *testing.T) {
	target := frameTarget()
	target.Template = "{{index .Fields \"text\"}}"
	target.Match.IncludeText = false

	sink := &fakeSink{}
	d := testDispatcher(t, target, sink, time.Now)
	e, raw := testFrame("must not appear")
	d.Dispatch(e, raw)
	waitFor(t, func() bool { return sink.count() == 1 })
	if strings.Contains(string(sink.bodies[0]), "must not appear") {
		t.Errorf("template reached the message body without include_text: %q", sink.bodies[0])
	}
}

func TestValidateTemplates_RejectsSyntaxErrorAtStartup(t *testing.T) {
	cfg := config.EventHooks{Targets: []config.HookTarget{{Name: "bad", Template: "{{.BoardID"}}}
	if err := ValidateTemplates(cfg); err == nil {
		t.Error("ValidateTemplates accepted an unterminated action")
	}
}

func TestDispatch_IncludeRawPayload(t *testing.T) {
	target := frameTarget()
	target.Match.IncludeRawPayload = true
	sink := &fakeSink{}
	d := testDispatcher(t, target, sink, time.Now)

	d.Dispatch(Event{Event: config.HookEventFrame, Portnum: "TEXT_MESSAGE_APP"}, []byte{0x01, 0x02, 0x03})
	waitFor(t, func() bool { return sink.count() == 1 })
	if !strings.Contains(string(sink.bodies[0]), "AQID") { // base64 of 01 02 03
		t.Errorf("raw_payload missing or not base64: %s", sink.bodies[0])
	}
}

// TestCommandSink_PayloadArrivesOnStdinAndEnvIsMinimal is the safety
// contract for local execution, checked by running a real script: brokerd's
// own environment holds channel PSKs and API tokens, and a hook script must
// not receive them.
func TestCommandSink_PayloadArrivesOnStdinAndEnvIsMinimal(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.txt")
	script := filepath.Join(dir, "hook.sh")
	body := "#!/bin/sh\n{ echo \"stdin:$(cat)\"; echo \"secret:${BROKERD_CHANNEL_TEST_PSK:-unset}\"; echo \"path:${PATH}\"; } > " + out + "\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("writing script: %v", err)
	}

	t.Setenv("BROKERD_CHANNEL_TEST_PSK", "a-secret-that-must-not-leak")

	sink := NewCommandSink()
	target := config.HookTarget{Name: "c", Kind: config.HookKindCommand, Command: script, Timeout: 5 * time.Second}
	if err := sink.Deliver(context.Background(), target, []byte(`{"event":"frame"}`)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading script output: %v", err)
	}
	text := string(got)
	if !strings.Contains(text, `stdin:{"event":"frame"}`) {
		t.Errorf("payload did not arrive on stdin: %q", text)
	}
	if !strings.Contains(text, "secret:unset") {
		t.Errorf("child inherited brokerd's environment: %q", text)
	}
	if strings.Contains(text, "a-secret-that-must-not-leak") {
		t.Errorf("secret leaked to the child: %q", text)
	}
}

// TestCommandSink_TimeoutKillsTheProcess proves a stalled script cannot
// hold a worker slot forever.
func TestCommandSink_TimeoutKillsTheProcess(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "sleep.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 30\n"), 0o700); err != nil {
		t.Fatalf("writing script: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := NewCommandSink().Deliver(ctx, config.HookTarget{
		Name: "c", Kind: config.HookKindCommand, Command: script, Timeout: 200 * time.Millisecond,
	}, []byte("{}"))
	elapsed := time.Since(start)

	if err == nil {
		t.Error("Deliver returned nil for a script killed by timeout")
	}
	if elapsed > 5*time.Second {
		t.Errorf("Deliver took %v, want the timeout to have killed it promptly", elapsed)
	}
}

// TestCommandSink_ArgsAreNotShellInterpreted records the no-shell rule: a
// value that would be command substitution in a shell must arrive at the
// program as a literal argument.
func TestCommandSink_ArgsAreNotShellInterpreted(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "arg.txt")
	script := filepath.Join(dir, "echo.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' \"$1\" > "+out+"\n"), 0o700); err != nil {
		t.Fatalf("writing script: %v", err)
	}

	payload := "$(id) `whoami` ; rm -rf /"
	err := NewCommandSink().Deliver(context.Background(), config.HookTarget{
		Name: "c", Kind: config.HookKindCommand, Command: script,
		Args: []string{payload}, Timeout: 5 * time.Second,
	}, []byte("{}"))
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if string(got) != payload {
		t.Errorf("argument was transformed: got %q, want the literal %q", got, payload)
	}
}

// TestCommandSink_ReportsChildOutput: a hook script inside the systemd
// sandbox can write only to the data directory and cannot count on reaching
// journald itself, so `echo` has to be enough. Discarding stdout left a
// script with nowhere to report to.
func TestCommandSink_ReportsChildOutput(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "say.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'hello from the hook'\n"), 0o700); err != nil {
		t.Fatalf("writing script: %v", err)
	}

	var logs strings.Builder
	sink := NewCommandSink()
	sink.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := sink.Deliver(context.Background(), config.HookTarget{
		Name: "c", Kind: config.HookKindCommand, Command: script, Timeout: 5 * time.Second,
	}, []byte("{}")); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	if !strings.Contains(logs.String(), "hello from the hook") {
		t.Errorf("child stdout not logged; got: %s", logs.String())
	}
}

// TestCommandSink_TruncatesFloodingOutput keeps one misbehaving script from
// filling the journal.
func TestCommandSink_TruncatesFloodingOutput(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "flood.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nyes x | head -c 10000\n"), 0o700); err != nil {
		t.Fatalf("writing script: %v", err)
	}

	var logs strings.Builder
	sink := NewCommandSink()
	sink.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := sink.Deliver(context.Background(), config.HookTarget{
		Name: "c", Kind: config.HookKindCommand, Command: script, Timeout: 5 * time.Second,
	}, []byte("{}")); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if n := len(logs.String()); n > 2000 {
		t.Errorf("log line is %d bytes; output should have been truncated", n)
	}
}

// TestDispatch_DrainsQueuedEventsOnShutdown covers the ordering that cost two
// real board_disconnected events: brokerd's shutdown produces them, so the
// dispatcher has to still be running when it does, and whatever is queued
// when its own context ends has to go out rather than disappear.
func TestDispatch_DrainsQueuedEventsOnShutdown(t *testing.T) {
	sink := &fakeSink{}
	target := frameTarget()
	target.Match.Events = []string{config.HookEventBoardDisconnected}

	d := New(Options{
		Config: config.EventHooks{
			Enabled: true, DryRun: false, QueueSize: 8, MaxConcurrent: 1,
			Targets: []config.HookTarget{target},
		},
		Logger: quietLogger(),
		Sinks:  map[config.HookKind]Sink{config.HookKindWebhook: sink},
	})

	ctx, cancel := context.WithCancel(context.Background())
	d.Run(ctx)

	for i := 0; i < 3; i++ {
		d.Dispatch(BoardEvent(config.HookEventBoardDisconnected, "alpha", "server shutting down"), nil)
	}
	cancel()
	d.Wait()

	if got := sink.count(); got != 3 {
		t.Errorf("delivered %d of 3 events queued before shutdown", got)
	}
}

// TestReportUndelivered_SaysSoRatherThanSwallowing: a queue with no consumer
// accepts writes silently, so the only way a lost event is visible is if
// something counts what was left.
func TestReportUndelivered_SaysSoRatherThanSwallowing(t *testing.T) {
	var logs strings.Builder
	d := New(Options{
		Config: config.EventHooks{
			Enabled: true, DryRun: false, QueueSize: 8, MaxConcurrent: 1,
			Targets: []config.HookTarget{frameTarget()},
		},
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})),
		Sinks:  map[config.HookKind]Sink{config.HookKindWebhook: &fakeSink{}},
	})

	// Never started: nothing consumes the queue.
	e, raw := testFrame("queued but never delivered")
	d.Dispatch(e, raw)
	d.ReportUndelivered()

	if !strings.Contains(logs.String(), "left undelivered at shutdown") {
		t.Errorf("undelivered events were not reported; got: %s", logs.String())
	}

	// And with nothing queued it stays quiet.
	logs.Reset()
	d.ReportUndelivered()
	if strings.Contains(logs.String(), "undelivered") {
		t.Errorf("reported undelivered events when the queue was empty: %s", logs.String())
	}
}

// TestFrameEvent_OmitsWhatThePacketDidNotState was written from a real
// payload: a MAP_REPORT_APP frame produced "packet_id":"0x00000000" and
// "hop_start":0 for fields the packet never carried. A map report states no
// packet id at all -- the fact duplicate suppression depends on (ADR-14) --
// so offering one to a consumer invents an identity.
func TestFrameEvent_OmitsWhatThePacketDidNotState(t *testing.T) {
	res := &decode.Result{
		Topic: "msh/pvt/2/map/", ChannelSegment: "LongFast",
		GatewayID: "!11223344", PacketID: 0, FromNode: 0x11223344, ToNode: 0xffffffff,
		Status: decode.StatusDecoded, Portnum: decode.PortNumMapReport, PacketParsed: true,
	}
	body, err := FrameEvent(res, "alpha", time.Now()).JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}

	for _, absent := range []string{"packet_id", "hop_start", "rx_snr", "rx_rssi", "bitfield"} {
		if _, present := decoded[absent]; present {
			t.Errorf("%s present though the packet did not state it: %s", absent, body)
		}
	}
	// hop_limit and via_mqtt stay: protobuf's default is the meaningful value.
	for _, kept := range []string{"hop_limit", "via_mqtt", "from", "to", "portnum"} {
		if _, present := decoded[kept]; !present {
			t.Errorf("%s missing from the payload: %s", kept, body)
		}
	}

	// A packet that does state an id still carries it.
	res.PacketID = 0x4dc1083a
	res.HopStart = 3
	body, _ = FrameEvent(res, "alpha", time.Now()).JSON()
	if !strings.Contains(string(body), `"packet_id":"0x4dc1083a"`) {
		t.Errorf("a stated packet id was dropped: %s", body)
	}
	if !strings.Contains(string(body), `"hop_start":3`) {
		t.Errorf("a stated hop_start was dropped: %s", body)
	}
}

// TestDispatch_DeliveredAtIsFilledIn: the field existed in every payload and
// was always empty until a real one was read.
func TestDispatch_DeliveredAtIsFilledIn(t *testing.T) {
	sink := &fakeSink{}
	fixed := time.Date(2026, 8, 21, 6, 59, 36, 0, time.UTC)
	d := testDispatcher(t, frameTarget(), sink, func() time.Time { return fixed })

	e, raw := testFrame("x")
	d.Dispatch(e, raw)
	waitFor(t, func() bool { return sink.count() == 1 })

	if !strings.Contains(string(sink.bodies[0]), `"delivered_at":"2026-08-21T06:59:36Z"`) {
		t.Errorf("delivered_at not filled in: %s", sink.bodies[0])
	}
}

// TestValidateTemplates_AcceptsWhatTheRendererAccepts pins the two paths
// together. They were built separately, and only the renderer registered the
// function map, so a template using `json` failed startup validation while
// being perfectly renderable -- caught by validation, but a drift that would
// have hit any future function the same way.
func TestValidateTemplates_AcceptsWhatTheRendererAccepts(t *testing.T) {
	target := frameTarget()
	target.Match.IncludeText = true
	target.Template = `{"body": {{json (trunc 20 (index .Fields "text"))}}}`

	cfg := config.EventHooks{Targets: []config.HookTarget{target}}
	if err := ValidateTemplates(cfg); err != nil {
		t.Fatalf("ValidateTemplates rejected a template the renderer supports: %v", err)
	}

	sink := &fakeSink{}
	d := testDispatcher(t, target, sink, time.Now)
	e, raw := testFrame("rendered fine")
	d.Dispatch(e, raw)
	waitFor(t, func() bool { return sink.count() == 1 })
}

// TestShutdown_WaitsForRunningDeliveries reproduces the first real shutdown
// with hooks armed: both board_disconnected events were queued, picked up, and
// then their command was killed mid-run ("context canceled", "signal: killed")
// because the workers' context was cancelled without waiting.
func TestShutdown_WaitsForRunningDeliveries(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	slow := &blockingSink{started: started, release: release}

	target := frameTarget()
	target.Match.Events = []string{config.HookEventBoardDisconnected}
	target.Timeout = 5 * time.Second

	d := New(Options{
		Config: config.EventHooks{
			Enabled: true, DryRun: false, QueueSize: 8, MaxConcurrent: 1,
			Targets: []config.HookTarget{target},
		},
		Logger: quietLogger(),
		Sinks:  map[config.HookKind]Sink{config.HookKindWebhook: slow},
	})
	ctx, cancel := context.WithCancel(context.Background())
	d.Run(ctx)

	d.Dispatch(BoardEvent(config.HookEventBoardDisconnected, "alpha", "server shutting down"), nil)
	<-started // delivery is in the sink now

	shutdownDone := make(chan struct{})
	go func() {
		d.Shutdown(3 * time.Second)
		close(shutdownDone)
	}()

	// Shutdown must not return while a delivery is running.
	select {
	case <-shutdownDone:
		t.Fatal("Shutdown returned while a delivery was still in flight")
	case <-time.After(150 * time.Millisecond):
	}

	close(release)
	select {
	case <-shutdownDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown did not return after the delivery finished")
	}

	cancel()
	d.Wait()

	if got := d.Snapshot().Failed["t"]; got != 0 {
		t.Errorf("failed_total = %d, want 0: the delivery completed before shutdown cancelled anything", got)
	}
	if got := d.Snapshot().Fired["t"]; got != 1 {
		t.Errorf("fired_total = %d, want 1", got)
	}
}

// TestShutdown_GivesUpAfterTimeout keeps a stuck sink from blocking shutdown
// forever, and says so rather than hanging quietly.
func TestShutdown_GivesUpAfterTimeout(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{}) // never closed
	stuck := &blockingSink{started: started, release: release}

	var logs strings.Builder
	target := frameTarget()
	// Long enough that the delivery is still running when Shutdown gives up,
	// short enough that the test does not wait for it.
	target.Timeout = 2 * time.Second

	d := New(Options{
		Config: config.EventHooks{
			Enabled: true, DryRun: false, QueueSize: 4, MaxConcurrent: 1,
			Targets: []config.HookTarget{target},
		},
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})),
		Sinks:  map[config.HookKind]Sink{config.HookKindWebhook: stuck},
	})
	ctx, cancel := context.WithCancel(context.Background())
	d.Run(ctx)
	defer func() { cancel(); d.Wait() }()

	e, raw := testFrame("stuck")
	d.Dispatch(e, raw)
	<-started

	start := time.Now()
	d.Shutdown(200 * time.Millisecond)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Shutdown took %v, want it to give up at the timeout", elapsed)
	}
	if !strings.Contains(logs.String(), "still delivering at shutdown deadline") {
		t.Errorf("no warning that deliveries were abandoned; got: %s", logs.String())
	}
}

// blockingSink signals when a delivery starts and blocks until released.
type blockingSink struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingSink) Deliver(ctx context.Context, _ config.HookTarget, _ []byte) error {
	select {
	case b.started <- struct{}{}:
	default:
	}
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *blockingSink) Describe(config.HookTarget) string { return "blocking" }

// TestInQuietHours_ZeroValueIsNotAllDay: unset quiet hours are spelled -1 by
// the config loader, but a HookTarget built in code has 0, and (0, 0) read as a
// wrapping window covers every minute of every day. A target that never
// configured quiet hours silently delivered nothing -- found when the hook self
// test stopped delivering, reporting suppressed_total against a target with no
// quiet hours configured at all.
func TestInQuietHours_ZeroValueIsNotAllDay(t *testing.T) {
	cases := []struct {
		name     string
		from, to int
		want     bool
	}{
		{"zero value", 0, 0, false},
		{"explicitly unset", -1, -1, false},
		{"equal bounds", 9 * 60, 9 * 60, false},
		{"inside a daytime window", 8 * 60, 10 * 60, true},
		{"outside a daytime window", 20 * 60, 22 * 60, false},
		{"inside a window that wraps midnight", 22 * 60, 10 * 60, true},
	}
	// 09:00 local, inside 08:00-10:00 and inside 22:00-10:00.
	now := time.Date(2026, 1, 1, 9, 0, 0, 0, time.Local)
	for _, c := range cases {
		if got := inQuietHours(now, c.from, c.to); got != c.want {
			t.Errorf("%s: inQuietHours(09:00, %d, %d) = %v, want %v", c.name, c.from, c.to, got, c.want)
		}
	}
}
