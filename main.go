// Command mesh-brokerd is this module's primary binary: the
// unified MQTT broker + storage + monitoring process referred to
// throughout the documentation as `brokerd` (docs/architecture.md §3).
//
// It lives in the module root rather than under cmd/ because it is the
// project's main artifact, following the "command with supporting
// packages" layout in https://go.dev/doc/modules/layout (root declares
// package main, everything else lives in internal/). Consequently
// `go install github.com/meinside/mesh-brokerd@latest` installs it
// directly, as `mesh-brokerd`.
//
// Secondary tools get their own directory under cmd/. The first planned
// one is cmd/mshserial-mqtt-proxy (not yet built), which shares no
// internal/* package with this command (docs/architecture.md §5).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/meinside/mesh-brokerd/internal/auth"
	"github.com/meinside/mesh-brokerd/internal/broker"
	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
	"github.com/meinside/mesh-brokerd/internal/hook"
	"github.com/meinside/mesh-brokerd/internal/monitor"
	"github.com/meinside/mesh-brokerd/internal/relay"
	"github.com/meinside/mesh-brokerd/internal/storage"
	"github.com/meinside/mesh-brokerd/internal/tlscert"
)

// retentionInterval is how often the retention deletion job runs
// (ADR-7: "run on a periodic schedule, e.g. daily").
const retentionInterval = 24 * time.Hour

func main() {
	configPath := flag.String("config", "config.json", "path to brokerd's config.json (docs/brokerd-config.md)")
	logLevel := flag.String("log-level", "info",
		"log verbosity: debug, info, warn, error. Use debug to surface mochi-mqtt's ACL denials, which are logged at debug level and are otherwise invisible \u2014 a board publishing outside its acl_filters (e.g. a wrong mqtt.root) fails silently at info")
	reprocess := flag.String("reprocess", "",
		"re-decode every stored frame from raw_frames.payload and fill in the columns a later decoder added (docs/storage-schema.md section 7). \"dry-run\" reports what would change and writes nothing; \"apply\" writes, after copying the database first. Any other value is an error")
	checkConfig := flag.Bool("check-config", false,
		"load and validate the config, report what it would do, and exit without touching the network or the database")
	testHooks := flag.Bool("test-hooks", false,
		"deliver one synthetic event to every configured event hook and exit, so the plumbing can be checked without waiting for real traffic (docs/event-hooks.md)")
	flag.Parse()

	level, err := parseLogLevel(*logLevel)
	if err != nil {
		// No logger yet, and this must not be survivable: silently
		// continuing at some other level is how an operator ends up
		// debugging with the diagnostics they asked for switched off.
		fmt.Fprintf(os.Stderr, "brokerd: %v\n", err)
		os.Exit(2)
	}
	// Set the level on the default handler rather than installing a new
	// one, so raising verbosity never also changes the log format that
	// existing log consumers see.
	slog.SetLogLoggerLevel(level)

	log := slog.Default()

	if err := run(*configPath, *reprocess, *testHooks, *checkConfig, log); err != nil {
		log.Error("brokerd exited with error", "error", err)
		os.Exit(1)
	}
}

// validateSubstituted rejects config values that still contain an
// unsubstituted <placeholder>.
//
// config.json.sample uses bracketed placeholders for paths and hostnames so
// they cannot be mistaken for working defaults, which means a copied-but-
// unedited file has to fail clearly. Left alone it otherwise surfaces as
// "unable to open database file: no such file or directory" -- a message that
// sends the reader looking for a missing directory. internal/config applies
// the same rule to outbound_relay's root_topic, where publishing to a
// literal "msh/<REGION>/..." would put nonsense on shared infrastructure.
func validateSubstituted(cfg *config.Config) error {
	unsubstituted := func(v string) bool { return strings.ContainsAny(v, "<>") }

	if unsubstituted(cfg.Storage.Path) {
		return fmt.Errorf("config: storage.path %q still contains a placeholder -- substitute a real path (docs/brokerd-config.md)", cfg.Storage.Path)
	}
	if unsubstituted(cfg.Listener.TLSCacheDir) {
		return fmt.Errorf("config: listener.tls_cache_dir %q still contains a placeholder -- substitute a real directory (docs/brokerd-config.md)", cfg.Listener.TLSCacheDir)
	}
	for _, d := range cfg.Listener.TLSCertDomains {
		if unsubstituted(d) {
			return fmt.Errorf("config: listener.tls_cert_domains contains %q, still a placeholder -- substitute the hostname boards connect to (docs/brokerd-config.md)", d)
		}
	}
	return nil
}

// parseLogLevel maps the -log-level flag to a slog level. Unknown values
// are an error rather than a silent default (see main).
func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown -log-level %q: expected one of debug, info, warn, error", s)
	}
}

func run(configPath, reprocess string, testHooks, checkConfig bool, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	// Fail on an unedited sample before anything touches the filesystem or
	// the network, with a message that names the key.
	if err := validateSubstituted(cfg); err != nil {
		return err
	}

	// Report anything readable beyond its owner, and change nothing
	// (permcheck.go).
	warnLoosePermissions(cfg, configPath, log)

	// -check-config answers "would this file start, and what does it say" with
	// nothing else happening: no listener, no ACME, no database, no hook
	// delivered. Everything that can be decided from the file has been decided
	// by this point, including templates just below.
	if checkConfig {
		if cfg.EventHooks.Enabled {
			if err := hook.ValidateTemplates(cfg.EventHooks); err != nil {
				return fmt.Errorf("event_hooks: %w", err)
			}
		}
		reportConfig(cfg, log)
		return nil
	}

	var hooks *hook.Dispatcher
	if cfg.EventHooks.Enabled {
		if err := hook.ValidateTemplates(cfg.EventHooks); err != nil {
			return fmt.Errorf("event_hooks: %w", err)
		}
		hooks = hook.New(hook.Options{Config: cfg.EventHooks, Boards: cfg.Boards, Logger: log})
		if cfg.EventHooks.DryRun {
			log.Info("event_hooks enabled in dry_run mode — nothing will be POSTed or executed",
				"targets", len(cfg.EventHooks.Targets))
		} else {
			log.Warn("event_hooks enabled with dry_run=false — configured webhooks WILL be POSTed and configured commands WILL be executed",
				"targets", len(cfg.EventHooks.Targets))
		}
	}

	// -test-hooks runs here, before TLS and storage: checking hook plumbing
	// must not depend on an ACME certificate or a writable database, and
	// making it wait for both is what turned the first attempt at this into
	// a certificate error.
	if testHooks {
		selfTestCtx, cancelSelfTest := context.WithCancel(context.Background())
		defer cancelSelfTest()
		if hooks != nil {
			hooks.Run(selfTestCtx)
		}
		err := runHookSelfTest(hooks, log)
		cancelSelfTest()
		if hooks != nil {
			hooks.Wait()
		}
		return err
	}

	store, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer func() { _ = store.Close() }()

	// Reprocessing runs here: it needs the config's channel keys and the
	// database, and nothing else. Like -test-hooks, it must not depend on a
	// certificate.
	if reprocess != "" {
		return runReprocess(store, cfg, reprocess, log)
	}

	boardHashes := make(map[string]string, len(cfg.Boards))
	for _, b := range cfg.Boards {
		boardHashes[b.Username] = b.PasswordHash
	}
	authHook := auth.New(
		boardHashes,
		cfg.Auth.FailureThreshold,
		time.Duration(cfg.Auth.BanDurationMinutes)*time.Minute,
		cfg.Auth.IPAllowlist,
	)

	tlsMgr, err := loadTLS(cfg, log)
	if err != nil {
		return fmt.Errorf("loading TLS configuration: %w", err)
	}
	tlsConfig := tlsMgr.TLSConfig()

	var relayEngine *relay.Engine
	if cfg.OutboundRelay.Enabled {
		publisher := relay.NewPahoPublisher(cfg.OutboundRelay.Targets)
		defer publisher.Close()
		relayEngine = relay.New(cfg.OutboundRelay, cfg.Boards, publisher, log)
		if cfg.OutboundRelay.DryRunAllRules {
			log.Info("outbound_relay enabled in dry_run mode — nothing will actually be published")
		} else {
			log.Warn("outbound_relay enabled with dry_run_all_rules=false — eligible packets WILL be published to a real external target")
		}
	}

	br, err := broker.New(broker.Options{
		MQTTAddr:              cfg.Listener.MQTTAddr,
		KeepaliveFloorSeconds: cfg.Listener.KeepaliveFloorSeconds,
		TLSConfig:             tlsConfig,
		Boards:                cfg.Boards,
		ChannelPSKs:           cfg.ChannelPSKs(),
		AuthHook:              authHook,
		Store:                 store,
		RelayEngine:           relayEngine,
		Hooks:                 hookDispatcherOrNil(hooks),
		Log:                   log,
	})
	if err != nil {
		return fmt.Errorf("building broker: %w", err)
	}

	mon := monitor.New(monitor.Options{
		ListenAddr: cfg.Monitoring.ListenAddr,
		APIToken:   cfg.Monitoring.APIToken,
		Store:      store,
		AuthHook:   authHook,
		Broker:     br,
		Boards:     cfg.Boards,
		Hooks:      hookCountersOrNil(hooks),

		TrustTailscaleIdentity: cfg.Monitoring.TrustTailscaleIdentity,
		TailscaleAllowedLogins: cfg.Monitoring.TailscaleAllowedLogins,
		Log:                    log,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// The dispatcher gets its own context, cancelled only after the broker
	// has fully stopped. Sharing ctx meant the workers exited on SIGTERM
	// while the broker was still shutting down, so the board_disconnected
	// events that shutdown produces went into a queue nobody was draining
	// and vanished -- the one moment a "board went away" notification is
	// guaranteed to be generated.
	if hooks != nil {
		hookCtx, stopHooks := context.WithCancel(context.Background())
		hooks.Run(hookCtx)
		defer func() {
			// Let queued deliveries finish before the workers' context is
			// cancelled: cancelling first kills a hook command that is
			// already running, which is what happened to the two
			// board_disconnected events of the first real shutdown.
			hooks.Shutdown(hookShutdownTimeout)
			stopHooks()
			hooks.Wait()
			hooks.ReportUndelivered()
		}()
	}

	go tlsMgr.RunRenewalLoop(ctx, 12*time.Hour, func(err error) {
		log.Error("TLS certificate renewal failed", "error", err)
	})

	go runRetentionTicker(ctx, store, cfg.Retention.RawFramesDays, cfg.Retention.DecodedDays, log)

	monErrCh := make(chan error, 1)
	go func() {
		log.Info("monitoring API listening", "addr", cfg.Monitoring.ListenAddr)
		if err := mon.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			monErrCh <- err
		}
	}()
	go func() {
		// The monitoring API is read-only and not required for the core
		// relay function (docs/architecture.md §3) — a bind/serve failure
		// here is logged loudly but does not bring down the broker.
		select {
		case err := <-monErrCh:
			log.Error("monitoring API failed", "error", err)
		case <-ctx.Done():
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = mon.Shutdown(shutdownCtx)
	}()

	log.Info("brokerd starting", "mqtt_addr", cfg.Listener.MQTTAddr)
	if err := br.Serve(ctx); err != nil {
		return fmt.Errorf("broker serve: %w", err)
	}

	return nil
}

// runRetentionTicker runs the retention deletion job on a fixed
// schedule (ADR-7) until ctx is cancelled.
func runRetentionTicker(ctx context.Context, store *storage.Store, rawFramesDays, decodedDays int, log *slog.Logger) {
	ticker := time.NewTicker(retentionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rawDeleted, decodedDeleted, err := store.DeleteExpired(rawFramesDays, decodedDays)
			if err != nil {
				log.Error("retention job failed", "error", err)
				continue
			}
			if rawDeleted > 0 || decodedDeleted > 0 {
				log.Info("retention job deleted expired rows", "raw_frames", rawDeleted, "text_messages", decodedDeleted)
			}
		}
	}
}

// loadTLS builds brokerd's certificate manager (ADR-8, docs/adr.md):
// automatic issuance/renewal via the ACME DNS-01 challenge, using
// go-acme/lego's DNS provider registry (internal/tlscert). This
// performs real network calls (ACME account registration, and a
// certificate Obtain if none is cached yet) — it is not offline.
func loadTLS(cfg *config.Config, log *slog.Logger) (*tlscert.Manager, error) {
	if cfg.Listener.TLSUseStagingCA {
		log.Warn("listener.tls_use_staging_ca is true — issuing from Let's Encrypt's STAGING CA; certificates will not be trusted by real clients")
	}

	mgr, err := tlscert.NewManager(tlscert.Config{
		Domains:         cfg.Listener.TLSCertDomains,
		DNSProviderName: cfg.Listener.TLSDNSProvider,
		CacheDir:        cfg.Listener.TLSCacheDir,
		UseStagingCA:    cfg.Listener.TLSUseStagingCA,
	})
	if err != nil {
		return nil, fmt.Errorf("tlscert.NewManager: %w", err)
	}
	return mgr, nil
}

// hookDispatcherOrNil keeps a nil *hook.Dispatcher from becoming a non-nil
// interface value, which would make the broker's "hooks configured?" checks
// always true and dispatch into a zero dispatcher.
// hookShutdownTimeout bounds how long shutdown waits for hook deliveries.
// Generous relative to a target's own timeout (10s by default) because the
// alternative -- killing a delivery already in progress -- produces a failure
// that looks like the hook's fault.
const hookShutdownTimeout = 15 * time.Second

func hookDispatcherOrNil(d *hook.Dispatcher) broker.HookDispatcher {
	if d == nil {
		return nil
	}
	return d
}

// selfTestNodeID is the anonymised node id this project uses in examples, so a
// self-test payload is obviously synthetic to whoever receives it.
const selfTestNodeID = 0x11223344

// runHookSelfTest delivers one synthetic event per event kind and reports
// the resulting counters, so a new target can be checked at a chosen moment
// instead of by waiting for the mesh to produce traffic. It respects
// dry_run: a self-test that ignored it would be the one thing that fires a
// hook nobody armed.
func runHookSelfTest(hooks *hook.Dispatcher, log *slog.Logger) error {
	if hooks == nil {
		return fmt.Errorf("-test-hooks: event_hooks is not enabled in this config")
	}
	for _, event := range config.HookEventNames {
		switch event {
		case config.HookEventFrame:
			// Build it through the real payload builder, not by hand. A
			// hand-made Event drifts from the thing it stands in for: this one
			// was missing from and from_label the day they were added, so the
			// self test reported success while producing a payload no real
			// frame would produce.
			hooks.Dispatch(hook.FrameEvent(&decode.Result{
				PacketParsed:   true,
				Portnum:        decode.PortNumTextMessage,
				FromNode:       selfTestNodeID,
				ToNode:         0xffffffff,
				PacketID:       0x11111111,
				ChannelSegment: "self-test",
				TextMessage:    &decode.TextMessage{Text: "brokerd -test-hooks"},
			}, "self-test", time.Now()), nil)
		default:
			hooks.Dispatch(hook.BoardEvent(event, "self-test", "brokerd -test-hooks"), nil)
		}
	}

	// Deliveries happen on the dispatcher's workers; give them a moment
	// rather than exiting while a POST is in flight.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		snap := hooks.Snapshot()
		if total(snap.Fired)+total(snap.Failed)+total(snap.DryRun)+total(snap.Dropped) > 0 {
			time.Sleep(500 * time.Millisecond)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	snap := hooks.Snapshot()
	log.Info("-test-hooks finished",
		"fired", snap.Fired, "failed", snap.Failed, "dry_run", snap.DryRun,
		"dropped", snap.Dropped, "ratelimited", snap.RateLimited, "suppressed", snap.Suppressed)
	if n := total(snap.Failed); n > 0 {
		return fmt.Errorf("-test-hooks: %d delivery failure(s) — see the log lines above", n)
	}
	return nil
}

func total(m map[string]int64) int64 {
	var n int64
	for _, v := range m {
		n += v
	}
	return n
}

// hookCountersOrNil keeps a nil dispatcher from becoming a non-nil
// interface value in the monitoring API, for the same reason as
// hookDispatcherOrNil.
func hookCountersOrNil(d *hook.Dispatcher) monitor.HookCounters {
	if d == nil {
		return nil
	}
	return d
}

// runReprocess re-decodes stored frames and reports what changed
// (docs/storage-schema.md §7). "dry-run" is the only value that writes
// nothing, and it is what an unrecognised value is *not* silently treated
// as: a typo here would otherwise rewrite every row in the database.
func runReprocess(store *storage.Store, cfg *config.Config, mode string, log *slog.Logger) error {
	var apply bool
	switch mode {
	case "dry-run":
		apply = false
	case "apply":
		apply = true
	default:
		return fmt.Errorf("-reprocess: unknown mode %q (want \"dry-run\" or \"apply\")", mode)
	}

	report, err := store.Reprocess(cfg.ChannelPSKs(), cfg.Retention.DecodedDays, apply, log)
	if err != nil {
		return fmt.Errorf("reprocessing: %w", err)
	}

	log.Info("reprocess finished",
		"mode", mode,
		"scanned", report.Scanned,
		"fields_updated", report.FieldsUpdated,
		"decoded_rows_inserted", report.DecodedRowsInserted,
		"decoded_rows_skipped_outside_retention", report.DecodedRowsSkipped,
		"failed", report.Failed,
		"status_changes", report.StatusChanges,
		"status_change_frames", report.StatusChangeIDs,
		"kept_because_no_longer_decodable", report.Regressions,
		"backup", report.BackupPath,
	)
	if !apply {
		log.Info("reprocess: nothing was written — re-run with -reprocess apply to make these changes")
	}
	return nil
}

// reportConfig prints what a config file would do, for -check-config. It states
// what is enabled and what each hook target would receive, because the common
// mistake is not an invalid file but a valid one that matches nothing: a target
// filtered to a portnum the mesh never sends, or left enabled: false.
//
// Boards and channels are named individually rather than counted, because the
// same class of mistake applies to them and is otherwise invisible: brokerd
// matches channels[].name against the topic's channel segment verbatim
// (docs/protocol-spec.md §1), so a channel that is misspelled, or renamed on the
// boards, or simply never added, produces a perfectly valid config under which
// that channel's traffic can only ever be stored as opaque raw_frames. A count
// of "3 channels" cannot show that; the names can. Same for acl_filters: a
// filter that does not cover a channel's topic makes mochi-mqtt refuse the
// board's publishes and subscribes for it silently, at QoS 0
// (docs/security.md §3).
func reportConfig(cfg *config.Config, log *slog.Logger) {
	log.Info("config is valid",
		"mqtt_addr", cfg.Listener.MQTTAddr,
		"boards", len(cfg.Boards),
		"channels", len(cfg.Channels),
		"monitoring_addr", cfg.Monitoring.ListenAddr,
		"storage", cfg.Storage.Path)

	for _, b := range cfg.Boards {
		log.Info("board", "id", b.ID, "username", b.Username,
			"acl_filters", strings.Join(b.ACLFilters, ","),
			"node_id", b.NodeID)
	}
	// The name is printed with its length because a channel name is capped at
	// 11 usable characters and the CLI's --ch-add path refuses more than 10
	// (docs/firmware-config.md §12): a name that disagrees with the boards by
	// one truncated character is the failure this makes visible. Never the PSK
	// itself -- only that one was resolved, which config.Load already
	// guarantees.
	for _, ch := range cfg.Channels {
		log.Info("channel", "name", ch.Name, "name_len", len(ch.Name), "psk", "resolved")
	}

	if cfg.OutboundRelay.Enabled {
		for _, r := range cfg.OutboundRelay.Rules {
			log.Info("outbound relay rule", "id", r.ID, "enabled", r.Enabled,
				"portnum", r.SourcePortnum, "dry_run_all_rules", cfg.OutboundRelay.DryRunAllRules)
		}
	} else {
		log.Info("outbound relay is disabled")
	}

	if !cfg.EventHooks.Enabled {
		log.Info("event hooks are disabled")
		return
	}
	for _, t := range cfg.EventHooks.Targets {
		events := t.Match.Events
		if len(events) == 0 {
			events = config.HookEventNames
		}
		portnums := "any"
		if len(t.Match.Portnums) > 0 {
			portnums = strings.Join(t.Match.Portnums, ",")
		}
		log.Info("event hook target",
			"name", t.Name, "kind", t.Kind, "enabled", t.Enabled,
			"dry_run", cfg.EventHooks.DryRun,
			"events", strings.Join(events, ","), "portnums", portnums,
			"include_text", t.Match.IncludeText,
			"has_template", t.Template != "",
			"signed", t.Secret != "")
	}
}
