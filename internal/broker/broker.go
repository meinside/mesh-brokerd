package broker

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	mauth "github.com/mochi-mqtt/server/v2/hooks/auth"
	"github.com/mochi-mqtt/server/v2/listeners"

	brokerdauth "github.com/meinside/mesh-brokerd/internal/auth"
	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
	"github.com/meinside/mesh-brokerd/internal/relay"
	"github.com/meinside/mesh-brokerd/internal/storage"
)

// Broker owns the embedded mochi-mqtt server, its hooks, and the
// storage worker goroutine (docs/architecture.md §3).
type Broker struct {
	server        *mqtt.Server
	relay         *RelayHook
	worker        *Worker
	noise         *NoiseFilter
	nodeID        *NodeIDChecker
	aclLog        *ACLDenialLogger
	presence      *PresenceHook
	subscriptions *SubscriptionTracker

	shutdownTimeout time.Duration
	log             *slog.Logger
}

// Options configures a new Broker.
type Options struct {
	MQTTAddr  string
	TLSConfig *tls.Config // nil = plaintext listener (dev/testing only, never on the public listener)
	QueueSize int         // ADR-3's bounded queue depth; 0 uses a default

	Boards []config.Board
	// ChannelPSKs is internal/config.Config.ChannelPSKs()'s output.
	ChannelPSKs map[string][decode.PSKSize]byte

	AuthHook *brokerdauth.Hook // internal/auth.New(...)

	Store *storage.Store

	// RelayEngine is nil unless outbound_relay is configured
	// (docs/outbound-relay.md, ADR-12).
	RelayEngine *relay.Engine

	// Hooks is nil unless event_hooks is configured (docs/event-hooks.md,
	// ADR-17). Frame events come from the storage worker, connection
	// events from the presence hook.
	Hooks HookDispatcher

	// KeepaliveFloorSeconds raises a client's advertised keepalive to at
	// least this value, lengthening mochi-mqtt's read deadline
	// (keepalive * 1.5). 0 leaves every client's own value alone and only
	// logs it (internal/broker.KeepaliveFloorHook).
	KeepaliveFloorSeconds uint16

	ShutdownTimeout time.Duration // ADR-6; 0 uses a default
	Log             *slog.Logger
}

const (
	defaultQueueSize       = 1024
	defaultShutdownTimeout = 10 * time.Second
)

// New builds a Broker: the mochi-mqtt server, its ACL/auth/relay hooks,
// one TLS+TCP listener, and the storage worker (not yet started —
// call Serve).
func New(opts Options) (*Broker, error) {
	if opts.QueueSize == 0 {
		opts.QueueSize = defaultQueueSize
	}
	if opts.ShutdownTimeout == 0 {
		opts.ShutdownTimeout = defaultShutdownTimeout
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	// Route mochi-mqtt's own logging through brokerd's logger, so broker
	// internals and brokerd's messages share one destination and one format
	// instead of mochi writing through its own handler.
	//
	// The wrapper demotes internet background noise (scanner TLS
	// handshakes, non-MQTT bytes) to DEBUG and counts it instead, so it
	// stops burying real diagnostics. It is applied only to mochi's
	// logger, never to brokerd's own, and only to the categories
	// NoiseFilter documents -- transport errors from real boards stay at
	// WARN because a flaky uplink is diagnosed by counting them.
	noise := NewNoiseFilter(log.Handler())
	server := mqtt.New(&mqtt.Options{Logger: slog.New(noise)})

	// Records the keepalive each client asks for, and raises it to a floor
	// when configured. Registered before the auth hook only for tidiness --
	// it provides OnConnect, which mochi-mqtt dispatches separately from
	// OnConnectAuthenticate. A floor of 0 (the default) changes nothing and
	// only logs, which is how the value gets measured before choosing one.
	if err := server.AddHook(NewKeepaliveFloorHook(opts.KeepaliveFloorSeconds, log), nil); err != nil {
		return nil, fmt.Errorf("broker: adding keepalive hook: %w", err)
	}

	// bcrypt authentication + per-IP banning (ADR-5).
	//
	// Registered BEFORE the ACL hook, and the order matters for the log.
	// mochi-mqtt dispatches OnConnectAuthenticate to each hook in
	// registration order and stops at the first true (an OR), so with this
	// hook first a successful connection never reaches the ACL hook's
	// OnConnectAuthenticate -- which cannot authenticate anything and logs
	// "client failed authentication check" when consulted. Reversed, that
	// line appears for every *successful* connection, and the only
	// server-side evidence of a healthy board becomes a message saying it
	// failed. Guarded by
	// TestBroker_SuccessfulAuthIsNotLoggedAsFailure.
	if err := server.AddHook(opts.AuthHook, nil); err != nil {
		return nil, fmt.Errorf("broker: adding auth hook: %w", err)
	}

	// ACL enforcement only (docs/security.md §3) -- this hook's own
	// OnConnectAuthenticate is never relied on (internal/auth.BuildLedger's
	// doc comment explains why).
	if err := server.AddHook(new(mauth.Hook), &mauth.Options{Ledger: brokerdauth.BuildLedger(opts.Boards)}); err != nil {
		return nil, fmt.Errorf("broker: adding ACL ledger hook: %w", err)
	}

	// Registered AFTER the ACL ledger, and the order is load-bearing:
	// mochi-mqtt's OnACLCheck is an OR that stops at the first hook to
	// return true, so a hook placed here is consulted only for topics the
	// ledger has already refused. That is what turns it into a denial
	// observer. It always returns false and never widens access
	// (internal/broker.ACLDenialLogger).
	aclDenials := NewACLDenialLogger(log)
	if err := server.AddHook(aclDenials, nil); err != nil {
		return nil, fmt.Errorf("broker: adding ACL denial logger: %w", err)
	}

	// Tracks which boards are connected, and counts frames published
	// while one was absent -- which, with cleanSession and QoS 0, are frames
	// that board will never see (docs/architecture.md section 7).
	presence := NewPresenceHook(opts.Boards, log)
	if err := server.AddHook(presence, nil); err != nil {
		return nil, fmt.Errorf("broker: adding presence hook: %w", err)
	}

	// Records what each board asked to receive. An absent subscription is
	// refused by nothing and logged by nothing, so without this a board that
	// silently never subscribes to a channel is indistinguishable from one
	// that does (internal/broker.SubscriptionTracker).
	subscriptions := NewSubscriptionTracker(log)
	if err := server.AddHook(subscriptions, nil); err != nil {
		return nil, fmt.Errorf("broker: adding subscription tracker: %w", err)
	}

	relay := NewRelayHook(opts.QueueSize)
	relay.SetPresence(presence)
	if opts.Hooks != nil {
		presence.SetHooks(opts.Hooks)
	}
	if err := server.AddHook(relay, nil); err != nil {
		return nil, fmt.Errorf("broker: adding relay hook: %w", err)
	}

	tcp := listeners.NewTCP(listeners.Config{
		ID:        "mqtt-tls",
		Address:   opts.MQTTAddr,
		TLSConfig: opts.TLSConfig,
	})
	if err := server.AddListener(tcp); err != nil {
		return nil, fmt.Errorf("broker: adding TCP listener on %s: %w", opts.MQTTAddr, err)
	}

	boardIDByUsername := make(map[string]string, len(opts.Boards))
	for _, b := range opts.Boards {
		boardIDByUsername[b.Username] = b.ID
	}
	// Cross-check each board's declared node_id against the
	// gateway_id its frames actually carry.
	nodeIDChecker := NewNodeIDChecker(opts.Boards)
	worker := NewWorker(relay, opts.Store, opts.ChannelPSKs, boardIDByUsername, opts.RelayEngine, nodeIDChecker, log)
	if opts.Hooks != nil {
		worker.SetHooks(opts.Hooks)
	}

	return &Broker{
		server:          server,
		relay:           relay,
		worker:          worker,
		noise:           noise,
		nodeID:          nodeIDChecker,
		aclLog:          aclDenials,
		presence:        presence,
		subscriptions:   subscriptions,
		shutdownTimeout: opts.ShutdownTimeout,
		log:             log,
	}, nil
}

// Serve starts the storage worker goroutine and the mochi-mqtt server
// (whose own Serve() call only sets up listeners and returns
// immediately — it is not itself blocking). This method blocks until
// ctx is cancelled, then performs ADR-6's graceful shutdown.
func (b *Broker) Serve(ctx context.Context) error {
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	go b.worker.Run(workerCtx)

	if err := b.server.Serve(); err != nil {
		cancelWorker()
		return fmt.Errorf("broker: starting mochi-mqtt server: %w", err)
	}

	<-ctx.Done()
	return b.shutdown(cancelWorker)
}

// shutdown implements ADR-6's graceful shutdown: stop accepting new
// broker connections, drain the storage queue up to shutdownTimeout,
// then let the caller exit. systemd (Restart=always) is expected to
// bring brokerd back up.
func (b *Broker) shutdown(cancelWorker context.CancelFunc) error {
	// Before anything closes: label the disconnects that are about to happen
	// as ours, so a hook consumer is not told a board dropped off
	// (internal/broker/presence.go).
	b.presence.MarkShuttingDown()

	if err := b.server.Close(); err != nil {
		b.log.Error("broker: error closing mochi-mqtt server", "error", err)
	}

	deadline := time.Now().Add(b.shutdownTimeout)
	for len(b.relay.messages()) > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}

	cancelWorker()
	return nil
}

// DropCount exposes RelayHook.DropCount for monitoring
// (docs/monitoring-api.md's storage_queue_drops).
func (b *Broker) DropCount() int64 { return b.relay.DropCount() }

// ListenerNoiseCounts exposes NoiseFilter.Counts for monitoring
// (docs/monitoring-api.md's listener_noise_suppressed_total).
func (b *Broker) ListenerNoiseCounts() map[string]int64 { return b.noise.Counts() }

// NodeIDMismatches exposes NodeIDChecker.Mismatches for monitoring
// (docs/monitoring-api.md's board_node_id_mismatches_total).
func (b *Broker) NodeIDMismatches() map[string]int64 { return b.nodeID.Mismatches() }

// ACLDenials exposes ACLDenialLogger.Denials for monitoring
// (docs/monitoring-api.md's acl_denials_total).
func (b *Broker) ACLDenials() map[string]int64 { return b.aclLog.Denials() }

// DownlinkMissed exposes PresenceHook.DownlinkMissed for monitoring
// (docs/monitoring-api.md's downlink_missed_total).
func (b *Broker) DownlinkMissed() map[string]int64 { return b.presence.DownlinkMissed() }

// SessionTakeovers exposes PresenceHook.SessionTakeovers for monitoring. It is
// the only record that a replaced session's disconnect was deliberately not
// reported, so it has to be readable from outside.
func (b *Broker) SessionTakeovers() map[string]int64 { return b.presence.SessionTakeovers() }

// ConnectedBoards exposes the currently-connected board usernames
// (docs/monitoring-api.md's connected_boards).
func (b *Broker) ConnectedBoards() []string { return b.presence.Connected() }

// BoardSubscriptions exposes SubscriptionTracker.Subscriptions for monitoring
// (docs/monitoring-api.md's board_subscriptions).
func (b *Broker) BoardSubscriptions() map[string][]string { return b.subscriptions.Subscriptions() }

// DecodeStatusCounts exposes Worker.DecodeStatusCounts for monitoring.
func (b *Broker) DecodeStatusCounts() map[string]int64 { return b.worker.DecodeStatusCounts() }

// PlaintextUplinks exposes PlaintextChecker's counters for monitoring
// (docs/monitoring-api.md's plaintext_uplinks_total).
func (b *Broker) PlaintextUplinks() map[string]int64 { return b.worker.PlaintextUplinks() }

// OutboundRelayCounters exposes the outbound relay engine's counters
// for monitoring (docs/monitoring-api.md section 4,
// docs/outbound-relay.md section 8). All three maps are empty
// (never nil) when no relay engine is configured.
// OutboundRelayRules reports what the relay is configured to do, so the
// monitoring page can show a rule that has published nothing yet instead of
// implying no relay exists.
func (b *Broker) OutboundRelayRules() []relay.RuleInfo {
	if b.worker.relayEngine == nil {
		return nil
	}
	return b.worker.relayEngine.ConfiguredRules()
}

func (b *Broker) OutboundRelayCounters() (dryRunTotal, publishedTotal, publishFailuresTotal map[string]int64) {
	if b.worker.relayEngine == nil {
		return map[string]int64{}, map[string]int64{}, map[string]int64{}
	}
	return b.worker.relayEngine.DryRunTotal(), b.worker.relayEngine.PublishedTotal(), b.worker.relayEngine.PublishFailuresTotal()
}
