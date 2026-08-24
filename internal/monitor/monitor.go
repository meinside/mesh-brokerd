// Package monitor implements brokerd's read-only monitoring HTTP API
// (docs/monitoring-api.md), exposed on the public 443 listener. Nothing
// here can change brokerd's configuration (docs/security.md §4).
package monitor

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/meinside/mesh-brokerd/internal/auth"
	"github.com/meinside/mesh-brokerd/internal/broker"
	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/hook"
	"github.com/meinside/mesh-brokerd/internal/storage"
)

// onlineWithin is how long after its last frame a board still counts as
// online.
//
// 2 hours, from measurement rather than taste: these gateways publish a map
// report once an hour (the firmware's minimum publish_interval_secs of 3600)
// and a position on a similar cadence, and nothing else is guaranteed to
// arrive at all. The first value here was 15 minutes, chosen before that
// cadence was known, and it reported a perfectly healthy board as offline for
// 45 minutes out of every hour. 90 minutes fixed that but left only half an
// hour of slack, so a single missed hourly report still read as silent; two
// hours means two consecutive misses before the page says so.
//
// A board's live MQTT session is the better signal and the page shows it
// separately; this threshold only answers "has anything arrived recently".
const onlineWithin = 2 * time.Hour

// Server is brokerd's monitoring HTTP server.
//
// It always serves **plain HTTP**. The API is meant to bind loopback and
// be published by a reverse proxy that terminates TLS
// (docs/monitoring-api.md section 0), so terminating TLS here as well
// would only break the proxy's plain-HTTP connection to it. brokerd's own
// ACME certificate (ADR-8) is therefore used solely by the MQTT listener.
type Server struct {
	// startedAt is when this process's monitoring server was built. Every
	// in-memory counter on the page resets here, so the page has to be able to
	// say since when -- a counter shown without its baseline reads as a total,
	// and "missed 4 downlink frames" was asked about for exactly that reason.
	startedAt  time.Time
	httpServer *http.Server
	store      *storage.Store
	authHook   *auth.Hook
	broker     *broker.Broker
	boards     []config.Board
	hooks      HookCounters
	token      string

	// Browser access without a token is possible only behind a Tailscale
	// Serve proxy, and only when explicitly enabled (auth.go explains why
	// the loopback listen address is this path's premise).
	trustTailscaleIdentity bool
	tailscaleAllowedLogins []string

	log *slog.Logger
}

// HookCounters is the part of internal/hook.Dispatcher this API reads. An
// interface so the monitoring server does not depend on the dispatcher's
// construction, and so "hooks not configured" stays a nil check.
type HookCounters interface {
	Snapshot() hook.Counters

	// ConfiguredTargets is what exists, as opposed to what has happened. The
	// page needs both: a target that has fired nothing must not read as no
	// target at all.
	ConfiguredTargets() []hook.TargetInfo
}

// Options configures a new Server.
type Options struct {
	// ListenAddr should normally be a loopback address (the default is
	// 127.0.0.1:9101, docs/brokerd-config.md) so this API is not exposed
	// directly to the internet.
	ListenAddr string
	APIToken   string
	Store      *storage.Store
	AuthHook   *auth.Hook
	Broker     *broker.Broker
	Boards     []config.Board
	// Hooks is nil unless event_hooks is configured (ADR-17).
	Hooks HookCounters

	TrustTailscaleIdentity bool
	TailscaleAllowedLogins []string

	Log *slog.Logger
}

// New builds a monitoring Server (not yet listening — call Serve).
func New(opts Options) *Server {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	s := &Server{
		startedAt:              time.Now(),
		store:                  opts.Store,
		authHook:               opts.AuthHook,
		broker:                 opts.Broker,
		boards:                 opts.Boards,
		hooks:                  opts.Hooks,
		trustTailscaleIdentity: opts.TrustTailscaleIdentity,
		tailscaleAllowedLogins: opts.TailscaleAllowedLogins,
		log:                    opts.Log,
		token:                  opts.APIToken,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.requirePageAuth(s.handlePage))
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/nodes", s.requireAuth(s.handleNodes))
	mux.HandleFunc("GET /api/v1/stats/messages", s.requireAuth(s.handleStatsMessages))
	mux.HandleFunc("GET /api/v1/stats/auth", s.requireAuth(s.handleStatsAuth))
	mux.HandleFunc("GET /metrics", s.requireAuth(s.handleMetrics))

	s.httpServer = &http.Server{
		Addr:    opts.ListenAddr,
		Handler: mux,
	}
	return s
}

// Serve blocks, listening on Options.ListenAddr over plain HTTP.
func (s *Server) Serve() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}
