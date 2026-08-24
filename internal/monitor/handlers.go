package monitor

import (
	"net/http"
	"time"
)

type nodeStatus struct {
	BoardID  string  `json:"board_id"`
	LastSeen *string `json:"last_seen"`
	Status   string  `json:"status"`
}

// handleNodes implements GET /api/v1/nodes (docs/monitoring-api.md §1):
// per-board (not yet per-mesh-node) online/offline + last-seen.
func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	lastSeen := make(map[string]time.Time)
	rows, err := s.store.DB().Query(`SELECT board_id, MAX(received_at) FROM raw_frames GROUP BY board_id;`)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var boardID, receivedAt string
		if err := rows.Scan(&boardID, &receivedAt); err != nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339, receivedAt); err == nil {
			lastSeen[boardID] = t
		}
	}

	now := time.Now()
	out := make([]nodeStatus, 0, len(s.boards))
	for _, b := range s.boards {
		ns := nodeStatus{BoardID: b.ID, Status: "offline"}
		if t, ok := lastSeen[b.ID]; ok {
			str := t.UTC().Format(time.RFC3339)
			ns.LastSeen = &str
			if now.Sub(t) <= onlineWithin {
				ns.Status = "online"
			}
		}
		out = append(out, ns)
	}

	writeJSON(w, out)
}

// handleStatsMessages implements GET /api/v1/stats/messages
// (docs/monitoring-api.md §1/§4): per-channel throughput (all-time
// counts since startup — a running total, not yet a rate; refine once
// real query patterns are known), decode failures by reason (ADR-4),
// the storage queue drop counter (ADR-3), and outbound_relay counters
// (empty until docs/outbound-relay.md ships, ADR-12).
func (s *Server) handleStatsMessages(w http.ResponseWriter, r *http.Request) {
	throughput := make(map[string]int64)
	rows, err := s.store.DB().Query(`SELECT channel_segment, COUNT(*) FROM raw_frames GROUP BY channel_segment;`)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var channel string
		var count int64
		if err := rows.Scan(&channel, &count); err != nil {
			continue
		}
		throughput[channel] = count
	}

	decodeFailures := make(map[string]int64)
	for status, count := range s.broker.DecodeStatusCounts() {
		if status == "decoded" {
			continue
		}
		decodeFailures[status] = count
	}

	dryRunTotal, publishedTotal, publishFailuresTotal := s.broker.OutboundRelayCounters()
	writeJSON(w, map[string]any{
		"throughput_per_topic":      throughput,
		"decode_failures_by_reason": decodeFailures,
		"storage_queue_drops":       s.broker.DropCount(),
		// Listener noise suppressed out of the WARN log (per category)
		// and boards whose declared node_id disagrees with the
		// gateway_id in their traffic. Both are reported rather
		// than acted on, so this is the only place they accumulate.
		"listener_noise_suppressed_total": s.broker.ListenerNoiseCounts(),
		"board_node_id_mismatches_total":  s.broker.NodeIDMismatches(),
		// Publishes/subscribes the ACL refused. mochi-mqtt refuses a QoS 0
		// publish silently, so this counter and its one log line are the
		// only record that it happened.
		"acl_denials_total": s.broker.ACLDenials(),
		// Frames published while a configured board was disconnected, and
		// so lost to it: MQTT downlink here is QoS 0 with a clean session,
		// leaving the broker nothing to replay (docs/architecture.md §8.1).
		// connected_boards is the same tracker's live view, and the
		// only way to tell "no traffic" from "board absent".

		"downlink_missed_total":   s.broker.DownlinkMissed(),
		"session_takeovers_total": s.broker.SessionTakeovers(),
		"connected_boards":        s.broker.ConnectedBoards(),
		// Event-hook counters (ADR-17). Present as an empty object when
		// event_hooks is not configured, so a consumer can tell "no hooks"
		// from "hooks that never fired".
		"event_hooks": s.hookCounters(),
		"outbound_relay": map[string]any{
			"dry_run_total":          dryRunTotal,
			"published_total":        publishedTotal,
			"publish_failures_total": publishFailuresTotal,
		},
	})
}

type banInfo struct {
	IP        string `json:"ip"`
	ExpiresAt string `json:"expires_at"`
}

// handleStatsAuth implements GET /api/v1/stats/auth
// (docs/monitoring-api.md §1, ADR-5). IP addresses are visible here —
// this endpoint is authenticated, never anonymous.
func (s *Server) handleStatsAuth(w http.ResponseWriter, r *http.Request) {
	bans := make([]banInfo, 0)
	for _, b := range s.authHook.ActiveBans() {
		bans = append(bans, banInfo{IP: b.IP, ExpiresAt: b.ExpiresAt.UTC().Format(time.RFC3339)})
	}

	writeJSON(w, map[string]any{
		"auth_failures_total": s.authHook.FailuresTotal(),
		"active_bans":         bans,
	})
}

// handleMetrics implements the reserved /metrics path
// (docs/monitoring-api.md §1): optional and deferred, "listed here so the
// path is reserved" -- this stub keeps the
// path from colliding with a future ad-hoc endpoint without claiming
// Prometheus support that doesn't exist yet.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented: reserved for a future Prometheus exposition endpoint (docs/monitoring-api.md §1)", http.StatusNotImplemented)
}

// hookCounters renders the event-hook dispatcher's totals, or an empty
// object when no hooks are configured. disabled_targets is the one field
// that reports an action brokerd took on its own (auto-disabling a target
// after repeated failures), which is why it must be readable here rather
// than only in a log line that has since scrolled away.
func (s *Server) hookCounters() map[string]any {
	if s.hooks == nil {
		return map[string]any{}
	}
	snap := s.hooks.Snapshot()
	return map[string]any{
		"fired_total":       snap.Fired,
		"failed_total":      snap.Failed,
		"dropped_total":     snap.Dropped,
		"ratelimited_total": snap.RateLimited,
		"suppressed_total":  snap.Suppressed,
		"dry_run_total":     snap.DryRun,
		"disabled_targets":  snap.Disabled,
	}
}
