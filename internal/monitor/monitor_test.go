package monitor

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/meinside/mesh-brokerd/internal/auth"
	"github.com/meinside/mesh-brokerd/internal/broker"
	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
	"github.com/meinside/mesh-brokerd/internal/storage"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerWith(t, nil)
}

// newTestServerWith builds a test server whose Options can be adjusted, for
// the cases that turn a non-default switch on.
func newTestServerWith(t *testing.T, adjust func(*Options)) *Server {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	authHook := auth.New(map[string]string{}, 5, 30*time.Minute, nil)
	boards := []config.Board{{ID: "alpha", Username: "alpha"}}

	b, err := broker.New(broker.Options{
		MQTTAddr:    "127.0.0.1:0",
		Boards:      boards,
		ChannelPSKs: map[string][decode.PSKSize]byte{},
		AuthHook:    authHook,
		Store:       store,
	})
	if err != nil {
		t.Fatalf("broker.New: %v", err)
	}

	opts := Options{
		ListenAddr: ":0",
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		APIToken:   "test-token",
		Store:      store,
		AuthHook:   authHook,
		Broker:     b,
		Boards:     boards,
	}
	if adjust != nil {
		adjust(&opts)
	}
	return New(opts)
}

func doRequest(t *testing.T, s *Server, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	return w
}

func TestHealth_Unauthenticated(t *testing.T) {
	s := newTestServer(t)
	w := doRequest(t, s, "GET", "/health", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /health = %d, want 200", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("body = %+v, want status=ok", body)
	}
}

func TestAuthenticatedEndpoints_RejectMissingOrWrongToken(t *testing.T) {
	s := newTestServer(t)
	for _, path := range []string{"/api/v1/nodes", "/api/v1/stats/messages", "/api/v1/stats/auth", "/metrics"} {
		if w := doRequest(t, s, "GET", path, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without token = %d, want 401", path, w.Code)
		}
		if w := doRequest(t, s, "GET", path, "wrong-token"); w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with wrong token = %d, want 401", path, w.Code)
		}
	}
}

func TestNodes_ListsConfiguredBoardsOffline(t *testing.T) {
	s := newTestServer(t)
	w := doRequest(t, s, "GET", "/api/v1/nodes", "test-token")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/nodes = %d, want 200", w.Code)
	}
	var nodes []nodeStatus
	if err := json.Unmarshal(w.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if len(nodes) != 1 || nodes[0].BoardID != "alpha" || nodes[0].Status != "offline" {
		t.Errorf("nodes = %+v, want one offline \"office\" entry (no raw_frames rows yet)", nodes)
	}
}

func TestStatsMessages_Shape(t *testing.T) {
	s := newTestServer(t)
	w := doRequest(t, s, "GET", "/api/v1/stats/messages", "test-token")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/stats/messages = %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	for _, key := range []string{
		"throughput_per_topic", "decode_failures_by_reason", "storage_queue_drops",
		"outbound_relay",
		// Every report-only counter must be reachable over the API: the
		// hooks that feed them act on nothing, so an unexposed counter is
		// a counter nobody can ever read (this list caught two).
		"listener_noise_suppressed_total", "board_node_id_mismatches_total",
		// A frame that arrived in the clear on a PSK'd channel decodes and
		// stores like any other, so this counter is the only reachable
		// evidence of mqtt.encryption_enabled = false on a board.
		"plaintext_uplinks_total",
		"acl_denials_total", "downlink_missed_total", "connected_boards",
		// session_takeovers_total is the only record that a replaced
		// session's disconnect was deliberately not reported.
		"session_takeovers_total",
		// Event-hook counters, including disabled_targets -- the one place
		// an action brokerd took on its own is readable after the log line
		// has scrolled away (ADR-17).
		"event_hooks",
	} {
		if _, ok := body[key]; !ok {
			t.Errorf("response missing key %q: %+v", key, body)
		}
	}
}

func TestStatsAuth_Shape(t *testing.T) {
	s := newTestServer(t)
	w := doRequest(t, s, "GET", "/api/v1/stats/auth", "test-token")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/stats/auth = %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if _, ok := body["auth_failures_total"]; !ok {
		t.Errorf("response missing auth_failures_total: %+v", body)
	}
	if _, ok := body["active_bans"]; !ok {
		t.Errorf("response missing active_bans: %+v", body)
	}
}

func TestMetrics_NotImplemented(t *testing.T) {
	s := newTestServer(t)
	w := doRequest(t, s, "GET", "/metrics", "test-token")
	if w.Code != http.StatusNotImplemented {
		t.Errorf("GET /metrics = %d, want 501", w.Code)
	}
}

// TestStatsMessages_EventHooksEmptyWithoutConfig distinguishes "no hooks
// configured" from "hooks that never fired": both are quiet, and only one
// of them is a misconfiguration.
func TestStatsMessages_EventHooksEmptyWithoutConfig(t *testing.T) {
	s := newTestServer(t)
	w := doRequest(t, s, "GET", "/api/v1/stats/messages", "test-token")
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	hooks, ok := body["event_hooks"].(map[string]any)
	if !ok {
		t.Fatalf("event_hooks missing or not an object: %v", body["event_hooks"])
	}
	if len(hooks) != 0 {
		t.Errorf("event_hooks = %v, want an empty object when no hooks are configured", hooks)
	}
}
