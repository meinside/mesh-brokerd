package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/meinside/mesh-brokerd/internal/config"
	"github.com/meinside/mesh-brokerd/internal/decode"
	"github.com/meinside/mesh-brokerd/internal/hook"
)

func TestParseLogLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		// Case should not matter: an operator typing DEBUG in a systemd
		// unit is not making a mistake worth failing startup over.
		{"DEBUG", slog.LevelDebug},
		{"Info", slog.LevelInfo},
		{" warn ", slog.LevelWarn},
	}
	for _, c := range cases {
		got, err := parseLogLevel(c.in)
		if err != nil {
			t.Errorf("parseLogLevel(%q) returned error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseLogLevel(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// An unusable value must fail loudly at startup rather than silently
// falling back, so a typo in a unit file cannot quietly leave brokerd
// logging at a level the operator did not choose.
func TestParseLogLevel_RejectsUnknown(t *testing.T) {
	for _, in := range []string{"", "verbose", "trace", "9"} {
		got, err := parseLogLevel(in)
		if err == nil {
			t.Errorf("parseLogLevel(%q) = %v, want an error", in, got)
			continue
		}
		// The message has to tell the operator what is accepted; being
		// told only that the value is wrong means reading source next.
		for _, want := range []string{"debug", "info", "warn", "error"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("parseLogLevel(%q) error %q does not mention the accepted value %q", in, err, want)
			}
		}
	}
}

// Copying config.json.sample and forgetting to substitute a path must fail
// with a message that says so.
//
// The sample uses bracketed placeholders for paths on purpose, so that they
// cannot be mistaken for working defaults. Left in place they produce
// "unable to open database file: no such file or directory", which reads as
// a missing directory rather than an unedited config. internal/config
// already rejects an unsubstituted outbound_relay root_topic; this covers
// the values that are always used.
func TestValidateSubstituted(t *testing.T) {
	clean := func() *config.Config {
		return &config.Config{
			Listener: config.Listener{
				TLSCertDomains: []string{"broker.example.com"},
				TLSCacheDir:    "/var/lib/brokerd/tls-cache",
			},
			Storage: config.Storage{Path: "/var/lib/brokerd/brokerd.db"},
		}
	}

	if err := validateSubstituted(clean()); err != nil {
		t.Fatalf("a fully substituted config was rejected: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*config.Config)
		wantKey string
	}{
		{"storage path", func(c *config.Config) { c.Storage.Path = "</path/to/brokerd.db>" }, "storage.path"},
		{"tls cache dir", func(c *config.Config) { c.Listener.TLSCacheDir = "</dir/to/tls-cache>" }, "listener.tls_cache_dir"},
		{"cert domain", func(c *config.Config) {
			c.Listener.TLSCertDomains = []string{"<broker.example.com>"}
		}, "listener.tls_cert_domains"},
	}
	for _, c := range cases {
		cfg := clean()
		c.mutate(cfg)
		err := validateSubstituted(cfg)
		if err == nil {
			t.Errorf("%s: an unsubstituted placeholder was accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.wantKey) {
			t.Errorf("%s: error does not name the key %q: %v", c.name, c.wantKey, err)
		}
	}
}

// TestRunHookSelfTest_ProducesARealisticPayload is the test the self test
// needed. It used to build its frame event by hand, so the payload it sent
// drifted from the one a real frame produces: the day `from` and `from_label`
// were added, -test-hooks kept reporting success while sending neither, and a
// template interpolating them rendered an empty string.
func TestRunHookSelfTest_ProducesARealisticPayload(t *testing.T) {
	bodies := make(chan []byte, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.EventHooks{
		Enabled: true, QueueSize: 16, MaxConcurrent: 2,
		Targets: []config.HookTarget{{
			Name: "self-test-target", Kind: config.HookKindWebhook, Enabled: true,
			URL: srv.URL, Timeout: 5 * time.Second,
			Match: config.HookMatch{Events: []string{config.HookEventFrame}, IncludeText: true},
		}},
	}
	var logs strings.Builder
	hooks := hook.New(hook.Options{Config: cfg, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); hooks.Wait() }()
	hooks.Run(ctx)

	if err := runHookSelfTest(hooks, slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatalf("runHookSelfTest: %v", err)
	}

	var payload map[string]any
	select {
	case body := <-bodies:
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("payload is not JSON: %v\n%s", err, body)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the self test delivered no frame event; dispatcher said:\n%s", logs.String())
	}

	// Every field a template is likely to interpolate must be there and
	// non-empty. This list is what a consumer builds a message out of.
	for _, key := range []string{"event", "delivered_at", "received_at", "board_id",
		"channel", "portnum", "from", "from_id", "packet_id"} {
		v, ok := payload[key]
		if !ok {
			t.Errorf("the self-test payload omits %q, so -test-hooks cannot show what a real frame looks like", key)
			continue
		}
		if s, isStr := v.(string); isStr && s == "" {
			t.Errorf("the self-test payload has an empty %q", key)
		}
	}
	// The id is spelled Meshtastic's way and stands on its own; the self test
	// has no name resolver, so from_name is legitimately absent -- and must not
	// be present as an empty string.
	if id, _ := payload["from_id"].(string); !strings.HasPrefix(id, "!") {
		t.Errorf("from_id = %q, want Meshtastic's !hex spelling", id)
	}
	if _, ok := payload["from_name"]; ok {
		t.Errorf("from_name is present with no name known: %v", payload["from_name"])
	}
	if fields, ok := payload["fields"].(map[string]any); !ok || fields["text"] == "" {
		t.Errorf("the self-test payload carries no message text: %v", payload["fields"])
	}
}

// TestSampleConfigTemplatesRender keeps the shipped sample honest. The config
// smoke test loads config.json.sample but never renders its templates, and
// ValidateTemplates runs from main rather than from loading -- so a sample
// carrying a template that cannot render would ship, and the first person to
// copy it would hit the failure instead of us.
func TestSampleConfigTemplatesRender(t *testing.T) {
	// Same environment the config package's own smoke test provides: the
	// sample references secrets by name and refuses to load without them.
	t.Setenv("BROKERD_DNS_TOKEN", "x")
	t.Setenv("BROKERD_BOARD_ALPHA_PASSWORD_HASH", "$2a$12$abcdefghijklmnopqrstuv")
	t.Setenv("BROKERD_BOARD_BRAVO_PASSWORD_HASH", "$2a$12$abcdefghijklmnopqrstuv")
	t.Setenv("BROKERD_CHANNEL_PRVTCHN_PSK", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
	t.Setenv("BROKERD_MONITORING_TOKEN", "x")
	t.Setenv("BROKERD_RELAY_PUBLIC_PASSWORD", "large4cats")

	cfg, err := config.Load("config.json.sample")
	if err != nil {
		t.Fatalf("loading config.json.sample: %v", err)
	}
	if len(cfg.EventHooks.Targets) == 0 {
		t.Fatal("the sample has no event hook targets to check")
	}
	if err := hook.ValidateTemplates(cfg.EventHooks); err != nil {
		t.Errorf("a template in config.json.sample cannot render: %v", err)
	}

	// At least one sample target should show the recommended way to name a
	// sender, since that is the expression every notification needs.
	found := false
	for _, target := range cfg.EventHooks.Targets {
		if strings.Contains(target.Template, "or .FromName .FromID") {
			found = true
		}
	}
	if !found {
		t.Error("no sample template shows {{or .FromName .FromID}}, the one expression that names a sender whether or not a name is known")
	}
}

// TestReportConfig_NamesBoardsAndChannels pins what -check-config must print.
// A count of channels cannot answer the question the flag exists for -- "is this
// valid file actually wired to what the boards send" -- because brokerd matches
// channels[].name against the topic's channel segment verbatim, and an
// acl_filters entry that misses a channel's topic makes every publish and
// subscribe for it fail silently at QoS 0. Both were invisible while this
// printed only counts, and README already promised the names.
func TestReportConfig_NamesBoardsAndChannels(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var psk [decode.PSKSize]byte
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	cfg := &config.Config{
		Listener:   config.Listener{MQTTAddr: ":8883"},
		Monitoring: config.Monitoring{ListenAddr: "127.0.0.1:9101"},
		Storage:    config.Storage{Path: "/tmp/brokerd.db"},
		Boards: []config.Board{
			{ID: "alpha", Username: "alpha", ACLFilters: []string{"msh/pvt/2/e/#"}},
		},
		Channels: []config.Channel{
			{Name: "pvt", PSK: psk},
			{Name: "elevenchars", PSK: psk},
		},
	}

	reportConfig(cfg, log)
	out := buf.String()

	for _, want := range []string{
		"alpha",         // the board is named, not just counted
		"msh/pvt/2/e/#", // and so is the ACL that decides what it may publish
		"name=pvt",      // every channel by name
		"name=elevenchars",
		"name_len=11", // the length, since 11 is the cap and --ch-add refuses >10
	} {
		if !strings.Contains(out, want) {
			t.Errorf("-check-config output does not mention %q:\n%s", want, out)
		}
	}
	// The PSK is resolved by then; printing it would put key material in an
	// operator's terminal and scrollback.
	if strings.Contains(out, "0102030405") || strings.Contains(out, base64.StdEncoding.EncodeToString(psk[:])) {
		t.Errorf("-check-config printed channel key material:\n%s", out)
	}
}
