package config

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPSKB64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" // 32 bytes of 0x01, valid test-only value

func writeSampleConfig(t *testing.T, dir string, mutate func(m map[string]any)) string {
	t.Helper()

	cfg := map[string]any{
		"listener": map[string]any{
			"mqtt_addr":        ":8883",
			"tls_cert_domains": []string{"broker.example.com"},
			"tls_dns_provider": "cloudflare",
			"tls_cache_dir":    filepath.Join(dir, "tls-cache"),
		},
		"boards": []any{
			map[string]any{
				"id":                "alpha",
				"username":          "alpha",
				"password_hash_env": "TEST_ALPHA_HASH",
				"acl_filters":       []string{"msh/pvt/2/e/#"},
			},
		},
		"channels": []any{
			map[string]any{
				"name":    "pvt",
				"psk_env": "TEST_PVT_PSK",
			},
		},
		"monitoring": map[string]any{
			"api_token_env": "TEST_API_TOKEN",
		},
		"storage": map[string]any{
			"path": filepath.Join(dir, "brokerd.db"),
		},
	}
	if mutate != nil {
		mutate(cfg)
	}

	path := filepath.Join(dir, "config.json")
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func setTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TEST_ALPHA_HASH", "$2a$12$abcdefghijklmnopqrstuv")
	t.Setenv("TEST_PVT_PSK", testPSKB64)
	t.Setenv("TEST_API_TOKEN", "api-token-value")
}

func TestLoad_Valid(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	path := writeSampleConfig(t, dir, nil)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Boards) != 1 || cfg.Boards[0].ID != "alpha" {
		t.Fatalf("Boards = %+v", cfg.Boards)
	}
	if cfg.Boards[0].PasswordHash != "$2a$12$abcdefghijklmnopqrstuv" {
		t.Errorf("PasswordHash not resolved from env: %q", cfg.Boards[0].PasswordHash)
	}
	if len(cfg.Channels) != 1 || cfg.Channels[0].Name != "pvt" {
		t.Fatalf("Channels = %+v", cfg.Channels)
	}
	wantPSK, _ := base64.StdEncoding.DecodeString(testPSKB64)
	if string(cfg.Channels[0].PSK[:]) != string(wantPSK) {
		t.Errorf("PSK not decoded correctly")
	}
	if cfg.Auth.BCryptCost != defaultBCryptCost {
		t.Errorf("Auth.BCryptCost = %d, want default %d", cfg.Auth.BCryptCost, defaultBCryptCost)
	}
	if cfg.Monitoring.ListenAddr != defaultMonitoringAddr {
		t.Errorf("Monitoring.ListenAddr = %q, want default %q", cfg.Monitoring.ListenAddr, defaultMonitoringAddr)
	}
}

func TestLoad_MissingEnvVar(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	_ = os.Unsetenv("TEST_PVT_PSK")
	path := writeSampleConfig(t, dir, nil)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load: want error for unset env var, got nil")
	}
	if !strings.Contains(err.Error(), "TEST_PVT_PSK") {
		t.Errorf("error %q does not mention the missing env var", err)
	}
	// The value is usually sitting in .env, visibly present, while the process
	// does not have it: brokerd never parses that file. Reporting only "unset"
	// there reads as a config or deployment fault, and cost a real debugging
	// detour on a hand-run -check-config.
	if !strings.Contains(err.Error(), ".env") {
		t.Errorf("error %q does not say that .env is not read and has to be sourced", err)
	}
}

func TestLoad_BadPSKLength(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	t.Setenv("TEST_PVT_PSK", base64.StdEncoding.EncodeToString([]byte("too-short")))
	path := writeSampleConfig(t, dir, nil)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load: want error for wrong PSK length, got nil")
	}
}

func TestLoad_RejectsWildcardACL(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	path := writeSampleConfig(t, dir, func(m map[string]any) {
		boards := m["boards"].([]any)
		boards[0].(map[string]any)["acl_filters"] = []string{"#"}
	})

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load: want error for wildcard ACL filter, got nil")
	}
}

func TestLoad_DuplicateBoardID(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	t.Setenv("TEST_ALPHA_HASH_2", "$2a$12$abcdefghijklmnopqrstuv")
	path := writeSampleConfig(t, dir, func(m map[string]any) {
		boards := m["boards"].([]any)
		dup := map[string]any{
			"id":                "alpha",
			"username":          "bravo",
			"password_hash_env": "TEST_ALPHA_HASH_2",
			"acl_filters":       []string{"msh/pvt/2/e/#"},
		}
		m["boards"] = append(boards, dup)
	})

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load: want error for duplicate boards[].id, got nil")
	}
}

func TestLoad_MissingTLSDNSProvider(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	path := writeSampleConfig(t, dir, func(m map[string]any) {
		m["listener"].(map[string]any)["tls_dns_provider"] = ""
	})

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load: want error for missing listener.tls_dns_provider, got nil")
	}
}

func TestLoad_MissingTLSCacheDir(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)
	path := writeSampleConfig(t, dir, func(m map[string]any) {
		m["listener"].(map[string]any)["tls_cache_dir"] = ""
	})

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load: want error for missing listener.tls_cache_dir, got nil")
	}
}

func TestParseNodeIDHex(t *testing.T) {
	v, err := parseNodeIDHex("!11223344")
	if err != nil {
		t.Fatalf("parseNodeIDHex: %v", err)
	}
	if v != 0x11223344 {
		t.Errorf("parseNodeIDHex(\"!11223344\") = %#x, want 0x11223344", v)
	}
}

// Retention defaults to a bounded window rather than keeping everything
// forever. An unbounded default grows the database without limit and keeps
// message content and metadata indefinitely, which is the wrong default for
// a privacy-first deployment (docs/security.md) as well as an operational
// hazard (docs/storage-schema.md §6, ADR-7).
func TestLoad_RetentionDefaultsTo30Days(t *testing.T) {
	dir := t.TempDir()
	path := writeSampleConfig(t, dir, func(m map[string]any) {
		delete(m, "retention")
	})
	setTestEnv(t)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Retention.RawFramesDays != 30 {
		t.Errorf("raw_frames_days = %d, want 30 when unset", cfg.Retention.RawFramesDays)
	}
	if cfg.Retention.DecodedDays != 30 {
		t.Errorf("decoded_days = %d, want 30 when unset", cfg.Retention.DecodedDays)
	}
}

// An explicit 0 must still mean "keep forever". Defaulting is for the
// unset case only: an operator who wrote 0 chose unlimited, and silently
// turning that into deletion would destroy data they asked to keep.
func TestLoad_RetentionExplicitZeroMeansUnlimited(t *testing.T) {
	dir := t.TempDir()
	path := writeSampleConfig(t, dir, func(m map[string]any) {
		m["retention"] = map[string]any{"raw_frames_days": 0, "decoded_days": 0}
	})
	setTestEnv(t)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Retention.RawFramesDays != 0 {
		t.Errorf("raw_frames_days = %d, want 0 (unlimited) when explicitly 0", cfg.Retention.RawFramesDays)
	}
	if cfg.Retention.DecodedDays != 0 {
		t.Errorf("decoded_days = %d, want 0 (unlimited) when explicitly 0", cfg.Retention.DecodedDays)
	}
}

func TestLoad_RetentionExplicitValueIsKept(t *testing.T) {
	dir := t.TempDir()
	path := writeSampleConfig(t, dir, func(m map[string]any) {
		m["retention"] = map[string]any{"raw_frames_days": 7, "decoded_days": 90}
	})
	setTestEnv(t)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Retention.RawFramesDays != 7 || cfg.Retention.DecodedDays != 90 {
		t.Errorf("retention = %d/%d, want 7/90", cfg.Retention.RawFramesDays, cfg.Retention.DecodedDays)
	}
}

// A negative value is a typo, not a policy. Left unchecked it behaves like
// unlimited (internal/storage's deletion only runs for days > 0), so the
// operator gets the opposite of the bounded window they were trying to
// write.
func TestLoad_RetentionRejectsNegative(t *testing.T) {
	for _, key := range []string{"raw_frames_days", "decoded_days"} {
		dir := t.TempDir()
		path := writeSampleConfig(t, dir, func(m map[string]any) {
			m["retention"] = map[string]any{key: -1}
		})
		setTestEnv(t)

		if _, err := Load(path); err == nil {
			t.Errorf("Load with %s = -1 succeeded, want an error", key)
		} else if !strings.Contains(err.Error(), key) {
			t.Errorf("error for %s = -1 does not name the key: %v", key, err)
		}
	}
}

// The keepalive floor is off unless configured, so adding the key cannot
// change an existing deployment's behaviour by accident.
func TestLoad_KeepaliveFloorDefaultsToOff(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)

	cfg, err := Load(writeSampleConfig(t, dir, nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listener.KeepaliveFloorSeconds != 0 {
		t.Errorf("KeepaliveFloorSeconds = %d, want 0 (measure-only) when unset", cfg.Listener.KeepaliveFloorSeconds)
	}
}

func TestLoad_KeepaliveFloorExplicit(t *testing.T) {
	dir := t.TempDir()
	setTestEnv(t)

	path := writeSampleConfig(t, dir, func(m map[string]any) {
		m["listener"].(map[string]any)["keepalive_floor_seconds"] = 60
	})
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listener.KeepaliveFloorSeconds != 60 {
		t.Errorf("KeepaliveFloorSeconds = %d, want 60", cfg.Listener.KeepaliveFloorSeconds)
	}
}

// A value that cannot fit MQTT's 16-bit keepalive field is a configuration
// error, not something to silently truncate: 65536 would wrap to 0 and
// disable the deadline entirely, which is the opposite of what someone
// asking for a very long floor wants.
func TestLoad_KeepaliveFloorRejectsOutOfRange(t *testing.T) {
	for _, v := range []int{-1, 65536, 100000} {
		dir := t.TempDir()
		setTestEnv(t)
		path := writeSampleConfig(t, dir, func(m map[string]any) {
			m["listener"].(map[string]any)["keepalive_floor_seconds"] = v
		})
		if _, err := Load(path); err == nil {
			t.Errorf("Load accepted keepalive_floor_seconds = %d, want an error", v)
		}
	}
}

// TestLoad_RejectsAnUnknownKey covers a silent failure that a config file
// cannot recover from on its own: json.Unmarshal ignores a key the schema does
// not define, so `min_intervl_seconds` left the rate limit unset while the
// operator believed it was applied. A config file is a claim about how the
// process behaves, and a typo in it must not be answered with silence.
func TestLoad_RejectsAnUnknownKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	raw := `{
	  "listener": {"mqtt_addr": ":8883", "tls_cert_domains": ["mqtt.example.com"],
	               "tls_dns_provider": "cloudflare", "tls_cache_dir": "` + dir + `/tls"},
	  "boards": [], "channels": [],
	  "storage": {"path": "` + dir + `/brokerd.db"},
	  "monitoring": {"listen_addr": "127.0.0.1:9101", "api_token_env": "TEST_TOKEN"},
	  "auth": {"bcrypt_cost": 12, "failure_threshold": 5, "ban_duration_minutes": 30},
	  "retention": {"raw_frames_days": 30, "decoded_days": 90},
	  "storage_typo_key": 1
	}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	t.Setenv("TEST_TOKEN", "x")

	_, err := Load(path)
	if err == nil {
		t.Fatal("a config with an undefined key loaded successfully")
	}
	if !strings.Contains(err.Error(), "storage_typo_key") {
		t.Errorf("the error does not name the offending key: %v", err)
	}
}
