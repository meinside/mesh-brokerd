package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeHookScript(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hook.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), mode); err != nil {
		t.Fatalf("writing script: %v", err)
	}
	// WriteFile is subject to umask, so set the mode explicitly.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return path
}

func hookRaw(target func(*rawConfig)) rawConfig {
	var raw rawConfig
	raw.EventHooks.Enabled = true
	dryRun := false
	raw.EventHooks.DryRun = &dryRun
	target(&raw)
	return raw
}

// TestLoadEventHooks_CommandMustNotBeWritableByOthers is the one place
// brokerd refuses instead of reporting: a file another account can rewrite
// decides what brokerd executes, which is not something to note in a log
// and run anyway (docs/security.md §4).
func TestLoadEventHooks_CommandMustNotBeWritableByOthers(t *testing.T) {
	for _, mode := range []os.FileMode{0o777, 0o775, 0o722} {
		path := writeHookScript(t, mode)
		raw := hookRaw(func(r *rawConfig) {
			r.EventHooks.Targets = append(r.EventHooks.Targets, hookTargetRaw("c", "command", path))
		})
		_, err := loadEventHooks(raw, nil)
		if err == nil {
			t.Errorf("mode %04o accepted", mode.Perm())
			continue
		}
		if !strings.Contains(err.Error(), "writable by group or other") {
			t.Errorf("mode %04o: error = %v, want it to name the permission problem", mode.Perm(), err)
		}
	}
}

func TestLoadEventHooks_CommandValidation(t *testing.T) {
	good := writeHookScript(t, 0o700)
	notExec := writeHookScript(t, 0o600)

	for _, tc := range []struct {
		name    string
		command string
		wantSub string
	}{
		{"relative path", "hooks/notify.sh", "absolute path"},
		{"missing file", "/nonexistent/hook.sh", "no such file"},
		{"not executable", notExec, "not executable"},
		{"directory", filepath.Dir(good), "not a regular file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := hookRaw(func(r *rawConfig) {
				r.EventHooks.Targets = append(r.EventHooks.Targets, hookTargetRaw("c", "command", tc.command))
			})
			_, err := loadEventHooks(raw, nil)
			if err == nil {
				t.Fatalf("accepted %q", tc.command)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantSub)
			}
		})
	}

	raw := hookRaw(func(r *rawConfig) {
		r.EventHooks.Targets = append(r.EventHooks.Targets, hookTargetRaw("c", "command", good))
	})
	cfg, err := loadEventHooks(raw, nil)
	if err != nil {
		t.Fatalf("valid command target rejected: %v", err)
	}
	if len(cfg.Targets) != 1 || cfg.Targets[0].Command != good {
		t.Fatalf("target not loaded: %+v", cfg.Targets)
	}
	// Retries must stay 0 for a command: re-running a program that may
	// already have had an effect is worse than reporting the failure.
	if cfg.Targets[0].Retries != 0 {
		t.Errorf("command target Retries = %d, want 0", cfg.Targets[0].Retries)
	}
}

func TestLoadEventHooks_CommandRetriesRejected(t *testing.T) {
	good := writeHookScript(t, 0o700)
	two := 2
	raw := hookRaw(func(r *rawConfig) {
		tr := hookTargetRaw("c", "command", good)
		tr.Retries = &two
		r.EventHooks.Targets = append(r.EventHooks.Targets, tr)
	})
	_, err := loadEventHooks(raw, nil)
	if err == nil || !strings.Contains(err.Error(), "must be 0 for a command target") {
		t.Errorf("error = %v, want a rejection explaining why commands are not retried", err)
	}
}

func TestLoadEventHooks_WebhookRequiresHTTPSAndSecret(t *testing.T) {
	t.Setenv("TEST_HOOK_URL_PLAIN", "http://example.com/hook")
	t.Setenv("TEST_HOOK_URL_HTTPS", "https://example.com/hook")
	t.Setenv("TEST_HOOK_URL_LOOPBACK", "http://127.0.0.1:9999/hook")
	t.Setenv("TEST_HOOK_SECRET", "s3cret")

	// Plaintext http to a remote host: refused, because the payload can
	// carry message text.
	raw := hookRaw(func(r *rawConfig) {
		tr := hookTargetRaw("w", "webhook", "")
		tr.URLEnv, tr.SecretEnv = "TEST_HOOK_URL_PLAIN", "TEST_HOOK_SECRET"
		r.EventHooks.Targets = append(r.EventHooks.Targets, tr)
	})
	if _, err := loadEventHooks(raw, nil); err == nil || !strings.Contains(err.Error(), "is not allowed") {
		t.Errorf("plain http accepted or wrong error: %v", err)
	}

	// https without a secret and without an explicit opt-out: refused. The
	// message names both ways out, because a receiver that authenticates by
	// URL has no secret to offer and would otherwise look unsupported.
	raw = hookRaw(func(r *rawConfig) {
		tr := hookTargetRaw("w", "webhook", "")
		tr.URLEnv = "TEST_HOOK_URL_HTTPS"
		r.EventHooks.Targets = append(r.EventHooks.Targets, tr)
	})
	if _, err := loadEventHooks(raw, nil); err == nil || !strings.Contains(err.Error(), "allow_unsigned") {
		t.Errorf("unsigned remote webhook accepted or wrong error: %v", err)
	}

	// The same target with the opt-out stated is accepted. An absent secret
	// alone must never mean "send anyway"; saying so must be deliberate.
	raw = hookRaw(func(r *rawConfig) {
		tr := hookTargetRaw("w", "webhook", "")
		tr.URLEnv = "TEST_HOOK_URL_HTTPS"
		tr.AllowUnsigned = true
		r.EventHooks.Targets = append(r.EventHooks.Targets, tr)
	})
	cfgUnsigned, err := loadEventHooks(raw, nil)
	if err != nil {
		t.Fatalf("allow_unsigned target rejected: %v", err)
	}
	if cfgUnsigned.Targets[0].Secret != "" || !cfgUnsigned.Targets[0].AllowUnsigned {
		t.Errorf("target = %+v, want no secret and AllowUnsigned true", cfgUnsigned.Targets[0])
	}

	// Loopback http without a secret is allowed: nothing leaves the host.
	raw = hookRaw(func(r *rawConfig) {
		tr := hookTargetRaw("w", "webhook", "")
		tr.URLEnv = "TEST_HOOK_URL_LOOPBACK"
		r.EventHooks.Targets = append(r.EventHooks.Targets, tr)
	})
	cfg, err := loadEventHooks(raw, nil)
	if err != nil {
		t.Fatalf("loopback webhook rejected: %v", err)
	}
	if cfg.Targets[0].Retries != defaultWebhookRetries {
		t.Errorf("Retries = %d, want the default %d", cfg.Targets[0].Retries, defaultWebhookRetries)
	}
}

func TestLoadEventHooks_DryRunDefaultsToTrue(t *testing.T) {
	var raw rawConfig
	raw.EventHooks.Enabled = true // no dry_run key at all
	cfg, err := loadEventHooks(raw, nil)
	if err != nil {
		t.Fatalf("loadEventHooks: %v", err)
	}
	if !cfg.DryRun {
		t.Error("absent dry_run resolved to false; absent must mean suppressed")
	}
}

func TestLoadEventHooks_KindAndEventValidation(t *testing.T) {
	good := writeHookScript(t, 0o700)

	raw := hookRaw(func(r *rawConfig) {
		r.EventHooks.Targets = append(r.EventHooks.Targets, hookTargetRaw("x", "carrier-pigeon", ""))
	})
	if _, err := loadEventHooks(raw, nil); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("unknown kind accepted or wrong error: %v", err)
	}

	raw = hookRaw(func(r *rawConfig) {
		tr := hookTargetRaw("c", "command", good)
		tr.Match.Events = []string{"frame", "board_exploded"}
		r.EventHooks.Targets = append(r.EventHooks.Targets, tr)
	})
	if _, err := loadEventHooks(raw, nil); err == nil || !strings.Contains(err.Error(), "unknown event") {
		t.Errorf("unknown event accepted or wrong error: %v", err)
	}

	// Events default to frame-only, so a target cannot start receiving
	// connection events because a later version added them.
	raw = hookRaw(func(r *rawConfig) {
		r.EventHooks.Targets = append(r.EventHooks.Targets, hookTargetRaw("c", "command", good))
	})
	cfg, err := loadEventHooks(raw, nil)
	if err != nil {
		t.Fatalf("loadEventHooks: %v", err)
	}
	if len(cfg.Targets[0].Match.Events) != 1 || cfg.Targets[0].Match.Events[0] != HookEventFrame {
		t.Errorf("default events = %v, want [%s]", cfg.Targets[0].Match.Events, HookEventFrame)
	}
}

func TestLoadEventHooks_MatchBoardsMustExist(t *testing.T) {
	good := writeHookScript(t, 0o700)
	raw := hookRaw(func(r *rawConfig) {
		tr := hookTargetRaw("c", "command", good)
		tr.Match.Boards = []string{"nonexistent"}
		r.EventHooks.Targets = append(r.EventHooks.Targets, tr)
	})
	_, err := loadEventHooks(raw, []Board{{ID: "alpha"}})
	if err == nil || !strings.Contains(err.Error(), "not a configured board id") {
		t.Errorf("error = %v, want a rejection naming the unknown board", err)
	}
}

func TestLoadEventHooks_DuplicateNames(t *testing.T) {
	good := writeHookScript(t, 0o700)
	raw := hookRaw(func(r *rawConfig) {
		r.EventHooks.Targets = append(r.EventHooks.Targets,
			hookTargetRaw("same", "command", good), hookTargetRaw("same", "command", good))
	})
	if _, err := loadEventHooks(raw, nil); err == nil || !strings.Contains(err.Error(), "duplicate target name") {
		t.Errorf("error = %v, want a duplicate-name rejection", err)
	}
}

func TestParseQuietHours(t *testing.T) {
	for _, tc := range []struct {
		in       string
		from, to int
		wantErr  bool
	}{
		{in: "23:00-07:00", from: 1380, to: 420},
		{in: "00:30-01:00", from: 30, to: 60},
		{in: "7:5-8:9", from: 425, to: 489},
		{in: "23:00", wantErr: true},
		{in: "24:00-01:00", wantErr: true},
		{in: "22:60-23:00", wantErr: true},
		{in: "12:00-12:00", wantErr: true}, // always or never; refuse to guess
		{in: "abc-def", wantErr: true},
	} {
		from, to, err := parseQuietHours(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseQuietHours(%q) accepted", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseQuietHours(%q): %v", tc.in, err)
			continue
		}
		if from != tc.from || to != tc.to {
			t.Errorf("parseQuietHours(%q) = %d,%d, want %d,%d", tc.in, from, to, tc.from, tc.to)
		}
	}
}

// hookTargetRaw builds a minimal raw target for the loader's tests.
func hookTargetRaw(name, kind, command string) rawHookTarget {
	return rawHookTarget{Name: name, Kind: kind, Enabled: true, Command: command}
}

// TestLoadEventHooks_DisabledTargetIsShapeCheckedButNotStatted is the rule
// that makes a shipped sample possible: a disabled target's path and
// secrets need not exist on the machine reading the config, but a
// structurally wrong target still fails to load.
func TestLoadEventHooks_DisabledTargetIsShapeCheckedButNotStatted(t *testing.T) {
	raw := hookRaw(func(r *rawConfig) {
		tr := hookTargetRaw("c", "command", "/nonexistent/hook.sh")
		tr.Enabled = false
		r.EventHooks.Targets = append(r.EventHooks.Targets, tr)
	})
	if _, err := loadEventHooks(raw, nil); err != nil {
		t.Errorf("disabled target with a missing file rejected: %v", err)
	}

	// Still refused: a relative path is wrong whether or not it is enabled.
	raw = hookRaw(func(r *rawConfig) {
		tr := hookTargetRaw("c", "command", "hooks/notify.sh")
		tr.Enabled = false
		r.EventHooks.Targets = append(r.EventHooks.Targets, tr)
	})
	if _, err := loadEventHooks(raw, nil); err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Errorf("error = %v, want the relative path to be refused even while disabled", err)
	}

	// And an unknown kind is refused regardless.
	raw = hookRaw(func(r *rawConfig) {
		tr := hookTargetRaw("x", "smoke-signal", "")
		tr.Enabled = false
		r.EventHooks.Targets = append(r.EventHooks.Targets, tr)
	})
	if _, err := loadEventHooks(raw, nil); err == nil {
		t.Error("disabled target with an unknown kind accepted")
	}
}

// TestLoadEventHooks_EnabledTargetIsStatted is the other half: turning a
// target on moves the filesystem check to that startup.
func TestLoadEventHooks_EnabledTargetIsStatted(t *testing.T) {
	raw := hookRaw(func(r *rawConfig) {
		tr := hookTargetRaw("c", "command", "/nonexistent/hook.sh")
		tr.Enabled = true
		r.EventHooks.Targets = append(r.EventHooks.Targets, tr)
	})
	if _, err := loadEventHooks(raw, nil); err == nil {
		t.Error("enabled target with a missing command accepted")
	}
}

// TestLoadEventHooks_HeaderEnvIndirection keeps the project's one rule about
// secrets: a header may need to carry a credential, and config.json is not
// where a credential goes.
func TestLoadEventHooks_HeaderEnvIndirection(t *testing.T) {
	t.Setenv("TEST_HOOK_URL_HTTPS", "https://example.com/hook")
	t.Setenv("TEST_HOOK_HEADER_TOKEN", "s3cret-header-value")

	raw := hookRaw(func(r *rawConfig) {
		tr := hookTargetRaw("w", "webhook", "")
		tr.URLEnv = "TEST_HOOK_URL_HTTPS"
		tr.AllowUnsigned = true
		tr.Headers = map[string]string{
			"Accept":        "application/vnd.example-chat-v2+json",
			"Authorization": "${TEST_HOOK_HEADER_TOKEN}",
		}
		r.EventHooks.Targets = append(r.EventHooks.Targets, tr)
	})
	cfg, err := loadEventHooks(raw, nil)
	if err != nil {
		t.Fatalf("loadEventHooks: %v", err)
	}
	h := cfg.Targets[0].Headers
	if h["Accept"] != "application/vnd.example-chat-v2+json" {
		t.Errorf("plain header value altered: %q", h["Accept"])
	}
	if h["Authorization"] != "s3cret-header-value" {
		t.Errorf("${VAR} header not resolved from the environment: %q", h["Authorization"])
	}

	// An unset variable fails at load, like every other *_env in this file.
	raw = hookRaw(func(r *rawConfig) {
		tr := hookTargetRaw("w", "webhook", "")
		tr.URLEnv = "TEST_HOOK_URL_HTTPS"
		tr.AllowUnsigned = true
		tr.Headers = map[string]string{"Authorization": "${TEST_HOOK_MISSING_VAR}"}
		r.EventHooks.Targets = append(r.EventHooks.Targets, tr)
	})
	if _, err := loadEventHooks(raw, nil); err == nil {
		t.Error("a header referencing an unset environment variable was accepted")
	}
}
