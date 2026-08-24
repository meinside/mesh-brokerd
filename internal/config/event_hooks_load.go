package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHookQueueSize     = 256
	defaultHookMaxConcurrent = 2
	defaultHookTimeout       = 10 * time.Second
	defaultWebhookRetries    = 2
	defaultDisableAfter      = 10
)

func loadEventHooks(raw rawConfig, boards []Board) (EventHooks, error) {
	out := EventHooks{
		Enabled:       raw.EventHooks.Enabled,
		QueueSize:     raw.EventHooks.QueueSize,
		MaxConcurrent: raw.EventHooks.MaxConcurrent,
	}

	// Absent means suppressed, for the same reason as the outbound relay's
	// dry_run_all_rules: a plain bool cannot tell "not configured" from
	// "configured to fire", and getting that backwards means executing a
	// program or POSTing message text nobody asked for.
	out.DryRun = true
	if v := raw.EventHooks.DryRun; v != nil {
		out.DryRun = *v
	}

	if out.QueueSize <= 0 {
		out.QueueSize = defaultHookQueueSize
	}
	if out.MaxConcurrent <= 0 {
		out.MaxConcurrent = defaultHookMaxConcurrent
	}

	boardIDs := make(map[string]struct{}, len(boards))
	for _, b := range boards {
		boardIDs[b.ID] = struct{}{}
	}

	seen := make(map[string]struct{}, len(raw.EventHooks.Targets))
	for i, rt := range raw.EventHooks.Targets {
		where := fmt.Sprintf("event_hooks.targets[%d]", i)
		if rt.Name == "" {
			return out, fmt.Errorf("config: %s.name must not be empty", where)
		}
		where = fmt.Sprintf("event_hooks.targets[%q]", rt.Name)
		if _, dup := seen[rt.Name]; dup {
			return out, fmt.Errorf("config: %s: duplicate target name", where)
		}
		seen[rt.Name] = struct{}{}

		t := HookTarget{
			Name:      rt.Name,
			Kind:      HookKind(rt.Kind),
			Enabled:   rt.Enabled,
			Args:      rt.Args,
			Template:  rt.Template,
			Timeout:   defaultHookTimeout,
			QuietFrom: -1,
			QuietTo:   -1,
			Match: HookMatch{
				Events:            rt.Match.Events,
				Portnums:          rt.Match.Portnums,
				Channels:          rt.Match.Channels,
				Boards:            rt.Match.Boards,
				IncludeText:       rt.Match.IncludeText,
				IncludeRawPayload: rt.Match.IncludeRawPayload,
				ExcludeOwnBoards:  rt.Match.ExcludeOwnBoards,
			},
		}

		if rt.TimeoutSeconds > 0 {
			t.Timeout = time.Duration(rt.TimeoutSeconds) * time.Second
		}
		t.MinInterval = time.Duration(rt.MinIntervalSeconds) * time.Second
		t.DedupeWindow = time.Duration(rt.DedupeWindowSeconds) * time.Second

		t.DisableAfterFailures = defaultDisableAfter
		if rt.DisableAfterFailures != nil {
			if *rt.DisableAfterFailures < 0 {
				return out, fmt.Errorf("config: %s.disable_after_failures must not be negative", where)
			}
			t.DisableAfterFailures = *rt.DisableAfterFailures
		}

		// Events default to frame-only. A target written to notify about
		// messages must not silently begin receiving connection events
		// because a later version added them.
		if len(t.Match.Events) == 0 {
			t.Match.Events = []string{HookEventFrame}
		}
		for _, e := range t.Match.Events {
			if !knownHookEvent(e) {
				return out, fmt.Errorf("config: %s.match.events: unknown event %q (known: %s)",
					where, e, strings.Join(HookEventNames, ", "))
			}
		}
		for _, b := range t.Match.Boards {
			if _, ok := boardIDs[b]; !ok {
				return out, fmt.Errorf("config: %s.match.boards: %q is not a configured board id", where, b)
			}
		}

		if rt.QuietHours != "" {
			from, to, err := parseQuietHours(rt.QuietHours)
			if err != nil {
				return out, fmt.Errorf("config: %s.quiet_hours: %w", where, err)
			}
			t.QuietFrom, t.QuietTo = from, to
		}

		switch t.Kind {
		case HookKindWebhook:
			if rt.Command != "" || len(rt.Args) > 0 {
				return out, fmt.Errorf("config: %s: kind webhook must not set command/args", where)
			}
			if !rt.Enabled {
				// Same reasoning as the command check below: a disabled
				// target's secrets need not exist in the environment yet.
				// Its shape was already validated above.
				out.Targets = append(out.Targets, t)
				continue
			}
			u, err := requireEnv(rt.URLEnv, where+".url_env")
			if err != nil {
				return out, err
			}
			parsed, err := url.Parse(u)
			if err != nil {
				return out, fmt.Errorf("config: %s.url_env (%s): not a URL: %w", where, rt.URLEnv, err)
			}
			// Checked at load, not at first delivery: a typo should fail at
			// boot, not at 3am when the event it was meant to report happens.
			if parsed.Scheme != "https" && !isLoopbackURL(parsed) {
				return out, fmt.Errorf("config: %s.url_env (%s): scheme %q is not allowed; use https, or http only for a loopback address",
					where, rt.URLEnv, parsed.Scheme)
			}
			t.URL = u
			t.AllowUnsigned = rt.AllowUnsigned
			if rt.SecretEnv != "" {
				secret, err := requireEnv(rt.SecretEnv, where+".secret_env")
				if err != nil {
					return out, err
				}
				t.Secret = secret
			} else if !isLoopbackURL(parsed) && !rt.AllowUnsigned {
				return out, fmt.Errorf("config: %s: a non-loopback webhook needs either secret_env, so the receiver can verify the signature, or allow_unsigned: true for a receiver that authenticates by URL and has no shared secret (docs/event-hooks.md)", where)
			}
			headers, err := resolveHookHeaders(rt.Headers, where)
			if err != nil {
				return out, err
			}
			t.Headers = headers
			t.Retries = defaultWebhookRetries
			if rt.Retries != nil {
				if *rt.Retries < 0 {
					return out, fmt.Errorf("config: %s.retries must not be negative", where)
				}
				t.Retries = *rt.Retries
			}

		case HookKindCommand:
			if rt.URLEnv != "" || rt.SecretEnv != "" {
				return out, fmt.Errorf("config: %s: kind command must not set url_env/secret_env", where)
			}
			if rt.Retries != nil && *rt.Retries != 0 {
				return out, fmt.Errorf("config: %s.retries must be 0 for a command target: re-running a program that may already have had an effect is worse than reporting the failure", where)
			}
			// The shape is checked always, but the file is only stat'd for
			// an enabled target: a shipped sample names a path that does not
			// exist on the machine reading it, and refusing to start over a
			// hook nobody armed would be the wrong trade. Flipping enabled
			// to true moves the check to that startup, which is when it
			// matters.
			if err := validateHookCommand(rt.Command, where, rt.Enabled); err != nil {
				return out, err
			}
			t.Command = rt.Command
			t.Retries = 0

		case "":
			return out, fmt.Errorf("config: %s.kind is required (%q or %q)", where, HookKindWebhook, HookKindCommand)
		default:
			return out, fmt.Errorf("config: %s.kind %q is not supported (%q or %q)", where, rt.Kind, HookKindWebhook, HookKindCommand)
		}

		out.Targets = append(out.Targets, t)
	}

	return out, nil
}

func knownHookEvent(name string) bool {
	for _, e := range HookEventNames {
		if e == name {
			return true
		}
	}
	return false
}

func isLoopbackURL(u *url.URL) bool {
	host := u.Hostname()
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// validateHookCommand refuses rather than reports. Permission problems
// elsewhere in brokerd are warned about and left alone, because the
// operator may have widened a mode deliberately (docs/security.md §4) --
// but this is a program brokerd will execute with its own privileges, and
// a file some other account can rewrite is not something to note in a log
// and then run anyway.
func validateHookCommand(path, where string, enabled bool) error {
	if path == "" {
		return fmt.Errorf("config: %s.command is required for kind command", where)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("config: %s.command %q must be an absolute path: resolving it through PATH would make what runs depend on the environment brokerd happens to inherit", where, path)
	}
	if !enabled {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("config: %s.command %q: %w", where, path, err)
	}
	if info.IsDir() || !info.Mode().IsRegular() {
		return fmt.Errorf("config: %s.command %q is not a regular file", where, path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("config: %s.command %q is not executable (mode %04o)", where, path, info.Mode().Perm())
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("config: %s.command %q is writable by group or other (mode %04o): anyone who can write it decides what brokerd executes", where, path, info.Mode().Perm())
	}
	return nil
}

// parseQuietHours parses "23:00-07:00" into minutes since local midnight.
// A window may wrap midnight, which is the usual case for sleep.
func parseQuietHours(s string) (from, to int, err error) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected HH:MM-HH:MM, got %q", s)
	}
	from, err = parseHHMM(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, err
	}
	to, err = parseHHMM(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, err
	}
	if from == to {
		return 0, 0, fmt.Errorf("start and end are identical (%q), which would mean either always or never", s)
	}
	return from, to, nil
}

func parseHHMM(s string) (int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("expected HH:MM, got %q", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("hour out of range in %q", s)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("minute out of range in %q", s)
	}
	return h*60 + m, nil
}

// resolveHookHeaders copies the configured headers, resolving a ${VAR} value
// from the environment. That indirection exists so a header carrying a
// credential -- some receivers want `Authorization` rather than a signature --
// still keeps the secret out of config.json, the same rule every other secret
// in this file follows.
func resolveHookHeaders(in map[string]string, where string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(in))
	for name, value := range in {
		if name == "" {
			return nil, fmt.Errorf("config: %s.headers: empty header name", where)
		}
		if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
			envName := strings.TrimSuffix(strings.TrimPrefix(value, "${"), "}")
			resolved, err := requireEnv(envName, fmt.Sprintf("%s.headers[%q]", where, name))
			if err != nil {
				return nil, err
			}
			value = resolved
		}
		out[name] = value
	}
	return out, nil
}
