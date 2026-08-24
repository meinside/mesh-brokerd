package hook

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"syscall"

	"github.com/meinside/mesh-brokerd/internal/config"
)

// CommandSink executes a local program, with the payload on stdin.
//
// Three properties of this sink are deliberate and must not be relaxed:
//
//  1. **No shell.** The program is executed directly with its argv; there
//     is no `sh -c`, so nothing in an event can be interpreted as syntax.
//  2. **The payload goes to stdin, never into an argument.** A message
//     body in a command line would end up in `ps` output and in audit
//     logs, and would invite quoting bugs in every hook script ever
//     written against this.
//  3. **The child gets a minimal environment, never brokerd's.**
//     brokerd's own environment holds channel PSKs, the monitoring token
//     and the DNS provider's API token (docs/security.md §7). A child
//     inheriting os.Environ() would hand all of that to a hook script.
type CommandSink struct {
	// Env is the exact environment handed to the child.
	Env []string

	// Log receives whatever the child writes to stdout. Without this a hook
	// script has nowhere to report to: it cannot rely on reaching journald
	// itself, because the systemd sandbox mounts the filesystem read-only
	// apart from the data directory, and it should not have to write a file
	// just to say one line. `echo` is enough.
	Log *slog.Logger
}

// NewCommandSink builds a sink with the minimal environment.
func NewCommandSink() *CommandSink {
	return &CommandSink{Env: MinimalEnv()}
}

// MinimalEnv is the child environment: a conservative PATH and nothing
// else. Not empty, because a script with a `#!/bin/sh` shebang and a bare
// `logger` call is the normal case and should work.
func MinimalEnv() []string {
	return []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"BROKERD_HOOK=1",
	}
}

func (s *CommandSink) Deliver(ctx context.Context, t config.HookTarget, body []byte) error {
	cmd := exec.CommandContext(ctx, t.Command, t.Args...)
	cmd.Env = s.Env
	cmd.Stdin = bytes.NewReader(body)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Own process group, so a timeout kills the whole tree rather than
	// leaving a stalled grandchild holding a worker slot forever.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	err := cmd.Run()

	// Whatever the child printed is reported either way, truncated so a hook
	// script cannot flood the journal.
	if out := truncate(stdout.String(), 512); out != "" {
		s.logger().Info("hook: command output", "target", t.Name, "output", out)
	}

	if err != nil {
		// The program's own diagnostics are worth more than the exit code
		// alone.
		return fmt.Errorf("%w (stderr: %s)", err, truncate(stderr.String(), 512))
	}
	return nil
}

func (s *CommandSink) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *CommandSink) Describe(t config.HookTarget) string {
	if len(t.Args) == 0 {
		return "exec " + t.Command + " (payload on stdin)"
	}
	return fmt.Sprintf("exec %s %s (payload on stdin)", t.Command, strings.Join(t.Args, " "))
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
