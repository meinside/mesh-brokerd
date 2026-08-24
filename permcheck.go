package main

import (
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/meinside/mesh-brokerd/internal/config"
)

// warnLoosePermissions reports files and directories readable beyond their
// owner, and changes nothing.
//
// It reports rather than fixes on purpose. A mode may have been widened
// deliberately — a backup agent that reads the database, a group that tails
// the logs — and silently overriding an operator's decision at every start is
// worse than telling them once. It also means this can run before anything
// else touches the filesystem without any risk of its own.
//
// What is at stake differs per path, which is why they are listed rather than
// globbed: `storage.path` and its SQLite sidecars hold **decrypted message
// bodies** (`text_messages`, docs/storage-schema.md), and
// `listener.tls_cache_dir` holds the **TLS private key** and the ACME account
// key. config.json holds no secrets by design (docs/security.md §7) but does
// describe the deployment.
//
// This deployment shipped with the database at 0644 for a while, protected
// only by the parent directory's mode — which is exactly the kind of thing
// that survives a backup, a copy, or a move and is noticed by nobody.
func warnLoosePermissions(cfg *config.Config, configPath string, log *slog.Logger) {
	type target struct {
		path string
		want fs.FileMode
		why  string
	}

	var targets []target

	if p := cfg.Storage.Path; p != "" {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			targets = append(targets, target{p + suffix, 0o600, "holds decrypted message content"})
		}
	}
	if configPath != "" {
		targets = append(targets, target{configPath, 0o600, "describes the deployment"})
	}
	if d := cfg.Listener.TLSCacheDir; d != "" {
		targets = append(targets, target{d, 0o700, "holds the TLS private key"})
		// The key files themselves, whatever the ACME client named them.
		if entries, err := os.ReadDir(d); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				targets = append(targets, target{filepath.Join(d, e.Name()), 0o600, "TLS/ACME key material"})
			}
		}
	}

	for _, t := range targets {
		fi, err := os.Stat(t.path)
		if err != nil {
			// Missing is normal: the database does not exist before the first
			// run, and the TLS cache not before the first certificate.
			continue
		}
		got := fi.Mode().Perm()
		// Only group/other bits matter here; owner bits are the process's own
		// business.
		if got&0o077 == 0 {
			continue
		}
		log.Warn("file permissions are looser than recommended",
			"path", t.path,
			"mode", fs.FileMode(got).String(),
			"recommended", fs.FileMode(t.want).String(),
			"recommended_octal", "0"+octal(t.want),
			"why", t.why,
			"note", "not changed automatically; run chmod yourself if this is unintended",
		)
	}
}

// octal renders a permission bitmask the way chmod takes it.
func octal(m fs.FileMode) string {
	const digits = "01234567"
	p := m.Perm()
	return string([]byte{digits[(p>>6)&7], digits[(p>>3)&7], digits[p&7]})
}
