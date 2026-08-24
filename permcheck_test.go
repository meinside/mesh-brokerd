package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meinside/mesh-brokerd/internal/config"
)

// permWarnFixture builds a config pointing at real files so the check has
// something to stat, and returns the captured log output after running it.
func permWarnFixture(t *testing.T, dbMode, cfgMode, cacheDirMode, keyMode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()

	dbPath := filepath.Join(dir, "brokerd.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dbPath, dbMode); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfgPath, cfgMode); err != nil {
		t.Fatal(err)
	}

	cacheDir := filepath.Join(dir, "tls-cache")
	if err := os.Mkdir(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(cacheDir, "cert.key")
	if err := os.WriteFile(keyPath, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, keyMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cacheDir, cacheDirMode); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	warnLoosePermissions(&config.Config{
		Listener: config.Listener{TLSCacheDir: cacheDir},
		Storage:  config.Storage{Path: dbPath},
	}, cfgPath, slog.New(slog.NewTextHandler(&buf, nil)))
	return buf.String()
}

// Correct permissions must produce no output at all.
//
// A check that warns during normal operation gets ignored, and then it is
// worth nothing on the day it matters.
func TestWarnLoosePermissions_SilentWhenCorrect(t *testing.T) {
	out := permWarnFixture(t, 0o600, 0o600, 0o700, 0o600)
	if out != "" {
		t.Errorf("a correctly-permissioned deployment produced warnings:\n%s", out)
	}
}

// The database holds decrypted message bodies (text_messages), so anything
// readable beyond the owner is worth saying out loud.
func TestWarnLoosePermissions_DatabaseReadableByOthers(t *testing.T) {
	out := permWarnFixture(t, 0o644, 0o600, 0o700, 0o600)
	if !strings.Contains(out, "brokerd.db") {
		t.Errorf("no warning for a world-readable database:\n%s", out)
	}
	if !strings.Contains(out, "0600") {
		t.Errorf("warning does not state the recommended mode:\n%s", out)
	}
}

// The TLS private key is the most serious of the lot.
func TestWarnLoosePermissions_TLSKeyReadableByGroup(t *testing.T) {
	out := permWarnFixture(t, 0o600, 0o600, 0o700, 0o640)
	if !strings.Contains(out, "cert.key") {
		t.Errorf("no warning for a group-readable TLS key:\n%s", out)
	}
}

func TestWarnLoosePermissions_CacheDirTraversable(t *testing.T) {
	out := permWarnFixture(t, 0o600, 0o600, 0o755, 0o600)
	if !strings.Contains(out, "tls-cache") {
		t.Errorf("no warning for a world-traversable TLS cache directory:\n%s", out)
	}
}

func TestWarnLoosePermissions_ConfigReadableByOthers(t *testing.T) {
	out := permWarnFixture(t, 0o600, 0o644, 0o700, 0o600)
	if !strings.Contains(out, "config.json") {
		t.Errorf("no warning for a world-readable config:\n%s", out)
	}
}

// It warns; it must never change anything. An operator may have deliberately
// widened a mode (a backup agent reading the database, say), and silently
// overriding that is worse than the warning.
func TestWarnLoosePermissions_DoesNotModify(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "brokerd.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	warnLoosePermissions(&config.Config{Storage: config.Storage{Path: dbPath}}, "", slog.New(slog.NewTextHandler(&buf, nil)))

	fi, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o644 {
		t.Errorf("mode changed to %04o; this check must only report", got)
	}
}

// A first run has no database yet. Warning about a file that does not exist
// would be noise on every fresh install.
func TestWarnLoosePermissions_IgnoresMissingFiles(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	warnLoosePermissions(&config.Config{
		Listener: config.Listener{TLSCacheDir: filepath.Join(dir, "nope")},
		Storage:  config.Storage{Path: filepath.Join(dir, "nope.db")},
	}, filepath.Join(dir, "nope.json"), slog.New(slog.NewTextHandler(&buf, nil)))

	if out := buf.String(); out != "" {
		t.Errorf("warned about files that do not exist yet:\n%s", out)
	}
}

// The SQLite sidecar files carry the same data as the database itself.
func TestWarnLoosePermissions_ChecksSQLiteSidecars(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "brokerd.db")
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dbPath+"-wal", 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	warnLoosePermissions(&config.Config{Storage: config.Storage{Path: dbPath}}, "", slog.New(slog.NewTextHandler(&buf, nil)))

	if !strings.Contains(buf.String(), "-wal") {
		t.Errorf("no warning for a world-readable -wal file:\n%s", buf.String())
	}
}
