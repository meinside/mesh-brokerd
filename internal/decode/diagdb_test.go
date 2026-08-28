//go:build diag

package decode

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// openDiagDB opens the database named by DIAG_DB read-only and refuses
// anything that is not a brokerd database.
//
// Why the check: the runbook's procedures start with
// `sqlite3 "$DB" ".backup /tmp/diag.db"`, and an unset or misspelled $DB makes
// sqlite3 open a transient in-memory database and back *that* up -- exit
// status 0, a 4 KiB file, no error anywhere. The diagnostic then failed with
// "no such table: raw_frames", which reads like a schema problem in the
// deployment rather than an empty copy. Failing here names the actual cause.
//
// This is the same shape as the misconfigurations these diagnostics exist to
// find: the silent success is worse than the error.
func openDiagDB(t *testing.T) *sql.DB {
	t.Helper()

	dbPath := os.Getenv("DIAG_DB")
	if dbPath == "" {
		t.Fatal("DIAG_DB not set")
	}
	db, err := sql.Open("sqlite3", "file:"+dbPath+"?mode=ro")
	if err != nil {
		t.Fatalf("opening %s: %v", dbPath, err)
	}

	var name string
	err = db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'raw_frames';`).Scan(&name)
	if err == sql.ErrNoRows {
		_ = db.Close()
		info, statErr := os.Stat(dbPath)
		size := int64(-1)
		if statErr == nil {
			size = info.Size()
		}
		t.Fatalf("%s (%d bytes) has no raw_frames table, so it is not a brokerd database.\n"+
			"The usual cause is an empty backup: `sqlite3 \"$DB\" \".backup ...\"` with $DB unset\n"+
			"backs up a transient in-memory database and still exits 0. Set DB to storage.path\n"+
			"from config.json and take the backup again (docs/runbook.md §9.5).", dbPath, size)
	}
	if err != nil {
		_ = db.Close()
		t.Fatalf("reading the schema of %s: %v", dbPath, err)
	}
	return db
}
