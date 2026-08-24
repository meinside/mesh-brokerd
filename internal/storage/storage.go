// Package storage implements brokerd's SQLite persistence layer
// (docs/storage-schema.md): raw-frame-first storage (ADR-3/ADR-4),
// decoded per-portnum tables, and retention deletion (ADR-7).
package storage

import (
	"database/sql"
	_ "embed"
	"fmt"

	_ "github.com/mattn/go-sqlite3" // cgo binding to the real SQLite C library (registers as "sqlite3")
)

// schemaSQL is brokerd's complete schema, applied with CREATE ... IF NOT
// EXISTS on every Open. There is no migration runner and no version table:
// with a single deployment, a schema change means editing schema.sql and
// running the same statement against that one database by hand
// (docs/storage-schema.md §5).
//
//go:embed schema.sql
var schemaSQL string

// DecodeVersion stamps each stored row with the generation of decoder that
// wrote it, so the reprocessing path can tell which rows predate a decoder
// fix (docs/storage-schema.md §7). It is a property of the decoding logic,
// not of the schema -- bump it when a decoder's output changes meaning.
const DecodeVersion = 2

// Store wraps the SQLite connection. A single writer goroutine (the
// storage worker, ADR-3) is expected to own all writes through this
// Store; monitoring reads may use a separate read-only connection
// against the same file (docs/storage-schema.md §4).
type Store struct {
	names nameCache
	db    *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path, applies
// the standard PRAGMAs (docs/storage-schema.md §4), and creates anything in
// schema.sql that does not exist yet.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: opening %s: %w", path, err)
	}

	s := &Store{db: db}
	if err := s.applySchema(); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("storage: %w (additionally, closing the connection failed: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("storage: %w", err)
	}
	// Node names are read on every page row and every hook event, so they
	// live in memory; the table is the durable copy.
	if err := s.loadNodeNames(); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("storage: %w (additionally, closing the connection failed: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("storage: %w", err)
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// DB exposes the underlying *sql.DB for read-only consumers (e.g.
// internal/monitor's stats queries) that don't need Store's write
// helpers.
func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) applySchema() error {
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("applying schema: %w", err)
	}
	return nil
}
