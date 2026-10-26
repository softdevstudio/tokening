// Package store owns Tokening's SQLite database and schema migrations.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"modernc.org/sqlite"
)

//go:embed migrations/001_initial.sql
var initialSchema string

//go:embed migrations/002_active_templates.sql
var activeTemplatesSchema string

//go:embed migrations/003_upstream_results.sql
var upstreamResultsSchema string

var migrations = []string{initialSchema, activeTemplatesSchema, upstreamResultsSchema}

type Store struct{ db *sql.DB }

// Open opens an on-disk database, enables WAL and applies migrations atomically.
// The parent directory must be controlled by the operator. SQLite URI parameters
// are constructed here, never accepted from the caller.
func Open(ctx context.Context, path string) (*Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil, fmt.Errorf("store needs a filesystem path, not a SQLite URI or in-memory database")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("database path: %w", err)
	}
	// Never follow an existing database symlink. This is not a substitute for a
	// private parent directory: a hostile directory owner could race any path use.
	if info, err := os.Lstat(abs); err == nil {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("database must be a regular file")
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("database stat: %w", err)
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("database file: %w", err)
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return nil, fmt.Errorf("database permissions: %w", err)
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	uriPath := filepath.ToSlash(abs)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Set("_txlock", "immediate")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	// One connection keeps per-connection settings and transaction ownership simple.
	// Other Tokening processes still contend through SQLite's own write locking.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	fail := func(err error) (*Store, error) { db.Close(); return nil, err }
	if err = db.PingContext(ctx); err != nil {
		return fail(fmt.Errorf("open SQLite: %w", err))
	}
	var mode string
	if err = enableWAL(ctx, db, &mode); err != nil {
		return fail(fmt.Errorf("enable WAL: %w", err))
	}
	if mode != "wal" {
		return fail(fmt.Errorf("database journal mode is %q, expected WAL", mode))
	}
	if err = migrate(ctx, db, migrations); err != nil {
		return fail(err)
	}
	return &Store{db: db}, nil
}

// Changing journal mode can return SQLITE_BUSY immediately despite busy_timeout
// when another opener holds a read lock. Retry only lock contention, within the
// same five-second budget used for other SQLite operations.
func enableWAL(ctx context.Context, db *sql.DB, mode *string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		err := db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(mode)
		var sqliteErr *sqlite.Error
		if !errors.As(err, &sqliteErr) || (sqliteErr.Code()&255 != 5 && sqliteErr.Code()&255 != 6) {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *Store) Close() error { return s.db.Close() }

func migrate(ctx context.Context, db *sql.DB, steps []string) error {
	// _txlock=immediate serializes migration readers as well as writers, so two
	// initializers cannot both observe schema version zero and create the tables.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema migration: %w", err)
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version < 0 || version > len(steps) {
		return fmt.Errorf("database schema %d is newer than supported schema %d; use a newer Tokening binary", version, len(steps))
	}
	for i := version; i < len(steps); i++ {
		if _, err = tx.ExecContext(ctx, steps[i]); err != nil {
			return fmt.Errorf("apply schema migration %d: %w", i+1, err)
		}
		if _, err = tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", i+1)); err != nil {
			return fmt.Errorf("record schema migration %d: %w", i+1, err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit schema migrations: %w", err)
	}
	return nil
}
