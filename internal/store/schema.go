// Package store owns buckle's SQLite database: schema, writes from the watcher, and pruning.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

const schemaVersion = 1

const schema = `
CREATE TABLE watches (
  id INTEGER PRIMARY KEY,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  end_reason TEXT,
  os_version TEXT,
  buffer_ns INTEGER NOT NULL
);
CREATE TABLE sessions (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  UNIQUE (kind, key)
);
CREATE TABLE profiles (
  hash TEXT PRIMARY KEY,
  text TEXT NOT NULL
);
CREATE TABLE runs (
  id INTEGER PRIMARY KEY,
  watch_id INTEGER NOT NULL REFERENCES watches(id),
  kind TEXT NOT NULL CHECK (kind IN ('sandbox-exec', 'sandbox-init', 'adopted')),
  parent_run_id INTEGER REFERENCES runs(id) ON DELETE SET NULL,
  session_id INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
  tag TEXT,
  tag_command TEXT,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  status TEXT NOT NULL CHECK (status IN ('running', 'exited', 'watch_stopped')),
  started_before_watch INTEGER NOT NULL DEFAULT 0,
  profile_source TEXT NOT NULL CHECK (profile_source IN ('inline', 'file', 'named', 'unknown')),
  profile_hash TEXT REFERENCES profiles(hash),
  profile_path TEXT,
  profile_name TEXT,
  profile_error TEXT,
  params_json TEXT NOT NULL DEFAULT '[]',
  extra_json TEXT NOT NULL DEFAULT '[]',
  command_json TEXT NOT NULL DEFAULT '[]',
  cwd TEXT
);
CREATE TABLE processes (
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  pid INTEGER NOT NULL,
  pidversion INTEGER,
  parent_process_id INTEGER REFERENCES processes(id) ON DELETE SET NULL,
  exec_prev_process_id INTEGER REFERENCES processes(id) ON DELETE SET NULL,
  ppid INTEGER,
  path TEXT,
  args_json TEXT NOT NULL DEFAULT '[]',
  is_platform_binary INTEGER,
  signing_id TEXT,
  team_id TEXT,
  cdhash TEXT,
  started_at INTEGER,
  ended_at INTEGER,
  end_reason TEXT CHECK (end_reason IN ('exit', 'exec', 'watch_stopped')),
  exit_status INTEGER
);
CREATE TABLE denials (
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  process_id INTEGER NOT NULL REFERENCES processes(id) ON DELETE CASCADE,
  time INTEGER NOT NULL,
  process_name TEXT NOT NULL,
  pid INTEGER NOT NULL,
  operation TEXT NOT NULL,
  target TEXT NOT NULL,
  message TEXT,
  count INTEGER NOT NULL
);
CREATE TABLE orphans (
  id INTEGER PRIMARY KEY,
  watch_id INTEGER NOT NULL REFERENCES watches(id),
  time INTEGER NOT NULL,
  process_name TEXT NOT NULL,
  pid INTEGER NOT NULL,
  operation TEXT NOT NULL,
  target TEXT NOT NULL,
  message TEXT,
  count INTEGER NOT NULL,
  last_path TEXT,
  last_pidversion INTEGER
);
`

// indexes are applied on every writable open so existing databases pick up new ones. Every
// foreign-key child column is indexed: with foreign_keys on, deleting a parent row otherwise scans
// the child table once per referencing column, which made pruning quadratic.
const indexes = `
CREATE INDEX IF NOT EXISTS runs_started ON runs(started_at);
CREATE INDEX IF NOT EXISTS runs_watch ON runs(watch_id);
CREATE INDEX IF NOT EXISTS runs_parent ON runs(parent_run_id);
CREATE INDEX IF NOT EXISTS runs_session ON runs(session_id);
CREATE INDEX IF NOT EXISTS runs_profile ON runs(profile_hash);
CREATE INDEX IF NOT EXISTS processes_run ON processes(run_id);
CREATE INDEX IF NOT EXISTS processes_parent ON processes(parent_process_id);
CREATE INDEX IF NOT EXISTS processes_exec_prev ON processes(exec_prev_process_id);
CREATE INDEX IF NOT EXISTS denials_run ON denials(run_id);
CREATE INDEX IF NOT EXISTS denials_process ON denials(process_id);
CREATE INDEX IF NOT EXISTS orphans_watch ON orphans(watch_id);
CREATE INDEX IF NOT EXISTS orphans_time ON orphans(time);
`

// Store wraps the database handle.
type Store struct {
	DB *sql.DB
}

// Open opens (creating if needed) the database at path for writing and applies the schema.
func Open(path string) (*Store, error) {
	if strings.Contains(path, "?") {
		return nil, fmt.Errorf("store: path must not contain '?': %s", path)
	}
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(DELETE)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// OpenReadOnly opens an existing database for queries only.
func OpenReadOnly(path string) (*Store, error) {
	if strings.Contains(path, "?") {
		return nil, fmt.Errorf("store: path must not contain '?': %s", path)
	}
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		db.Close()
		return nil, err
	}
	if v != schemaVersion {
		db.Close()
		return nil, fmt.Errorf("store: %s has schema version %d, want %d", path, v, schemaVersion)
	}
	return &Store{DB: db}, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) migrate() error {
	var v int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	switch {
	case v == schemaVersion:
		return s.ensureIndexes()
	case v > schemaVersion:
		return fmt.Errorf("store: database schema version %d is newer than this buckle (%d)", v, schemaVersion)
	case v != 0:
		return errors.New("store: unknown schema version")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(schema); err != nil {
		return fmt.Errorf("store: create schema: %w", err)
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.ensureIndexes()
}

func (s *Store) ensureIndexes() error {
	if _, err := s.DB.Exec(indexes); err != nil {
		return fmt.Errorf("store: create indexes: %w", err)
	}
	return nil
}
