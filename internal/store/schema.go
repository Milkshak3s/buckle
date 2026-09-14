// Package store owns buckle's SQLite database: schema, writes from the watcher, and pruning.
package store

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	_ "modernc.org/sqlite"
)

const schemaV1 = `
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
CREATE INDEX IF NOT EXISTS watches_rev ON watches(rev);
CREATE INDEX IF NOT EXISTS sessions_rev ON sessions(rev);
CREATE INDEX IF NOT EXISTS profiles_rev ON profiles(rev);
CREATE INDEX IF NOT EXISTS runs_rev ON runs(rev);
CREATE INDEX IF NOT EXISTS processes_rev ON processes(rev);
CREATE INDEX IF NOT EXISTS denials_rev ON denials(rev);
CREATE INDEX IF NOT EXISTS orphans_rev ON orphans(rev);
CREATE INDEX IF NOT EXISTS run_env_rev ON run_env(rev);
`

// SchemaVersion is the endpoint database schema this buckle reads and writes.
const SchemaVersion = 3

// v2Tables are the tables upgradeV2 adds change tracking to, in revision backfill order.
var v2Tables = []string{"watches", "sessions", "profiles", "runs", "processes", "denials", "orphans"}

var (
	ErrNeedsMigration = errors.New("database schema is out of date; run 'buckle migrate' (without sudo) first")
	ErrNeedsSudo      = errors.New("database is in use by a root process (buckle watch/ship); re-run with sudo")
)

// revTriggers stamps rows with the next global revision on insert and on update. The WHEN guard
// stops the trigger's own UPDATE from bumping again.
func revTriggers(table string) string {
	return fmt.Sprintf(`
CREATE TRIGGER %[1]s_rev_insert AFTER INSERT ON %[1]s BEGIN
  UPDATE rev_counter SET value = value + 1 WHERE id = 1;
  UPDATE %[1]s SET rev = (SELECT value FROM rev_counter WHERE id = 1) WHERE rowid = NEW.rowid;
END;
CREATE TRIGGER %[1]s_rev_update AFTER UPDATE ON %[1]s WHEN NEW.rev = OLD.rev BEGIN
  UPDATE rev_counter SET value = value + 1 WHERE id = 1;
  UPDATE %[1]s SET rev = (SELECT value FROM rev_counter WHERE id = 1) WHERE rowid = NEW.rowid;
END;`, table)
}

// upgradeV2 adds change tracking to a v1 schema inside tx: rev columns backfilled with unique
// revisions, the counter, triggers and a random db_instance.
func upgradeV2(tx *sql.Tx) error {
	if _, err := tx.Exec(`CREATE TABLE rev_counter (id INTEGER PRIMARY KEY CHECK (id = 1), value INTEGER NOT NULL);
		CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);`); err != nil {
		return err
	}
	inst, err := newUUID()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO meta (key, value) VALUES ('db_instance', ?)`, inst); err != nil {
		return err
	}
	var offset int64
	for _, t := range v2Tables {
		if _, err := tx.Exec(`ALTER TABLE ` + t + ` ADD COLUMN rev INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE `+t+` SET rev = rowid + ?`, offset); err != nil {
			return err
		}
		var max int64
		if err := tx.QueryRow(`SELECT coalesce(max(rowid), 0) FROM ` + t).Scan(&max); err != nil {
			return err
		}
		offset += max
		if _, err := tx.Exec(revTriggers(t)); err != nil {
			return err
		}
	}
	_, err = tx.Exec(`INSERT INTO rev_counter (id, value) VALUES (1, ?)`, offset)
	return err
}

// upgradeV3 adds run_env: the session detectors' declared environment variables from each
// sandbox-exec run's root exec.
func upgradeV3(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE run_env (
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  rev INTEGER NOT NULL DEFAULT 0,
  UNIQUE (run_id, name)
);` + revTriggers("run_env"))
	return err
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// Store wraps the database handle.
type Store struct {
	DB *sql.DB
}

func openWritable(path string) (*sql.DB, error) {
	if strings.Contains(path, "?") {
		return nil, fmt.Errorf("store: path must not contain '?': %s", path)
	}
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// Open opens (creating if needed) the database at path for writing. New databases are created at
// SchemaVersion; older ones are refused with ErrNeedsMigration.
func Open(path string) (*Store, error) {
	db, err := openWritable(path)
	if err != nil {
		return nil, err
	}
	s := &Store{DB: db}
	if _, err := s.migrate(false); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Migrate upgrades an existing older database at path to SchemaVersion. It reports the db_instance
// and whether anything changed.
func Migrate(path string) (string, bool, error) {
	if _, err := os.Stat(path); err != nil {
		return "", false, err
	}
	db, err := openWritable(path)
	if err != nil {
		return "", false, err
	}
	s := &Store{DB: db}
	defer s.Close()
	migrated, err := s.migrate(true)
	if err != nil {
		return "", false, err
	}
	inst, err := s.DBInstance()
	return inst, migrated, err
}

// OpenReadOnly opens an existing current-schema database for queries only.
func OpenReadOnly(path string) (*Store, error) {
	if strings.Contains(path, "?") {
		return nil, fmt.Errorf("store: path must not contain '?': %s", path)
	}
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	// A WAL reader must write -shm. When root (watch/ship) created it, fail with a clear message
	// instead of SQLite's "unable to open database file". 2 is W_OK.
	if os.Geteuid() != 0 {
		if err := syscall.Access(path+"-shm", 2); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", path, ErrNeedsSudo)
		}
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
	switch {
	case v == SchemaVersion:
		return &Store{DB: db}, nil
	case v > 0 && v < SchemaVersion:
		db.Close()
		return nil, ErrNeedsMigration
	}
	db.Close()
	return nil, fmt.Errorf("store: %s has schema version %d, want %d", path, v, SchemaVersion)
}

func (s *Store) Close() error { return s.DB.Close() }

// DBInstance is the random id identifying this database to the report server.
func (s *Store) DBInstance() (string, error) {
	var v string
	err := s.DB.QueryRow(`SELECT value FROM meta WHERE key = 'db_instance'`).Scan(&v)
	return v, err
}

// migrate brings the schema to SchemaVersion (upgrading an existing older database only when
// allowOld) and enables WAL. It reports whether the schema changed.
func (s *Store) migrate(allowOld bool) (bool, error) {
	var v int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return false, err
	}
	changed := false
	switch {
	case v == SchemaVersion:
	case v > SchemaVersion:
		return false, fmt.Errorf("store: database schema version %d is newer than this buckle (%d)", v, SchemaVersion)
	case v < 0:
		return false, errors.New("store: unknown schema version")
	case v > 0 && !allowOld:
		return false, ErrNeedsMigration
	default:
		tx, err := s.DB.Begin()
		if err != nil {
			return false, err
		}
		defer tx.Rollback()
		if v == 0 {
			if _, err := tx.Exec(schemaV1); err != nil {
				return false, fmt.Errorf("store: create schema: %w", err)
			}
		}
		if v < 2 {
			if err := upgradeV2(tx); err != nil {
				return false, fmt.Errorf("store: upgrade to v2: %w", err)
			}
		}
		if err := upgradeV3(tx); err != nil {
			return false, fmt.Errorf("store: upgrade to v3: %w", err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, SchemaVersion)); err != nil {
			return false, err
		}
		if err := tx.Commit(); err != nil {
			return false, err
		}
		changed = true
	}
	var mode string
	if err := s.DB.QueryRow(`PRAGMA journal_mode=WAL`).Scan(&mode); err != nil {
		return false, err
	}
	if mode != "wal" {
		return false, fmt.Errorf("store: journal_mode is %q, want wal", mode)
	}
	return changed, s.ensureIndexes()
}

func (s *Store) ensureIndexes() error {
	if _, err := s.DB.Exec(indexes); err != nil {
		return fmt.Errorf("store: create indexes: %w", err)
	}
	return nil
}
