// Package serverdb is buckle serve's database: mirrored endpoint rows keyed by host and database
// instance, plus the queries behind the web pages.
package serverdb

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"

	"buckle/internal/wire"

	_ "modernc.org/sqlite"
)

const schemaVersion = 1

type DB struct {
	DB *sql.DB
}

// PathForHome is the server database location inside a user's home directory.
func PathForHome(home string) string {
	return filepath.Join(home, "Library", "Application Support", "buckle", "server.db")
}

func quote(id string) string { return `"` + id + `"` }

// ddl mirrors every shipped table with untyped columns (values keep the types they were sent
// with), no foreign keys and no CHECKs: rows may arrive before their parents.
func ddl() string {
	var b strings.Builder
	for _, t := range wire.Tables {
		cols := make([]string, len(wire.Columns[t]))
		for i, c := range wire.Columns[t] {
			cols[i] = quote(c)
		}
		fmt.Fprintf(&b, "CREATE TABLE %s (host_uuid TEXT NOT NULL, db_instance TEXT NOT NULL, %s, PRIMARY KEY (host_uuid, db_instance, %s));\n",
			quote(t), strings.Join(cols, ", "), quote(wire.Key(t)))
	}
	b.WriteString(`
CREATE TABLE hosts (uuid TEXT PRIMARY KEY, name TEXT NOT NULL, first_seen INTEGER NOT NULL, last_report_at INTEGER NOT NULL);
CREATE TABLE sync_state (host_uuid TEXT NOT NULL, db_instance TEXT NOT NULL, rev INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  PRIMARY KEY (host_uuid, db_instance));
CREATE INDEX runs_session ON runs (host_uuid, db_instance, session_id);
CREATE INDEX runs_parent ON runs (host_uuid, db_instance, parent_run_id);
CREATE INDEX processes_run ON processes (host_uuid, db_instance, run_id);
CREATE INDEX denials_run ON denials (host_uuid, db_instance, run_id);
CREATE INDEX watches_host ON watches (host_uuid, started_at);
`)
	return b.String()
}

// Open opens (creating if needed) the server database.
func Open(path string) (*DB, error) {
	if strings.Contains(path, "?") {
		return nil, fmt.Errorf("serverdb: path must not contain '?': %s", path)
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := initSchema(db, path); err != nil {
		db.Close()
		return nil, err
	}
	return &DB{DB: db}, nil
}

func initSchema(db *sql.DB, path string) error {
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	switch v {
	case schemaVersion:
	case 0:
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err := tx.Exec(ddl()); err != nil {
			return fmt.Errorf("serverdb: create schema: %w", err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("serverdb: %s has schema version %d, want %d", path, v, schemaVersion)
	}
	var mode string
	return db.QueryRow(`PRAGMA journal_mode=WAL`).Scan(&mode)
}

func (d *DB) Close() error { return d.DB.Close() }
