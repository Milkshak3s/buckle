package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"buckle/internal/wire"
)

// createV1 builds a schema v1 database with rows in every table, as the first buckle builds left it.
func createV1(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "buckle.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	ns := t0.UnixNano()
	exec(schemaV1)
	exec(`INSERT INTO watches (started_at, buffer_ns) VALUES (?, 5000000000)`, ns)
	exec(`INSERT INTO sessions (kind, key, first_seen, last_seen) VALUES ('claude-code', '_k3j9x0q2m_SBX', ?, ?)`, ns, ns)
	exec(`INSERT INTO profiles (hash, text) VALUES ('abc', '(version 1)')`)
	exec(`INSERT INTO runs (watch_id, kind, session_id, started_at, status, profile_source, profile_hash)
		VALUES (1, 'sandbox-exec', 1, ?, 'exited', 'inline', 'abc')`, ns)
	exec(`INSERT INTO processes (run_id, pid) VALUES (1, 100)`)
	exec(`INSERT INTO processes (run_id, pid, parent_process_id) VALUES (1, 101, 1)`)
	exec(`INSERT INTO denials (run_id, process_id, time, process_name, pid, operation, target, count)
		VALUES (1, 2, ?, 'cat', 101, 'file-read-data', '/private/etc/hosts', 1)`, ns)
	exec(`INSERT INTO orphans (watch_id, time, process_name, pid, operation, target, count)
		VALUES (1, ?, 'curl', 200, 'network-outbound', 'remote:*:80', 2)`, ns)
	exec(`PRAGMA user_version = 1`)
	return path
}

func journalMode(t *testing.T, s *Store) string {
	t.Helper()
	var mode string
	if err := s.DB.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	return mode
}

func TestMigrateV1ToV3(t *testing.T) {
	path := createV1(t)
	inst, migrated, err := Migrate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !migrated || len(inst) != 36 {
		t.Fatalf("Migrate = %q, %v; want a 36-char instance and migrated=true", inst, migrated)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if v := count(t, s, `PRAGMA user_version`); v != SchemaVersion {
		t.Errorf("user_version = %d, want %d", v, SchemaVersion)
	}
	if m := journalMode(t, s); m != "wal" {
		t.Errorf("journal_mode = %q, want wal", m)
	}
	var parts []string
	for _, tbl := range wire.Tables {
		parts = append(parts, "SELECT rev FROM "+tbl)
	}
	var total, distinct, minRev, maxRev int
	if err := s.DB.QueryRow(`SELECT count(*), count(DISTINCT rev), min(rev), max(rev) FROM (`+strings.Join(parts, " UNION ALL ")+`)`).
		Scan(&total, &distinct, &minRev, &maxRev); err != nil {
		t.Fatal(err)
	}
	if total != 8 || distinct != 8 || minRev < 1 {
		t.Errorf("backfill: total=%d distinct=%d min=%d; want 8 unique revs >= 1", total, distinct, minRev)
	}
	if c := count(t, s, `SELECT value FROM rev_counter`); c != maxRev {
		t.Errorf("rev_counter = %d, want max rev %d", c, maxRev)
	}
	if got, err := s.DBInstance(); err != nil || got != inst {
		t.Errorf("DBInstance = %q, %v; want %q", got, err, inst)
	}
	s.Close()

	again, migrated, err := Migrate(path)
	if err != nil || migrated || again != inst {
		t.Errorf("second Migrate = %q, %v, %v; want %q, false, nil", again, migrated, err, inst)
	}
}

func TestV1Refused(t *testing.T) {
	path := createV1(t)
	if _, err := Open(path); !errors.Is(err, ErrNeedsMigration) {
		t.Errorf("Open v1: %v, want ErrNeedsMigration", err)
	}
	if _, err := OpenReadOnly(path); !errors.Is(err, ErrNeedsMigration) {
		t.Errorf("OpenReadOnly v1: %v, want ErrNeedsMigration", err)
	}
	if _, _, err := Migrate(filepath.Join(t.TempDir(), "none.db")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Migrate missing: %v, want ErrNotExist", err)
	}
}

// createV2 builds a schema v2 database with a run, as buckle left it before run_env existed.
func createV2(t *testing.T) (path, inst string) {
	t.Helper()
	path = createV1(t)
	inst, _, err := Migrate(path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE run_env; PRAGMA user_version = 2`); err != nil {
		t.Fatal(err)
	}
	return path, inst
}

func TestMigrateV2ToV3(t *testing.T) {
	path, inst := createV2(t)
	if _, err := Open(path); !errors.Is(err, ErrNeedsMigration) {
		t.Errorf("Open v2: %v, want ErrNeedsMigration", err)
	}
	if _, err := OpenReadOnly(path); !errors.Is(err, ErrNeedsMigration) {
		t.Errorf("OpenReadOnly v2: %v, want ErrNeedsMigration", err)
	}
	got, migrated, err := Migrate(path)
	if err != nil || !migrated || got != inst {
		t.Fatalf("Migrate v2 = %q, %v, %v; want %q, true, nil", got, migrated, err, inst)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	before := count(t, s, `SELECT value FROM rev_counter`)
	if _, err := s.InsertRun(Run{WatchID: 1, Kind: "sandbox-exec", StartedAt: t0, ProfileSource: "unknown",
		Env: map[string]string{"CURSOR_AGENT": "1"}}); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM run_env WHERE rev > ?`, before); n != 1 {
		t.Errorf("run_env rows stamped after migration = %d, want 1 (trigger missing?)", n)
	}
}

func TestFreshDatabaseIsCurrent(t *testing.T) {
	s, _ := openTemp(t)
	if v := count(t, s, `PRAGMA user_version`); v != SchemaVersion {
		t.Errorf("user_version = %d, want %d", v, SchemaVersion)
	}
	if m := journalMode(t, s); m != "wal" {
		t.Errorf("journal_mode = %q, want wal", m)
	}
	if inst, err := s.DBInstance(); err != nil || len(inst) != 36 {
		t.Errorf("DBInstance = %q, %v", inst, err)
	}
	for _, tbl := range wire.Tables {
		rows, err := s.DB.Query(`SELECT name FROM pragma_table_info(?) ORDER BY cid`, tbl)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for rows.Next() {
			var n string
			rows.Scan(&n)
			got = append(got, n)
		}
		rows.Close()
		if !slices.Equal(got, wire.Columns[tbl]) {
			t.Errorf("%s columns = %v, want wire.Columns %v", tbl, got, wire.Columns[tbl])
		}
	}
}

func TestRevBumps(t *testing.T) {
	s, _ := openTemp(t)
	counter := func() int { return count(t, s, `SELECT value FROM rev_counter`) }
	c0 := counter()
	w, err := s.BeginWatch(t0, "14.2", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if counter() != c0+1 || count(t, s, `SELECT rev FROM watches WHERE id = ?`, w) != c0+1 {
		t.Errorf("insert: counter %d, want %d", counter(), c0+1)
	}
	s.EndWatch(w, t0, "stopped")
	if counter() != c0+2 || count(t, s, `SELECT rev FROM watches WHERE id = ?`, w) != c0+2 {
		t.Errorf("update: counter %d, want %d", counter(), c0+2)
	}
	sid, _ := s.EnsureSession("claude-code", "_a_SBX", t0)
	s.EnsureSession("claude-code", "_a_SBX", t0.Add(time.Second)) // upsert fires the update trigger
	if counter() != c0+4 || count(t, s, `SELECT rev FROM sessions WHERE id = ?`, sid) != c0+4 {
		t.Errorf("session upsert: counter %d, want %d", counter(), c0+4)
	}
	r, _ := s.InsertRun(Run{WatchID: w, Kind: "sandbox-exec", StartedAt: t0, ProfileSource: "inline", ProfileText: "(version 1)"})
	profRev := count(t, s, `SELECT rev FROM profiles`)
	s.InsertRun(Run{WatchID: w, Kind: "sandbox-exec", StartedAt: t0, ProfileSource: "inline", ProfileText: "(version 1)"})
	if counter() != c0+7 || count(t, s, `SELECT rev FROM profiles`) != profRev {
		t.Errorf("profile dedup: counter %d (want %d), profile rev changed", counter(), c0+7)
	}
	s.SetRunSession(r, sid, "", "")
	s.SetRunSession(r, sid, "", "") // matches no row: no bump
	if counter() != c0+8 {
		t.Errorf("SetRunSession: counter %d, want %d", counter(), c0+8)
	}
}

func TestChangesSince(t *testing.T) {
	s, _ := openTemp(t)
	w, _ := s.BeginWatch(t0, "14.2", 5*time.Second)
	r, _ := s.InsertRun(Run{WatchID: w, Kind: "sandbox-exec", StartedAt: t0, ProfileSource: "unknown", Command: []string{"/bin/cat"}})
	if _, err := s.InsertProcess(Process{RunID: r, PID: 100, StartedAt: ptr(t0)}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ChangesSince(0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for i, row := range rows {
		tables = append(tables, row.Table)
		if i > 0 && row.Rev <= rows[i-1].Rev {
			t.Errorf("rows not in rev order: %d after %d", row.Rev, rows[i-1].Rev)
		}
		if len(row.Data) != len(wire.Columns[row.Table]) || row.Data["rev"] != row.Rev {
			t.Errorf("%s row data %v incomplete or rev mismatch", row.Table, row.Data)
		}
	}
	if !slices.Equal(tables, []string{"watches", "runs", "processes"}) {
		t.Fatalf("tables = %v", tables)
	}
	if rows[1].Data["command_json"] != `["/bin/cat"]` || rows[1].Data["started_at"] != t0.UnixNano() {
		t.Errorf("run data = %v", rows[1].Data)
	}
	cursor := rows[2].Rev
	if more, _ := s.ChangesSince(cursor, 1000); len(more) != 0 {
		t.Errorf("nothing changed, got %d rows", len(more))
	}
	s.EndRun(r, ptr(t0), "exited")
	more, _ := s.ChangesSince(cursor, 1000)
	if len(more) != 1 || more[0].Table != "runs" || more[0].Data["status"] != "exited" || more[0].Rev <= cursor {
		t.Errorf("after update: %+v", more)
	}
	limited, _ := s.ChangesSince(0, 2)
	if len(limited) != 2 || limited[0].Table != "watches" || limited[1].Table != "processes" {
		t.Errorf("limit 2 = %+v, want watches then processes", limited)
	}
}

// A database from a future buckle must be refused, not silently treated as needing migration.
func TestNewerSchemaVersionRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "buckle.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, SchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path); err == nil || errors.Is(err, ErrNeedsMigration) {
		t.Errorf("Open newer: %v, want a plain error (not nil, not ErrNeedsMigration)", err)
	}
	if _, err := OpenReadOnly(path); err == nil || errors.Is(err, ErrNeedsMigration) {
		t.Errorf("OpenReadOnly newer: %v, want a plain error (not nil, not ErrNeedsMigration)", err)
	}
	if _, _, err := Migrate(path); err == nil || errors.Is(err, ErrNeedsMigration) {
		t.Errorf("Migrate newer: %v, want a plain error (not nil, not ErrNeedsMigration)", err)
	}
}

// The rev triggers created by upgradeV2 must fire on a migrated (backfilled) database, not just a
// fresh v2 one.
func TestMigratedDBTriggersFire(t *testing.T) {
	path := createV1(t)
	if _, _, err := Migrate(path); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var parts []string
	for _, tbl := range wire.Tables {
		parts = append(parts, "SELECT rev FROM "+tbl)
	}
	maxBackfill := count(t, s, `SELECT max(rev) FROM (`+strings.Join(parts, " UNION ALL ")+`)`)

	if err := s.EndWatch(1, t0, "stopped"); err != nil {
		t.Fatal(err)
	}
	if newRev := count(t, s, `SELECT rev FROM watches WHERE id = 1`); newRev <= maxBackfill {
		t.Errorf("EndWatch rev on migrated DB = %d, want > backfill max %d (trigger didn't fire)", newRev, maxBackfill)
	}
}

// ON DELETE SET NULL of a child run's parent_run_id must bump the child's rev so the server picks
// up the change.
func TestPruneNullsChildParentRevBump(t *testing.T) {
	s, _ := openTemp(t)
	old := t0.Add(-31 * 24 * time.Hour)
	recent := t0.Add(-time.Hour)

	oldW, _ := s.BeginWatch(old, "14.2", time.Second)
	newW, _ := s.BeginWatch(recent, "14.2", time.Second)
	parent, err := s.InsertRun(Run{WatchID: oldW, Kind: "sandbox-exec", StartedAt: old, ProfileSource: "unknown"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := s.InsertRun(Run{WatchID: newW, Kind: "sandbox-exec", ParentRunID: &parent, StartedAt: recent, ProfileSource: "unknown"})
	if err != nil {
		t.Fatal(err)
	}
	cursor := int64(count(t, s, `SELECT rev FROM runs WHERE id = ?`, child))

	// Cutoff deletes only the parent run: it started 31 days ago, the child only an hour ago.
	st, err := s.Prune(t0, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if st.Runs != 1 {
		t.Fatalf("pruned runs = %d, want 1 (the parent only)", st.Runs)
	}
	if n := count(t, s, `SELECT count(*) FROM runs WHERE id = ?`, child); n != 1 {
		t.Fatalf("child run was deleted, want it kept")
	}

	rows, err := s.ChangesSince(cursor, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, row := range rows {
		if row.Table != "runs" || row.Data["id"] != child {
			continue
		}
		found = true
		if row.Data["parent_run_id"] != nil {
			t.Errorf("child parent_run_id = %v, want nil after parent pruned", row.Data["parent_run_id"])
		}
	}
	if !found {
		t.Errorf("ChangesSince(%d) didn't return the child run after its parent was pruned: %+v", cursor, rows)
	}
}

func TestReadOnlyNeedsSudo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write any -shm")
	}
	s, path := openTemp(t)
	s.Close()
	os.Remove(path + "-shm") // WriteFile keeps an existing file's mode
	if err := os.WriteFile(path+"-shm", nil, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReadOnly(path); !errors.Is(err, ErrNeedsSudo) {
		t.Errorf("OpenReadOnly with unwritable -shm: %v, want ErrNeedsSudo", err)
	}
}
