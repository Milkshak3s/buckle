package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"buckle/internal/wire"
)

// createV1 builds a schema v1 database with rows in every table, as buckle 0.1 left it.
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

func TestMigrateV1ToV2(t *testing.T) {
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
	if v := count(t, s, `PRAGMA user_version`); v != 2 {
		t.Errorf("user_version = %d, want 2", v)
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

func TestFreshDatabaseIsV2(t *testing.T) {
	s, _ := openTemp(t)
	if v := count(t, s, `PRAGMA user_version`); v != 2 {
		t.Errorf("user_version = %d, want 2", v)
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
