package store

import (
	"testing"
	"time"
)

// Every foreign-key child column needs an index: with foreign_keys on, deleting a parent row
// scans the child table once per referencing column otherwise, which made prune quadratic.
func TestForeignKeyColumnsIndexed(t *testing.T) {
	s, path := openTemp(t)
	cols := [][2]string{
		{"runs", "watch_id"}, {"runs", "parent_run_id"}, {"runs", "session_id"}, {"runs", "profile_hash"},
		{"processes", "run_id"}, {"processes", "parent_process_id"}, {"processes", "exec_prev_process_id"},
		{"denials", "run_id"}, {"denials", "process_id"},
		{"orphans", "watch_id"}, {"orphans", "time"},
	}
	check := func(s *Store) {
		t.Helper()
		for _, c := range cols {
			n := count(t, s, `SELECT count(*) FROM pragma_index_list(?) il JOIN pragma_index_info(il.name) ii
				WHERE ii.seqno = 0 AND ii.name = ?`, c[0], c[1])
			if n == 0 {
				t.Errorf("no index leading with %s.%s", c[0], c[1])
			}
		}
	}
	check(s)

	// A database created before an index existed gets it on the next writable open.
	if _, err := s.DB.Exec(`DROP INDEX processes_parent`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	check(s2)
}

func TestPruneScalesWithProcessTrees(t *testing.T) {
	s, _ := openTemp(t)
	now := t0
	old := now.Add(-31 * 24 * time.Hour)
	w, err := s.BeginWatch(old, "14.2", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	var prevRun any
	for i := 0; i < 200; i++ {
		st := old
		if i%2 == 0 {
			st = now
		}
		res, err := tx.Exec(`INSERT INTO runs (watch_id, kind, parent_run_id, started_at, status, profile_source)
			VALUES (?, 'sandbox-exec', ?, ?, 'running', 'unknown')`, w, prevRun, st.UnixNano())
		if err != nil {
			t.Fatal(err)
		}
		rid, _ := res.LastInsertId()
		prevRun = rid
		var prev any
		for j := 0; j < 40; j++ {
			res, err := tx.Exec(`INSERT INTO processes (run_id, pid, parent_process_id, exec_prev_process_id) VALUES (?, ?, ?, ?)`, rid, j, prev, prev)
			if err != nil {
				t.Fatal(err)
			}
			prev, _ = res.LastInsertId()
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	st, err := s.Prune(now, 30*24*time.Hour)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if st.Runs != 100 {
		t.Errorf("pruned runs = %d, want 100", st.Runs)
	}
	if n := count(t, s, `SELECT count(*) FROM processes`); n != 4000 {
		t.Errorf("processes left = %d, want 4000", n)
	}
	if elapsed > 3*time.Second {
		t.Errorf("prune of 4000 process rows took %v", elapsed)
	}
}
