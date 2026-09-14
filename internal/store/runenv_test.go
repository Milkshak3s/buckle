package store

import (
	"testing"
	"time"
)

func TestInsertRunEnv(t *testing.T) {
	s, _ := openTemp(t)
	old := t0.Add(-31 * 24 * time.Hour)
	w, _ := s.BeginWatch(old, "14.2", time.Second)
	c0 := count(t, s, `SELECT value FROM rev_counter`)
	r, err := s.InsertRun(Run{WatchID: w, Kind: "sandbox-exec", StartedAt: old, ProfileSource: "unknown",
		Env: map[string]string{"CURSOR_REQUEST_ID": "req", "CURSOR_AGENT": "1", "EMPTY": ""}})
	if err != nil {
		t.Fatal(err)
	}
	// One revision for the run, then one per variable in name order.
	if got := count(t, s, `SELECT value FROM rev_counter`); got != c0+4 {
		t.Errorf("rev counter = %d, want %d", got, c0+4)
	}
	rows, err := s.DB.Query(`SELECT name, value, rev FROM run_env WHERE run_id = ? ORDER BY rev`, r)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var name, value string
		var rev int
		rows.Scan(&name, &value, &rev)
		names = append(names, name+"="+value)
	}
	rows.Close()
	if len(names) != 3 || names[0] != "CURSOR_AGENT=1" || names[1] != "CURSOR_REQUEST_ID=req" || names[2] != "EMPTY=" {
		t.Errorf("run_env = %v", names)
	}

	if _, err := s.InsertRun(Run{WatchID: w, Kind: "sandbox-exec", StartedAt: t0, ProfileSource: "unknown"}); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM run_env`); n != 3 {
		t.Errorf("run without env added rows: %d", n)
	}

	if _, err := s.Prune(t0, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM run_env`); n != 0 {
		t.Errorf("run_env rows after pruning their run = %d, want 0", n)
	}
}
