package store

import (
	"path/filepath"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 13, 17, 8, 38, 775921977, time.UTC)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "buckle.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func ptr[T any](v T) *T { return &v }

func count(t *testing.T, s *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func TestRoundTrip(t *testing.T) {
	s, _ := openTemp(t)
	w, err := s.BeginWatch(t0, "14.2", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := s.EnsureSession("claude-code", "_k3j9x0q2m_SBX", t0)
	if err != nil {
		t.Fatal(err)
	}
	profile := "(version 1)(allow default)"
	r1, err := s.InsertRun(Run{WatchID: w, Kind: "sandbox-exec", StartedAt: t0, ProfileSource: "inline", ProfileText: profile,
		Params: [][2]string{{"OUT", "/private/tmp"}}, Command: []string{"/bin/cat", "/etc/hosts"}, Cwd: "/"})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.InsertRun(Run{WatchID: w, Kind: "sandbox-exec", ParentRunID: &r1, StartedAt: t0, ProfileSource: "inline", ProfileText: profile})
	if err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM profiles`); n != 1 {
		t.Errorf("profiles = %d, want 1 (dedup by hash)", n)
	}
	var hash, params, cmd, status string
	if err := s.DB.QueryRow(`SELECT profile_hash, params_json, command_json, status FROM runs WHERE id=?`, r1).Scan(&hash, &params, &cmd, &status); err != nil {
		t.Fatal(err)
	}
	if len(hash) != 64 || params != `[["OUT","/private/tmp"]]` || cmd != `["/bin/cat","/etc/hosts"]` || status != "running" {
		t.Errorf("run row: %s %s %s %s", hash, params, cmd, status)
	}

	if err := s.SetRunSession(r1, sid, "CMD64_x_END__k3j9x0q2m_SBX", "x"); err != nil {
		t.Fatal(err)
	}
	other, _ := s.EnsureSession("claude-code", "_other_SBX", t0)
	if err := s.SetRunSession(r1, other, "y", "y"); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM runs WHERE id=? AND session_id=? AND tag_command='x'`, r1, sid); n != 1 {
		t.Error("SetRunSession must not overwrite an existing session")
	}

	p1, err := s.InsertProcess(Process{RunID: r1, PID: 15505, PIDVersion: ptr(34597), PPID: 15504, Path: "/usr/bin/sandbox-exec",
		Args: []string{"/usr/bin/sandbox-exec"}, IsPlatform: ptr(true), CDHash: "AB", StartedAt: &t0})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := s.InsertProcess(Process{RunID: r1, PID: 15505, PIDVersion: ptr(34600), ExecPrevProcessID: &p1, Path: "/bin/cat", IsPlatform: ptr(true), StartedAt: &t0})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EndProcess(p1, &t0, "exec", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.EndProcess(p2, &t0, "exit", ptr(256)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM processes WHERE id=? AND end_reason='exit' AND exit_status=256 AND ended_at IS NOT NULL`, p2); n != 1 {
		t.Error("EndProcess not stored")
	}

	d, err := s.InsertDenial(Denial{RunID: r1, ProcessID: p2, Time: t0, ProcessName: "cat", PID: 15505, Operation: "file-read-data", Target: "/private/etc/hosts", Count: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddDenialCount(d, 3); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count FROM denials WHERE id=?`, d); n != 4 {
		t.Errorf("denial count = %d", n)
	}
	if _, err := s.InsertOrphan(Orphan{WatchID: w, Time: t0, ProcessName: "x", PID: 1, Operation: "op", Count: 1, LastPath: "/x", LastPIDVersion: ptr(3)}); err != nil {
		t.Fatal(err)
	}

	if err := s.EndRun(r2, nil, "watch_stopped"); err != nil {
		t.Fatal(err)
	}
	if err := s.EndRun(r1, &t0, "exited"); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s, `SELECT count(*) FROM runs WHERE (id=? AND status='watch_stopped' AND ended_at IS NULL) OR (id=? AND status='exited' AND ended_at IS NOT NULL)`, r2, r1); n != 2 {
		t.Error("EndRun not stored")
	}
	if err := s.EndWatch(w, t0, "stopped"); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureSessionUpsert(t *testing.T) {
	s, _ := openTemp(t)
	a, err := s.EnsureSession("claude-code", "_k_SBX", t0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.EnsureSession("claude-code", "_k_SBX", t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("ids differ: %d %d", a, b)
	}
	if n := count(t, s, `SELECT count(*) FROM sessions WHERE last_seen=? AND first_seen=?`, t0.Add(time.Hour).UnixNano(), t0.UnixNano()); n != 1 {
		t.Error("last_seen not bumped")
	}
}

func TestForeignKeysEnforced(t *testing.T) {
	s, _ := openTemp(t)
	if _, err := s.InsertProcess(Process{RunID: 999, PID: 1}); err == nil {
		t.Error("insert with bad run_id succeeded")
	}
}

func TestReadOnly(t *testing.T) {
	s, path := openTemp(t)
	if _, err := s.BeginWatch(t0, "14.2", time.Second); err != nil {
		t.Fatal(err)
	}
	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if n := count(t, ro, `SELECT count(*) FROM watches`); n != 1 {
		t.Errorf("watches = %d", n)
	}
	if _, err := ro.BeginWatch(t0, "14.2", time.Second); err == nil {
		t.Error("write through read-only store succeeded")
	}
	if _, err := OpenReadOnly(filepath.Join(t.TempDir(), "missing.db")); err == nil {
		t.Error("OpenReadOnly on missing file succeeded")
	}
}

func TestPrune(t *testing.T) {
	s, _ := openTemp(t)
	now := t0
	old := now.Add(-31 * 24 * time.Hour)
	recent := now.Add(-time.Hour)

	oldW, _ := s.BeginWatch(old, "14.2", time.Second)
	newW, _ := s.BeginWatch(recent, "14.2", time.Second)
	oldSess, _ := s.EnsureSession("claude-code", "_old_SBX", old)
	keepSess, _ := s.EnsureSession("claude-code", "_keep_SBX", recent)

	oldRun, _ := s.InsertRun(Run{WatchID: oldW, Kind: "sandbox-exec", SessionID: &oldSess, StartedAt: old, ProfileSource: "inline", ProfileText: "old profile"})
	newRun, _ := s.InsertRun(Run{WatchID: newW, Kind: "sandbox-exec", SessionID: &keepSess, StartedAt: recent, ProfileSource: "inline", ProfileText: "new profile"})
	child, _ := s.InsertRun(Run{WatchID: newW, Kind: "sandbox-exec", ParentRunID: &oldRun, StartedAt: recent, ProfileSource: "unknown"})
	op, _ := s.InsertProcess(Process{RunID: oldRun, PID: 1})
	np, _ := s.InsertProcess(Process{RunID: newRun, PID: 2})
	if _, err := s.InsertDenial(Denial{RunID: oldRun, ProcessID: op, Time: old, ProcessName: "a", PID: 1, Operation: "o", Count: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertDenial(Denial{RunID: newRun, ProcessID: np, Time: recent, ProcessName: "b", PID: 2, Operation: "o", Count: 1}); err != nil {
		t.Fatal(err)
	}
	s.InsertOrphan(Orphan{WatchID: oldW, Time: old, ProcessName: "x", PID: 3, Operation: "o", Count: 1})
	s.InsertOrphan(Orphan{WatchID: newW, Time: recent, ProcessName: "y", PID: 4, Operation: "o", Count: 1})

	st, err := s.Prune(now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if st.Runs != 1 || st.Orphans != 1 {
		t.Errorf("stats = %+v", st)
	}
	checks := []struct {
		q    string
		want int
	}{
		{`SELECT count(*) FROM runs`, 2},
		{`SELECT count(*) FROM processes`, 1},
		{`SELECT count(*) FROM denials`, 1},
		{`SELECT count(*) FROM orphans`, 1},
		{`SELECT count(*) FROM watches`, 1},
		{`SELECT count(*) FROM sessions`, 1},
		{`SELECT count(*) FROM profiles`, 1},
		{`SELECT count(*) FROM runs WHERE parent_run_id IS NULL`, 2},
	}
	for _, c := range checks {
		if n := count(t, s, c.q); n != c.want {
			t.Errorf("%s = %d, want %d", c.q, n, c.want)
		}
	}
	_ = child
}
