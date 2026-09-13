package correlate

import (
	"database/sql"
	"io/fs"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"buckle/internal/eslog"
	"buckle/internal/store"
	"buckle/internal/testutil"
	"buckle/internal/ulog"
)

const paramProfile = "(version 1)\n(allow default)\n(deny file-write* (subpath (param \"OUT\")))\n"

func fixtureReadFile(path string) ([]byte, error) {
	if path == "/private/tmp/buckle-capture.3s465f/param.sb" {
		return []byte(paramProfile), nil
	}
	return nil, fs.ErrNotExist
}

type fakeEnts struct {
	appSandbox bool
	err        error
	calls      int
}

func (f *fakeEnts) HasAppSandbox(path, cdhash string) (bool, error) {
	f.calls++
	return f.appSandbox, f.err
}

// replay feeds items through a fresh correlator backed by a temp DB and shuts it down.
func replay(t *testing.T, items []testutil.Item, deps Deps) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "buckle.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	start := items[0].Time
	w, err := s.BeginWatch(start, "14.2", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c := New(Config{WatchID: w, WatchStart: start, Buffer: 5 * time.Second}, s, deps)
	for _, it := range items {
		if it.ES != nil {
			err = c.HandleES(*it.ES)
		} else {
			err = c.HandleDenial(*it.Denial, it.Time)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Tick(it.Time); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Shutdown(items[len(items)-1].Time.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	return s
}

func queryInt(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n sql.NullInt64
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return int(n.Int64)
}

type runRow struct {
	id                                  int64
	kind, status, source                string
	name, path, perr, hash, tagCmd, tag sql.NullString
	params, command                     string
	sessionID, parentRun, endedAt       sql.NullInt64
	beforeWatch                         int
}

func runByCommand(t *testing.T, db *sql.DB, command string) runRow {
	t.Helper()
	var r runRow
	err := db.QueryRow(`SELECT id, kind, status, profile_source, profile_name, profile_path, profile_error, profile_hash,
		tag_command, tag, params_json, command_json, session_id, parent_run_id, ended_at, started_before_watch
		FROM runs WHERE command_json = ?`, command).
		Scan(&r.id, &r.kind, &r.status, &r.source, &r.name, &r.path, &r.perr, &r.hash, &r.tagCmd, &r.tag,
			&r.params, &r.command, &r.sessionID, &r.parentRun, &r.endedAt, &r.beforeWatch)
	if err != nil {
		t.Fatalf("run %s: %v", command, err)
	}
	return r
}

func processID(t *testing.T, db *sql.DB, runID int64, pid, pidversion int) int64 {
	t.Helper()
	return int64(queryInt(t, db, `SELECT id FROM processes WHERE run_id = ? AND pid = ? AND pidversion = ?`, runID, pid, pidversion))
}

const fixtureTag = "CMD64_Y2F0IC9ldGMvaG9zdHMgfCBoZWFkIC0x_END__k3j9x0q2m_SBX"

func TestReplayFixture(t *testing.T) {
	items := testutil.LoadFixture(t, testutil.FixtureDir(t, "macos14.2"))
	s := replay(t, items, Deps{ReadFile: fixtureReadFile, Entitlements: &fakeEnts{}})
	db := s.DB

	if n := queryInt(t, db, `SELECT count(*) FROM runs WHERE kind = 'sandbox-exec'`); n != 6 {
		t.Errorf("sandbox-exec runs = %d, want 6", n)
	}
	if n := queryInt(t, db, `SELECT count(*) FROM runs`); n != 7 {
		t.Errorf("runs = %d, want 7", n)
	}
	if n := queryInt(t, db, `SELECT count(*) FROM runs WHERE kind = 'sandbox-exec' AND (status != 'exited' OR ended_at IS NULL)`); n != 0 {
		t.Errorf("%d sandbox-exec runs not exited", n)
	}
	if n := queryInt(t, db, `SELECT count(*) FROM profiles`); n != 3 {
		t.Errorf("profiles = %d, want 3 (p_single and dup share text)", n)
	}
	if n := queryInt(t, db, `SELECT count(*) FROM sessions`); n != 1 {
		t.Errorf("sessions = %d, want 1", n)
	}

	// p_single
	r := runByCommand(t, db, `["/bin/cat","/etc/hosts"]`)
	if r.source != "inline" || !r.hash.Valid || r.sessionID.Valid {
		t.Errorf("p_single run = %+v", r)
	}
	if n := queryInt(t, db, `SELECT count(*) FROM processes WHERE run_id = ?`, r.id); n != 2 {
		t.Errorf("p_single processes = %d, want 2", n)
	}
	cat := processID(t, db, r.id, 15505, 34600)
	if n := queryInt(t, db, `SELECT count(*) FROM denials WHERE run_id = ? AND process_id = ? AND operation = 'file-read-data' AND target = '/private/etc/hosts' AND count = 1`, r.id, cat); n != 1 {
		t.Errorf("p_single denial on cat image missing")
	}
	sbxRow := processID(t, db, r.id, 15505, 34597)
	if got := queryInt(t, db, `SELECT exec_prev_process_id FROM processes WHERE id = ?`, cat); int64(got) != sbxRow {
		t.Errorf("cat exec_prev = %d, want %d", got, sbxRow)
	}
	if n := queryInt(t, db, `SELECT count(*) FROM processes WHERE id = ? AND end_reason = 'exec'`, sbxRow); n != 1 {
		t.Error("sandbox-exec image should end by exec")
	}
	if n := queryInt(t, db, `SELECT count(*) FROM processes WHERE id = ? AND end_reason = 'exit' AND exit_status = 256 AND is_platform_binary = 1`, cat); n != 1 {
		t.Error("cat image should end by exit 256")
	}

	// f_param
	r = runByCommand(t, db, `["/usr/bin/touch","/private/tmp/buckle_capture_probe"]`)
	if r.source != "file" || r.params != `[["OUT","/private/tmp"]]` || r.path.String != "/private/tmp/buckle-capture.3s465f/param.sb" || !r.hash.Valid || r.perr.Valid {
		t.Errorf("f_param run = %+v", r)
	}
	if n := queryInt(t, db, `SELECT count(*) FROM denials WHERE run_id = ? AND operation = 'file-write-create'`, r.id); n != 1 {
		t.Error("f_param denial missing")
	}

	// f_unreadable
	r = runByCommand(t, db, `["/usr/bin/true"]`)
	if r.source != "file" || r.hash.Valid || !r.perr.Valid {
		t.Errorf("f_unreadable run = %+v", r)
	}

	// n_named
	r = runByCommand(t, db, `["/usr/bin/curl","-s","-m","2","http://1.1.1.1/"]`)
	if r.source != "named" || r.name.String != "no-network" || r.hash.Valid {
		t.Errorf("n_named run = %+v", r)
	}
	if n := queryInt(t, db, `SELECT count(*) FROM denials WHERE run_id = ? AND operation = 'network-outbound'`, r.id); n != 2 {
		t.Errorf("n_named denials = %d, want 2", n)
	}

	// tagged_tree
	tagged := runByCommand(t, db, `["/bin/sh","-c","cat /etc/hosts | head -1; (cat /etc/hosts &); wait"]`)
	if tagged.tagCmd.String != "cat /etc/hosts | head -1" || tagged.tag.String != fixtureTag || !tagged.sessionID.Valid {
		t.Errorf("tagged run = %+v", tagged)
	}
	if key := queryInt(t, db, `SELECT count(*) FROM sessions WHERE id = ? AND kind = 'claude-code' AND key = '_k3j9x0q2m_SBX'`, tagged.sessionID.Int64); key != 1 {
		t.Error("tagged run session key wrong")
	}
	if n := queryInt(t, db, `SELECT count(*) FROM processes WHERE run_id = ?`, tagged.id); n != 10 {
		t.Errorf("tagged processes = %d, want 10", n)
	}
	sh := processID(t, db, tagged.id, 15527, 34647)
	bash := processID(t, db, tagged.id, 15527, 34648)
	if got := queryInt(t, db, `SELECT exec_prev_process_id FROM processes WHERE id = ?`, bash); int64(got) != sh {
		t.Errorf("bash exec_prev = %d, want sh %d", got, sh)
	}
	forked := processID(t, db, tagged.id, 15528, 34649)
	if got := queryInt(t, db, `SELECT parent_process_id FROM processes WHERE id = ?`, forked); int64(got) != bash {
		t.Errorf("fork child parent = %d, want bash %d", got, bash)
	}
	bgCat := processID(t, db, tagged.id, 15531, 34655)
	if n := queryInt(t, db, `SELECT count(*) FROM denials WHERE run_id = ? AND message = ?`, tagged.id, fixtureTag); n != 2 {
		t.Errorf("tagged denials = %d, want 2", n)
	}
	if n := queryInt(t, db, `SELECT count(*) FROM denials WHERE process_id = ?`, bgCat); n != 1 {
		t.Error("reparented background cat denial not attributed")
	}

	// dup
	r = runByCommand(t, db, `["/bin/sh","-c","for i in $(seq 1 40); do : </etc/hosts; done 2>/dev/null"]`)
	if n := queryInt(t, db, `SELECT count(*) FROM processes WHERE run_id = ?`, r.id); n != 6 {
		t.Errorf("dup processes = %d, want 6", n)
	}
	if n := queryInt(t, db, `SELECT count(*) FROM denials WHERE run_id = ? AND process_id = ?`, r.id, processID(t, db, r.id, 15536, 34667)); n != 1 {
		t.Error("dup bash denial missing")
	}

	// preexisting → adopted
	var adoptedID, beforeWatch int64
	var status string
	var endedAt, sessionID sql.NullInt64
	if err := db.QueryRow(`SELECT id, started_before_watch, status, ended_at, session_id FROM runs WHERE kind = 'adopted'`).
		Scan(&adoptedID, &beforeWatch, &status, &endedAt, &sessionID); err != nil {
		t.Fatal(err)
	}
	if beforeWatch != 1 || status != "watch_stopped" || endedAt.Valid || sessionID.Int64 != tagged.sessionID.Int64 {
		t.Errorf("adopted run: before=%d status=%s ended=%v session=%v", beforeWatch, status, endedAt, sessionID)
	}
	adoptedCat := processID(t, db, adoptedID, 15571, 34760)
	if n := queryInt(t, db, `SELECT count(*) FROM denials WHERE run_id = ? AND process_id = ?`, adoptedID, adoptedCat); n != 1 {
		t.Error("adopted denial missing")
	}

	// Every stored process belongs to a run and every denial to a workload pid.
	if n := queryInt(t, db, `SELECT count(*) FROM denials WHERE pid NOT IN (15505, 15511, 15522, 15528, 15531, 15536, 15571)`); n != 0 {
		t.Errorf("%d non-workload denials stored", n)
	}

	// Orphans: exactly the non-workload denials whose pid appeared in an exec/fork event.
	seen := map[int]bool{}
	for _, it := range items {
		if it.ES != nil && it.ES.Kind != eslog.KindExit {
			seen[it.ES.Process.Token.PID] = true
			seen[it.ES.Target.Token.PID] = true
		}
	}
	want := map[int]bool{}
	for _, it := range items {
		if d := it.Denial; d != nil && seen[d.PID] && !map[int]bool{15505: true, 15511: true, 15522: true, 15528: true, 15531: true, 15536: true, 15571: true}[d.PID] {
			want[d.PID] = true
		}
	}
	got := map[int]bool{}
	rows, err := db.Query(`SELECT DISTINCT pid FROM orphans`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var pid int
		rows.Scan(&pid)
		got[pid] = true
	}
	rows.Close()
	if !equalSets(got, want) {
		t.Errorf("orphan pids = %v, want %v", keys(got), keys(want))
	}
}

func TestReplaySandboxInitCandidate(t *testing.T) {
	items := testutil.LoadFixture(t, testutil.FixtureDir(t, "macos14.2"))
	var execTime time.Time
	for _, it := range items {
		if it.ES != nil && it.ES.Kind == eslog.KindExec && it.ES.Target.Token.PID == 15543 {
			execTime = it.ES.Time
		}
	}
	if execTime.IsZero() {
		t.Fatal("sbinit exec not in fixture")
	}
	d := ulog.Denial{Time: execTime.Add(time.Millisecond), Name: "sbinit", PID: 15543, DenyN: 1,
		Operation: "file-write-create", Target: "/private/tmp/buckle_sbinit_probe"}
	items = append(items, testutil.Item{Time: d.Time, Denial: &d})
	sort.SliceStable(items, func(i, j int) bool { return items[i].Time.Before(items[j].Time) })

	ents := &fakeEnts{}
	s := replay(t, items, Deps{ReadFile: fixtureReadFile, Entitlements: ents})
	r := runByCommand(t, s.DB, `["/private/tmp/buckle-capture.3s465f/sbinit"]`)
	if r.kind != "sandbox-init" || r.source != "unknown" || r.status != "exited" {
		t.Errorf("sbinit run = %+v", r)
	}
	if n := queryInt(t, s.DB, `SELECT count(*) FROM denials WHERE run_id = ? AND pid = 15543`, r.id); n != 1 {
		t.Error("sbinit denial not attributed")
	}
	if n := queryInt(t, s.DB, `SELECT count(*) FROM processes WHERE run_id = ? AND is_platform_binary = 0`, r.id); n != 1 {
		t.Error("sbinit process row should be non-platform")
	}
	if ents.calls != 1 {
		t.Errorf("entitlement checks = %d, want 1", ents.calls)
	}
}

func equalSets(a, b map[int]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func keys(m map[int]bool) []int {
	var out []int
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
