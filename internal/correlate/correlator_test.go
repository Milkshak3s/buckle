package correlate

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"buckle/internal/eslog"
	"buckle/internal/store"
	"buckle/internal/ulog"
)

var base = time.Date(2026, 9, 13, 17, 0, 0, 0, time.UTC)

func ms(n int) time.Time { return base.Add(time.Duration(n) * time.Millisecond) }

type harness struct {
	t     *testing.T
	s     *store.Store
	c     *Correlator
	warns []string
	dummy int
}

func newHarness(t *testing.T, ents EntitlementChecker) *harness {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "buckle.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	w, err := s.BeginWatch(base, "14.2", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, s: s}
	h.c = New(Config{WatchID: w, WatchStart: base, Buffer: 5 * time.Second}, s, Deps{
		ReadFile:     func(string) ([]byte, error) { return nil, errors.New("no files in tests") },
		Entitlements: ents,
		Warn:         func(m string) { h.warns = append(h.warns, m) },
	})
	return h
}

func proc(pid, pv int, path string, platform bool) eslog.Proc {
	return eslog.Proc{Token: eslog.Token{PID: pid, PIDVersion: pv}, Path: path, IsPlatform: platform, CDHash: "CD" + path}
}

func (h *harness) es(ev eslog.Event) {
	h.t.Helper()
	if err := h.c.HandleES(ev); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) fork(at time.Time, parent, child eslog.Proc) {
	h.t.Helper()
	h.es(eslog.Event{Kind: eslog.KindFork, Time: at, Process: parent, Target: child})
}

func (h *harness) exec(at time.Time, from, to eslog.Proc, args ...string) {
	h.t.Helper()
	h.es(eslog.Event{Kind: eslog.KindExec, Time: at, Process: from, Target: to, Args: args, Cwd: "/"})
}

func (h *harness) exit(at time.Time, p eslog.Proc, status int) {
	h.t.Helper()
	h.es(eslog.Event{Kind: eslog.KindExit, Time: at, Process: p, ExitStatus: status})
}

func (h *harness) deny(at, arrived time.Time, pid int, target, msg string, dup int) {
	h.t.Helper()
	d := ulog.Denial{Time: at, Name: "proc", PID: pid, DenyN: 1, Operation: "file-read-data", Target: target, Message: msg, Duplicate: dup}
	if err := h.c.HandleDenial(d, arrived); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) tick(at time.Time) {
	h.t.Helper()
	if err := h.c.Tick(at); err != nil {
		h.t.Fatal(err)
	}
}

// settle advances the eslogger watermark with an unrelated fork at `at`, then ticks.
func (h *harness) settle(at time.Time) {
	h.t.Helper()
	h.dummy++
	h.fork(at, shell, proc(60000+h.dummy, 1, "/bin/zsh", true))
	h.tick(at)
}

func (h *harness) n(q string, args ...any) int {
	h.t.Helper()
	return queryInt(h.t, h.s.DB, q, args...)
}

var (
	shell = proc(50, 1, "/bin/zsh", true)
)

// sandboxCat starts `sandbox-exec -p P /bin/cat /x` as pid with pidversions pv, pv+1, pv+2 at t0 ms.
func (h *harness) sandboxCat(pid, pv, t0 int, profile string) (child, sbxImg, cat eslog.Proc) {
	h.t.Helper()
	child = proc(pid, pv, "/bin/zsh", true)
	sbxImg = proc(pid, pv+1, "/usr/bin/sandbox-exec", true)
	cat = proc(pid, pv+2, "/bin/cat", true)
	h.fork(ms(t0), shell, child)
	h.exec(ms(t0+1), child, sbxImg, "/usr/bin/sandbox-exec", "-p", profile, "/bin/cat", "/x")
	h.exec(ms(t0+2), sbxImg, cat, "/bin/cat", "/x")
	return
}

func TestDenialBeforeExecEvent(t *testing.T) {
	h := newHarness(t, nil)
	child := proc(200, 2, "/bin/zsh", true)
	h.fork(ms(0), shell, child)
	h.deny(ms(8), ms(8), 200, "/x", "", 0) // log line beats the exec events
	if n := h.n(`SELECT count(*) FROM denials`); n != 0 {
		t.Fatal("attributed before exec was seen")
	}
	sbxImg := proc(200, 3, "/usr/bin/sandbox-exec", true)
	cat := proc(200, 4, "/bin/cat", true)
	h.exec(ms(1), child, sbxImg, "/usr/bin/sandbox-exec", "-n", "no-write", "/bin/cat", "/x")
	h.tick(ms(9))
	if n := h.n(`SELECT count(*) FROM denials`); n != 0 {
		t.Fatal("attributed before the eslogger stream caught up with the denial")
	}
	h.exec(ms(5), sbxImg, cat, "/bin/cat", "/x")
	h.exit(ms(20), cat, 256)
	h.tick(ms(21))
	if n := h.n(`SELECT count(*) FROM denials d JOIN processes p ON p.id = d.process_id WHERE p.pidversion = 4`); n != 1 {
		t.Errorf("denial not attributed to cat image after late exec")
	}
	h.tick(ms(10_000))
	if n := h.n(`SELECT count(*) FROM orphans`); n != 0 {
		t.Errorf("orphans = %d", n)
	}
}

func TestDenialAfterExit(t *testing.T) {
	h := newHarness(t, nil)
	_, _, cat := h.sandboxCat(300, 1, 0, "(version 1)")
	h.exit(ms(6), cat, 256)
	h.deny(ms(8), ms(8), 300, "/x", "", 0)
	h.settle(ms(30))
	if n := h.n(`SELECT count(*) FROM denials d JOIN processes p ON p.id = d.process_id WHERE p.pidversion = 3`); n != 1 {
		t.Error("denial just after exit not attributed")
	}
	if n := h.n(`SELECT count(*) FROM runs WHERE status = 'exited'`); n != 1 {
		t.Error("run should be exited")
	}
}

func TestPIDReuseGoesToOrphan(t *testing.T) {
	h := newHarness(t, nil)
	_, _, cat := h.sandboxCat(900, 1, 0, "(version 1)")
	h.exit(ms(10), cat, 0)
	reused := proc(900, 7, "/bin/zsh", true)
	ls := proc(900, 8, "/bin/ls", true)
	h.fork(ms(1000), shell, reused)
	h.exec(ms(1000), reused, ls, "/bin/ls")
	h.deny(ms(1500), ms(1500), 900, "/x", "", 0)
	h.tick(ms(6400))
	if n := h.n(`SELECT count(*) FROM orphans`); n != 0 {
		t.Fatal("finalized before the buffer window")
	}
	h.settle(ms(6500))
	if n := h.n(`SELECT count(*) FROM denials`); n != 0 {
		t.Error("denial attributed to the exited image of a reused pid")
	}
	if n := h.n(`SELECT count(*) FROM orphans WHERE pid = 900 AND last_pidversion = 8 AND last_path = '/bin/ls'`); n != 1 {
		t.Error("orphan with the reused pid's last image missing")
	}
}

func TestDuplicateReports(t *testing.T) {
	h := newHarness(t, nil)
	h.sandboxCat(400, 1, 0, "(version 1)")
	h.deny(ms(5), ms(5), 400, "/x", "", 0)
	h.deny(ms(6), ms(6), 400, "/x", "", 3)
	h.settle(ms(30))
	if n := h.n(`SELECT count FROM denials WHERE target = '/x'`); n != 4 {
		t.Errorf("count = %d, want 4", n)
	}
	h.deny(ms(31), ms(31), 400, "/x", "", 2) // duplicate of an already stored row
	h.deny(ms(32), ms(32), 400, "/y", "", 3)
	h.settle(ms(60))
	if n := h.n(`SELECT count FROM denials WHERE target = '/x'`); n != 6 {
		t.Errorf("count after stored duplicate = %d, want 6", n)
	}
	if n := h.n(`SELECT count FROM denials WHERE target = '/y'`); n != 3 {
		t.Errorf("duplicate without original: count = %d, want 3", n)
	}
	if n := h.n(`SELECT count(*) FROM denials`); n != 2 {
		t.Errorf("rows = %d, want 2", n)
	}
}

func TestDuplicateWhileBuffered(t *testing.T) {
	h := newHarness(t, nil)
	child := proc(410, 1, "/bin/zsh", true)
	h.fork(ms(0), shell, child)
	h.deny(ms(5), ms(5), 410, "/x", "", 0)
	h.deny(ms(6), ms(6), 410, "/x", "", 2)
	sbxImg := proc(410, 2, "/usr/bin/sandbox-exec", true)
	h.exec(ms(1), child, sbxImg, "/usr/bin/sandbox-exec", "-n", "no-write", "/bin/cat")
	h.settle(ms(30))
	if n := h.n(`SELECT count FROM denials`); n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
}

func TestUnseenUntaggedDropped(t *testing.T) {
	h := newHarness(t, nil)
	h.deny(ms(0), ms(0), 4242, "/x", "", 0)
	h.settle(ms(4900))
	if len(h.c.pendingByPID) != 1 {
		t.Fatal("dropped before the buffer window")
	}
	h.settle(ms(5000))
	if len(h.c.pendingByPID) != 0 {
		t.Fatal("not finalized after the buffer window")
	}
	if n := h.n(`SELECT (SELECT count(*) FROM orphans) + (SELECT count(*) FROM denials) + (SELECT count(*) FROM runs)`); n != 0 {
		t.Errorf("rows written for system noise: %d", n)
	}
}

func TestAdoptTaggedPreexisting(t *testing.T) {
	h := newHarness(t, nil)
	tag := "CMD64_bHM=_END__abc_SBX"
	h.deny(ms(0), ms(0), 777, "/x", tag, 0)
	h.settle(ms(5000))
	h.deny(ms(5100), ms(5100), 778, "/y", tag, 0)
	h.settle(ms(10_200))
	h.deny(ms(10_300), ms(10_300), 777, "/z", "", 0) // untagged, but pid 777 is now known to the adopted run
	h.settle(ms(15_300))

	if n := h.n(`SELECT count(*) FROM runs`); n != 1 {
		t.Fatalf("runs = %d, want 1", n)
	}
	if n := h.n(`SELECT count(*) FROM runs r JOIN sessions s ON s.id = r.session_id
		WHERE r.kind = 'adopted' AND r.started_before_watch = 1 AND r.profile_source = 'unknown' AND r.tag_command = 'ls' AND s.key = '_abc_SBX'`); n != 1 {
		t.Error("adopted run fields wrong")
	}
	if n := h.n(`SELECT count(*) FROM processes WHERE pidversion IS NULL AND is_platform_binary IS NULL`); n != 2 {
		t.Errorf("stub processes = %d, want 2", n)
	}
	if n := h.n(`SELECT count(*) FROM denials`); n != 3 {
		t.Errorf("denials = %d, want 3", n)
	}
	if err := h.c.Shutdown(ms(20_000)); err != nil {
		t.Fatal(err)
	}
	if n := h.n(`SELECT count(*) FROM runs WHERE status = 'watch_stopped' AND ended_at IS NULL`); n != 1 {
		t.Error("adopted run should end as watch_stopped")
	}
}

func TestSessionFromDenialTag(t *testing.T) {
	h := newHarness(t, nil)
	h.sandboxCat(500, 1, 0, "(version 1)(allow default)")
	if n := h.n(`SELECT count(*) FROM runs WHERE session_id IS NULL`); n != 1 {
		t.Fatal("untagged profile should have no session")
	}
	h.deny(ms(5), ms(5), 500, "/x", "CMD64_bHM=_END__xyz_SBX", 0)
	h.settle(ms(30))
	if n := h.n(`SELECT count(*) FROM runs r JOIN sessions s ON s.id = r.session_id WHERE s.key = '_xyz_SBX' AND r.tag_command = 'ls'`); n != 1 {
		t.Error("session not attached from denial tag")
	}
}

func TestShutdown(t *testing.T) {
	h := newHarness(t, nil)
	h.sandboxCat(600, 1, 0, "(version 1)")
	other := proc(601, 1, "/bin/zsh", true)
	h.fork(ms(3), shell, other)
	h.deny(ms(4), ms(4), 601, "/x", "", 0)
	if err := h.c.Shutdown(ms(100)); err != nil {
		t.Fatal(err)
	}
	if n := h.n(`SELECT count(*) FROM orphans WHERE pid = 601`); n != 1 {
		t.Error("buffered denial for a seen pid should become an orphan on shutdown")
	}
	if n := h.n(`SELECT count(*) FROM runs WHERE status = 'watch_stopped' AND ended_at IS NULL`); n != 1 {
		t.Error("live run should be watch_stopped")
	}
	if n := h.n(`SELECT count(*) FROM processes WHERE end_reason = 'watch_stopped' AND ended_at IS NULL`); n != 1 {
		t.Error("live cat image should be watch_stopped")
	}
	if n := h.n(`SELECT count(*) FROM processes WHERE end_reason = 'exec'`); n != 1 {
		t.Error("sandbox-exec image keeps its exec end")
	}
}

func TestNestedSandboxExec(t *testing.T) {
	h := newHarness(t, nil)
	_, _, cat := h.sandboxCat(700, 1, 0, "(version 1)")
	inner := proc(700, 4, "/usr/bin/sandbox-exec", true)
	h.exec(ms(3), cat, inner, "/usr/bin/sandbox-exec", "-n", "no-network", "/usr/bin/true")
	var outer, parent sql.NullInt64
	if err := h.s.DB.QueryRow(`SELECT (SELECT id FROM runs WHERE profile_source = 'inline'), (SELECT parent_run_id FROM runs WHERE profile_source = 'named')`).Scan(&outer, &parent); err != nil {
		t.Fatal(err)
	}
	if !parent.Valid || parent.Int64 != outer.Int64 {
		t.Errorf("nested run parent = %v, want %v", parent, outer)
	}
	if n := h.n(`SELECT count(*) FROM runs WHERE profile_source = 'inline' AND status = 'exited'`); n != 1 {
		t.Error("outer run should end when its last image execs into a nested sandbox")
	}
}

// Candidates (DESIGN §4.4)

func TestCandidateNonPlatform(t *testing.T) {
	ents := &fakeEnts{}
	h := newHarness(t, ents)
	pre := proc(800, 1, "/bin/zsh", true)
	tool := eslog.Proc{Token: eslog.Token{PID: 800, PIDVersion: 2}, Path: "/opt/x/tool", CDHash: "AA"}
	h.fork(ms(0), shell, pre)
	h.exec(ms(1), pre, tool, "/opt/x/tool", "-v")
	worker := eslog.Proc{Token: eslog.Token{PID: 801, PIDVersion: 3}, Path: "/opt/x/tool", CDHash: "AA"}
	h.fork(ms(2), tool, worker)
	h.deny(ms(10), ms(10), 800, "/a", "", 0)
	h.deny(ms(11), ms(11), 801, "/b", "", 0)
	h.settle(ms(6000))

	if n := h.n(`SELECT count(*) FROM runs WHERE kind = 'sandbox-init' AND command_json = '["/opt/x/tool","-v"]' AND profile_source = 'unknown' AND status = 'running'`); n != 1 {
		t.Fatalf("candidate run missing")
	}
	if n := h.n(`SELECT count(*) FROM denials`); n != 2 {
		t.Errorf("denials = %d, want 2", n)
	}
	if n := h.n(`SELECT count(*) FROM processes WHERE is_platform_binary = 0`); n != 2 {
		t.Errorf("processes = %d, want tool + worker", n)
	}
	if n := h.n(`SELECT count(*) FROM processes c JOIN processes p ON p.id = c.parent_process_id WHERE c.pid = 801 AND p.pid = 800`); n != 1 {
		t.Error("worker should be a child of tool")
	}

	other := eslog.Proc{Token: eslog.Token{PID: 850, PIDVersion: 9}, Path: "/opt/x/tool", CDHash: "AA"}
	h.fork(ms(7000), shell, proc(850, 8, "/bin/zsh", true))
	h.exec(ms(7001), proc(850, 8, "/bin/zsh", true), other, "/opt/x/tool")
	h.exit(ms(7002), other, 0)
	h.deny(ms(7002), ms(7003), 850, "/c", "", 0)
	h.settle(ms(13_000))
	if ents.calls != 1 {
		t.Errorf("entitlement checks = %d, want 1 (cached by cdhash)", ents.calls)
	}
	if n := h.n(`SELECT count(*) FROM runs WHERE kind = 'sandbox-init'`); n != 2 {
		t.Errorf("sandbox-init runs = %d, want 2", n)
	}
	if n := h.n(`SELECT count(*) FROM runs WHERE kind = 'sandbox-init' AND status = 'exited' AND ended_at IS NOT NULL`); n != 1 {
		t.Error("exited candidate run should be closed")
	}
}

func TestCandidateExclusions(t *testing.T) {
	cases := []struct {
		name      string
		ents      *fakeEnts
		platform  bool
		wantRuns  int
		wantCalls int
		wantWarn  bool
	}{
		{"platform binary", &fakeEnts{}, true, 0, 0, false},
		{"app sandbox entitlement", &fakeEnts{appSandbox: true}, false, 0, 1, false},
		{"codesign failure counts as candidate", &fakeEnts{err: errors.New("boom")}, false, 1, 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, c.ents)
			pre := proc(900, 1, "/bin/zsh", true)
			bin := eslog.Proc{Token: eslog.Token{PID: 900, PIDVersion: 2}, Path: "/opt/app", IsPlatform: c.platform, CDHash: "BB"}
			h.fork(ms(0), shell, pre)
			h.exec(ms(1), pre, bin, "/opt/app")
			h.deny(ms(5), ms(5), 900, "/x", "", 0)
			h.settle(ms(6000))
			if n := h.n(`SELECT count(*) FROM runs`); n != c.wantRuns {
				t.Errorf("runs = %d, want %d", n, c.wantRuns)
			}
			if c.wantRuns == 0 {
				if n := h.n(`SELECT count(*) FROM orphans WHERE pid = 900`); n != 1 {
					t.Error("non-candidate denial should be an orphan")
				}
			}
			if c.ents.calls != c.wantCalls {
				t.Errorf("calls = %d, want %d", c.ents.calls, c.wantCalls)
			}
			if (len(h.warns) > 0) != c.wantWarn {
				t.Errorf("warns = %v", h.warns)
			}
		})
	}
}

func TestNoCandidateBeforeBufferWindow(t *testing.T) {
	// A non-platform launcher (like Claude Code) forks a child that execs sandbox-exec. If the
	// denial arrives before the exec events, it must not be misread as a sandbox_init candidate.
	ents := &fakeEnts{}
	h := newHarness(t, ents)
	pre := proc(1000, 1, "/bin/zsh", true)
	launcher := eslog.Proc{Token: eslog.Token{PID: 1000, PIDVersion: 2}, Path: "/opt/claude", CDHash: "CC"}
	h.fork(ms(0), shell, pre)
	h.exec(ms(1), pre, launcher, "/opt/claude")
	child := eslog.Proc{Token: eslog.Token{PID: 1001, PIDVersion: 3}, Path: "/opt/claude", CDHash: "CC"}
	h.fork(ms(2), launcher, child)
	h.deny(ms(10), ms(10), 1001, "/x", "", 0)
	sbxImg := proc(1001, 4, "/usr/bin/sandbox-exec", true)
	sh := proc(1001, 5, "/bin/sh", true)
	h.exec(ms(3), child, sbxImg, "/usr/bin/sandbox-exec", "-p", "(version 1)", "/bin/sh")
	h.exec(ms(4), sbxImg, sh, "/bin/sh")
	h.settle(ms(6000))
	if n := h.n(`SELECT count(*) FROM runs WHERE kind = 'sandbox-init'`); n != 0 {
		t.Error("launcher misclassified as sandbox_init candidate")
	}
	if n := h.n(`SELECT count(*) FROM denials d JOIN runs r ON r.id = d.run_id WHERE r.kind = 'sandbox-exec'`); n != 1 {
		t.Error("denial should belong to the sandbox-exec run")
	}
	if ents.calls != 0 {
		t.Errorf("entitlement checks = %d, want 0", ents.calls)
	}
}
