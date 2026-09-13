package correlate

import (
	"strings"
	"testing"

	"buckle/internal/eslog"
)

// A non-platform launcher (like Claude Code) forks a child that execs sandbox-exec, but eslogger
// is running more than the buffer window behind the log stream. The denial must wait for the
// exec events instead of turning the launcher into a sandbox_init candidate.
func TestLaggingESDoesNotCreateCandidate(t *testing.T) {
	ents := &fakeEnts{}
	h := newHarness(t, ents)
	pre := proc(1000, 1, "/bin/zsh", true)
	launcher := eslog.Proc{Token: eslog.Token{PID: 1000, PIDVersion: 2}, Path: "/opt/claude", CDHash: "CC"}
	h.fork(ms(0), shell, pre)
	h.exec(ms(1), pre, launcher, "/opt/claude")
	child := eslog.Proc{Token: eslog.Token{PID: 1001, PIDVersion: 3}, Path: "/opt/claude", CDHash: "CC"}
	h.fork(ms(2), launcher, child)
	h.deny(ms(10), ms(10), 1001, "/x", "", 0)
	h.tick(ms(5100)) // buffer window over, eslogger still behind the denial
	sbxImg := proc(1001, 4, "/usr/bin/sandbox-exec", true)
	sh := proc(1001, 5, "/bin/sh", true)
	h.exec(ms(3), child, sbxImg, "/usr/bin/sandbox-exec", "-p", "(version 1)", "/bin/sh")
	h.exec(ms(4), sbxImg, sh, "/bin/sh")
	h.settle(ms(6000))

	if n := h.n(`SELECT count(*) FROM runs WHERE kind = 'sandbox-init'`); n != 0 {
		t.Errorf("sandbox-init runs = %d, want 0", n)
	}
	if n := h.n(`SELECT count(*) FROM denials d JOIN runs r ON r.id = d.run_id WHERE r.kind = 'sandbox-exec'`); n != 1 {
		t.Errorf("denials in the sandbox-exec run = %d, want 1", n)
	}
	if ents.calls != 0 {
		t.Errorf("entitlement checks = %d, want 0", ents.calls)
	}
}

// Tagged variant: the lag must not produce a bogus adopted "started before watch" run.
func TestLaggingESDoesNotAdopt(t *testing.T) {
	h := newHarness(t, nil)
	child := proc(1101, 3, "/bin/zsh", true)
	h.fork(ms(0), shell, child)
	tag := "CMD64_bHM=_END__abc_SBX"
	h.deny(ms(10), ms(10), 1101, "/x", tag, 0)
	h.tick(ms(5100))
	sbxImg := proc(1101, 4, "/usr/bin/sandbox-exec", true)
	cat := proc(1101, 5, "/bin/cat", true)
	h.exec(ms(3), child, sbxImg, "/usr/bin/sandbox-exec", "-p", "(version 1) ; LogTag: "+tag, "/bin/cat")
	h.exec(ms(4), sbxImg, cat, "/bin/cat")
	h.settle(ms(6000))

	if n := h.n(`SELECT count(*) FROM runs WHERE kind = 'adopted'`); n != 0 {
		t.Errorf("adopted runs = %d, want 0", n)
	}
	if n := h.n(`SELECT count(*) FROM denials d JOIN runs r ON r.id = d.run_id WHERE r.kind = 'sandbox-exec'`); n != 1 {
		t.Errorf("denials in the sandbox-exec run = %d, want 1", n)
	}
}

// If eslogger never catches up, denials are eventually finalized, but without the guesses
// (adoption, candidates) that depend on complete process events.
func TestLagCapFallsBackToOrphan(t *testing.T) {
	ents := &fakeEnts{}
	h := newHarness(t, ents)
	pre := proc(1200, 1, "/bin/zsh", true)
	launcher := eslog.Proc{Token: eslog.Token{PID: 1200, PIDVersion: 2}, Path: "/opt/claude", CDHash: "CC"}
	h.fork(ms(0), shell, pre)
	h.exec(ms(1), pre, launcher, "/opt/claude")
	h.fork(ms(2), launcher, eslog.Proc{Token: eslog.Token{PID: 1201, PIDVersion: 3}, Path: "/opt/claude", CDHash: "CC"})
	h.fork(ms(2), launcher, eslog.Proc{Token: eslog.Token{PID: 1202, PIDVersion: 4}, Path: "/opt/claude", CDHash: "CC"})
	h.deny(ms(10), ms(10), 1201, "/x", "", 0)
	h.deny(ms(10), ms(10), 1202, "/y", "CMD64_bHM=_END__abc_SBX", 0)

	h.tick(ms(49_000))
	if len(h.c.pendingByPID) != 2 {
		t.Fatalf("pending pids = %d, want 2 before the lag cap", len(h.c.pendingByPID))
	}
	h.tick(ms(50_010))
	if len(h.c.pendingByPID) != 0 {
		t.Fatal("denials not finalized at the lag cap")
	}
	if n := h.n(`SELECT count(*) FROM runs`); n != 0 {
		t.Errorf("runs = %d, want 0 (no candidate or adoption without process events)", n)
	}
	if n := h.n(`SELECT count(*) FROM orphans`); n != 2 {
		t.Errorf("orphans = %d, want 2", n)
	}
	if ents.calls != 0 {
		t.Errorf("entitlement checks = %d, want 0", ents.calls)
	}
	if len(h.warns) == 0 || !strings.Contains(strings.Join(h.warns, "\n"), "behind") {
		t.Errorf("warns = %v, want a lag warning", h.warns)
	}
}

// A duplicate report for a reused pid must not be added to the previous process's denial row;
// it belongs to the new process's orphan. Covers reuse before and after the old image is evicted.
func TestDuplicateAfterPIDReuseFollowsOrphan(t *testing.T) {
	for _, c := range []struct {
		name    string
		reuseAt int
	}{{"old image still retained", 10_000}, {"old image evicted", 60_000}} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, nil)
			_, _, cat := h.sandboxCat(900, 1, 0, "(version 1)")
			h.deny(ms(5), ms(5), 900, "/x", "", 0)
			h.settle(ms(30))
			h.exit(ms(40), cat, 0)
			h.fork(ms(c.reuseAt), shell, proc(900, 7, "/bin/zsh", true))
			h.deny(ms(c.reuseAt+10), ms(c.reuseAt+10), 900, "/x", "", 0)
			h.settle(ms(c.reuseAt + 6000))
			h.deny(ms(c.reuseAt+6100), ms(c.reuseAt+6100), 900, "/x", "", 5)
			h.settle(ms(c.reuseAt + 12_000))

			if n := h.n(`SELECT count FROM denials`); n != 1 {
				t.Errorf("old run's denial count = %d, want 1", n)
			}
			if n := h.n(`SELECT count(*) FROM orphans`); n != 1 {
				t.Errorf("orphan rows = %d, want 1", n)
			}
			if n := h.n(`SELECT coalesce(sum(count), 0) FROM orphans WHERE last_pidversion = 7`); n != 6 {
				t.Errorf("orphan count = %d, want 6", n)
			}
		})
	}
}

// A process that execs after a denial is still the same process: its duplicate report counts.
func TestDuplicateAfterExecStaysOnRow(t *testing.T) {
	h := newHarness(t, nil)
	_, _, cat := h.sandboxCat(950, 1, 0, "(version 1)")
	h.deny(ms(5), ms(5), 950, "/x", "", 0)
	h.settle(ms(30))
	h.exec(ms(40), cat, proc(950, 4, "/bin/ls", true), "/bin/ls")
	h.deny(ms(50), ms(50), 950, "/x", "", 2)
	h.settle(ms(80))
	if n := h.n(`SELECT count(*) FROM denials`); n != 1 {
		t.Errorf("rows = %d, want 1", n)
	}
	if n := h.n(`SELECT count FROM denials`); n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
}

// Duplicate-report bookkeeping is released along with the process images it refers to.
func TestStoredDenialsForgottenWithImages(t *testing.T) {
	h := newHarness(t, nil)
	_, _, cat := h.sandboxCat(960, 1, 0, "(version 1)")
	h.deny(ms(5), ms(5), 960, "/x", "", 0)
	h.settle(ms(30))
	h.exit(ms(40), cat, 0)
	if len(h.c.lastStored) != 1 {
		t.Fatalf("lastStored = %d, want 1", len(h.c.lastStored))
	}
	h.settle(ms(40_000))
	if len(h.c.lastStored) != 0 {
		t.Errorf("lastStored = %d after eviction, want 0", len(h.c.lastStored))
	}
}
