package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"buckle/internal/serverdb"
)

func argsJSON(t *testing.T, args ...string) string {
	t.Helper()
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNewArgsView(t *testing.T) {
	profile := strings.Repeat("(allow default)\n", 1500) // 24000 bytes, like Claude Code's profile
	long := strings.Repeat("a", 5000)
	medium := "source /Users/me/.claude/shell-snapshots/snapshot.sh && eval '" + strings.Repeat("echo hi; ", 45) + "'"

	cases := []struct {
		name, path string
		js         string
		text       string
		full       bool
	}{
		{
			name: "detached inline profile",
			path: "/usr/bin/sandbox-exec",
			js:   argsJSON(t, "/usr/bin/sandbox-exec", "-p", profile, "/bin/zsh", "-c", "echo hi"),
			text: "/usr/bin/sandbox-exec -p <inline profile, 24000 bytes: see Profile text> /bin/zsh -c 'echo hi'",
			full: true,
		},
		{
			name: "attached inline profile",
			path: "/usr/bin/sandbox-exec",
			js:   argsJSON(t, "/usr/bin/sandbox-exec", "-p"+profile, "/usr/bin/true"),
			text: "/usr/bin/sandbox-exec -p<inline profile, 24000 bytes: see Profile text> /usr/bin/true",
			full: true,
		},
		{
			name: "file profile untouched",
			path: "/usr/bin/sandbox-exec",
			js:   argsJSON(t, "/usr/bin/sandbox-exec", "-f", "/private/tmp/p.sb", "/bin/cat"),
			text: "/usr/bin/sandbox-exec -f /private/tmp/p.sb /bin/cat",
		},
		{
			name: "medium argument shown in full",
			path: "/bin/zsh",
			js:   argsJSON(t, "/bin/zsh", "-c", medium),
			text: argv(argsJSON(t, "/bin/zsh", "-c", medium)),
		},
		{
			name: "very long argument elided",
			path: "/bin/echo",
			js:   argsJSON(t, "/bin/echo", long),
			text: "/bin/echo " + strings.Repeat("a", 200) + "…<4800 more bytes>",
			full: true,
		},
		{
			name: "invalid JSON falls back to raw",
			path: "/bin/echo",
			js:   `not json`,
			text: `not json`,
		},
	}
	for _, c := range cases {
		v := newArgsView(c.path, c.js)
		if v.Text != c.text {
			t.Errorf("%s: Text = %q\nwant %q", c.name, v.Text, c.text)
		}
		if c.full != (v.Full != "") {
			t.Errorf("%s: Full set = %v, want %v", c.name, v.Full != "", c.full)
		}
		if c.full && v.Full != argv(c.js) {
			t.Errorf("%s: Full is not the complete quoted argv", c.name)
		}
	}
}

func i64(n int64) *int64 { return &n }

func TestSpan(t *testing.T) {
	const start = int64(1_789_334_604_482_000_000)
	cases := []struct {
		name       string
		start, end any
		want       string
	}{
		{"milliseconds", start, i64(start + 44_000_000), "44 ms"},
		{"zero length", start, i64(start), "0 ms"},
		{"just under a second", start, i64(start + 999_999_999), "999 ms"},
		{"seconds keep one decimal", start, start + 5_420_000_000, "5.4 s"},
		{"seconds never round up to a minute", start, start + 59_960_000_000, "59.9 s"},
		{"one minute", start, start + 60_000_000_000, "1m 00s"},
		{"minutes", start, start + 1_113_276_000_000, "18m 33s"},
		{"hours", start, start + 3_725_000_000_000, "1h 02m"},
		{"end not recorded", start, (*int64)(nil), "unknown"},
		{"start not recorded", int64(0), i64(start), "unknown"},
		{"end before start", start, start - 1, "unknown"},
	}
	for _, c := range cases {
		if got := span(c.start, c.end); got != c.want {
			t.Errorf("%s: span = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestStamp(t *testing.T) {
	pdt := time.FixedZone("PDT", -7*3600)
	const ns = int64(1_789_334_604_482_000_000) // run 5's start
	cases := []struct {
		name       string
		v          any
		utc, local string
	}{
		{"int64", ns, "2026-09-13 21:23:24.482 UTC", "14:23:24.482 PDT"},
		{"pointer", i64(ns), "2026-09-13 21:23:24.482 UTC", "14:23:24.482 PDT"},
		{"zero", int64(0), "unknown", ""},
		{"nil pointer", (*int64)(nil), "unknown", ""},
	}
	for _, c := range cases {
		if utc, local := stamp(c.v, pdt); utc != c.utc || local != c.local {
			t.Errorf("%s: stamp = %q, %q; want %q, %q", c.name, utc, local, c.utc, c.local)
		}
	}
}

func TestDenialClass(t *testing.T) {
	for n, want := range map[int64]string{0: "", 1: "warn", 19: "warn", 20: "hot", 69: "hot"} {
		if got := denialClass(n); got != want {
			t.Errorf("denialClass(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestTotals(t *testing.T) {
	runs := []serverdb.RunSummary{
		{ID: 2, ProcessCount: 5, DenialCount: 1},
		{ID: 6, ProcessCount: 5, DenialCount: 69},
		{ID: 7, ProcessCount: 6, DenialCount: 0},
	}
	if p, d := runTotals(runs); p != 16 || d != 70 {
		t.Errorf("runTotals = %d processes, %d denials; want 16, 70", p, d)
	}
	denials := []serverdb.Denial{{ID: 1, Count: 1}, {ID: 2, Count: 3}}
	if got := denialTotal(denials); got != 4 {
		t.Errorf("denialTotal = %d, want 4", got)
	}
}

func TestTimelineKinds(t *testing.T) {
	d := serverdb.RunDetail{
		Processes: []serverdb.Process{
			{ID: 1, PID: 100, Path: "/usr/bin/sandbox-exec", ArgsJSON: "[]", StartedAt: i64(10), EndedAt: i64(60), EndReason: "exit", ExitStatus: i64(0)},
			{ID: 2, PID: 101, Path: "/bin/zsh", ArgsJSON: "[]", ParentProcessID: i64(1), StartedAt: i64(20), EndReason: "watch_stopped"},
			{ID: 3, PID: 101, Path: "/bin/sh", ArgsJSON: "[]", ParentProcessID: i64(1), ExecPrevProcessID: i64(2), StartedAt: i64(30), EndedAt: i64(50), EndReason: "exec"},
		},
		Denials: []serverdb.Denial{{ID: 1, Time: 40, PID: 101, Operation: "file-write-create", Count: 1}},
	}
	want := []struct{ kind, label string }{
		{"start", "start"},
		{"fork", "fork"},
		{"exec", "exec"},
		{"denial", "denial"},
		{"exit", "exit (status 0)"},
		{"stopped", "watch stopped, end unknown"},
	}
	es := timeline(d)
	if len(es) != len(want) {
		t.Fatalf("timeline has %d entries, want %d: %+v", len(es), len(want), es)
	}
	for i, w := range want {
		if es[i].Kind != w.kind || es[i].Label != w.label {
			t.Errorf("entry %d = %s/%q, want %s/%q", i, es[i].Kind, es[i].Label, w.kind, w.label)
		}
	}
}
