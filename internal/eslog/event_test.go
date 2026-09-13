package eslog

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

const fixture = "../../testdata/fixtures/macos14.2/es.jsonl"

func fixtureLines(t *testing.T) [][]byte {
	t.Helper()
	f, err := os.Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

// findEvent returns the first fixture event matching pred.
func findEvent(t *testing.T, pred func(Event) bool) Event {
	t.Helper()
	for _, l := range fixtureLines(t) {
		ev, err := Parse(l)
		if err != nil {
			continue
		}
		if pred(ev) {
			return ev
		}
	}
	t.Fatal("no matching fixture event")
	return Event{}
}

// findLine returns the raw fixture line whose event matches pred, decoded as a generic map.
func findLine(t *testing.T, pred func(Event) bool) map[string]any {
	t.Helper()
	for _, l := range fixtureLines(t) {
		ev, err := Parse(l)
		if err != nil || !pred(ev) {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(l, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	t.Fatal("no matching fixture line")
	return nil
}

func TestParseExecSandboxExecToCat(t *testing.T) {
	ev := findEvent(t, func(e Event) bool {
		return e.Kind == KindExec && e.Target.Token == Token{15505, 34600}
	})
	if ev.Process.Token != (Token{15505, 34597}) || ev.Process.Path != "/usr/bin/sandbox-exec" {
		t.Errorf("process = %+v", ev.Process)
	}
	tg := ev.Target
	if tg.Path != "/bin/cat" || !tg.IsPlatform || tg.CDHash != "F5E9948DBF7B7BCCA96ACD0F85C63D9999D0C211" {
		t.Errorf("target = %+v", tg)
	}
	if tg.PPID != 15504 || tg.Parent != (Token{15504, 34595}) || tg.SigningID != "com.apple.cat" || tg.TeamID != "" {
		t.Errorf("target lineage/signing = %+v", tg)
	}
	if len(ev.Args) != 2 || ev.Args[0] != "/bin/cat" || ev.Args[1] != "/etc/hosts" {
		t.Errorf("args = %q", ev.Args)
	}
	if ev.Cwd != "/Users/me/buckle" {
		t.Errorf("cwd = %q", ev.Cwd)
	}
	if ev.Time.IsZero() || ev.Time.Format("2006-01-02T15:04:05.000000") != "2026-09-13T17:08:38.775921" {
		t.Errorf("time = %v", ev.Time)
	}
	if ev.SchemaVersion != 1 {
		t.Errorf("schema = %d", ev.SchemaVersion)
	}
}

func TestParseFork(t *testing.T) {
	ev := findEvent(t, func(e Event) bool { return e.Kind == KindFork && e.Target.Token.PID == 15528 })
	if ev.Process.Token != (Token{15527, 34648}) || ev.Target.Token != (Token{15528, 34649}) {
		t.Errorf("fork = %+v -> %+v", ev.Process.Token, ev.Target.Token)
	}
	if ev.Target.Path != "/bin/bash" {
		t.Errorf("child path = %q", ev.Target.Path)
	}
}

func TestParseExit(t *testing.T) {
	ev := findEvent(t, func(e Event) bool { return e.Kind == KindExit && e.Process.Token == Token{15528, 34651} })
	if ev.ExitStatus != 256 {
		t.Errorf("exit status = %d", ev.ExitStatus)
	}
}

func TestParseNonPlatform(t *testing.T) {
	ev := findEvent(t, func(e Event) bool { return e.Kind == KindExec && e.Target.Token.PID == 15543 })
	if ev.Target.IsPlatform || ev.Target.TeamID != "" || ev.Target.Path != "/private/tmp/buckle-capture.3s465f/sbinit" {
		t.Errorf("target = %+v", ev.Target)
	}
}

func TestParseDrift(t *testing.T) {
	m := findLine(t, func(e Event) bool { return e.Kind == KindExec && e.Target.Token.PID == 15543 })
	delete(m["event"].(map[string]any)["exec"].(map[string]any)["target"].(map[string]any), "audit_token")
	b, _ := json.Marshal(m)
	_, err := Parse(b)
	var de *DriftError
	if !errors.As(err, &de) || de.Field != "event.exec.target.audit_token" {
		t.Fatalf("err = %v", err)
	}

	m = findLine(t, func(e Event) bool { return e.Kind == KindExit })
	delete(m, "time")
	b, _ = json.Marshal(m)
	if _, err := Parse(b); !errors.As(err, &de) || de.Field != "time" {
		t.Fatalf("missing time err = %v", err)
	}
}

func TestParseSkipAndGarbage(t *testing.T) {
	if _, err := Parse([]byte(`{"event":{"open":{}},"time":"2026-09-13T17:08:38.775921977Z"}`)); !errors.Is(err, ErrSkip) {
		t.Errorf("open event err = %v", err)
	}
	_, err := Parse([]byte(`not json`))
	var de *DriftError
	if err == nil || errors.Is(err, ErrSkip) || errors.As(err, &de) {
		t.Errorf("garbage err = %v", err)
	}
}

func TestParseWholeFixture(t *testing.T) {
	counts := map[Kind]int{}
	for i, l := range fixtureLines(t) {
		ev, err := Parse(l)
		if err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		counts[ev.Kind]++
	}
	if counts[KindExec] != 127 || counts[KindFork] != 89 || counts[KindExit] != 75 {
		t.Errorf("counts = %v", counts)
	}
}
