package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func proc(pid, pv int, path string) string {
	return fmt.Sprintf(`{"audit_token":{"pid":%d,"pidversion":%d},"executable":{"path":%q}}`, pid, pv, path)
}

func exec(from, to string) string {
	return fmt.Sprintf(`{"time":"2026-09-13T17:00:00Z","process":%s,"event":{"exec":{"target":%s,"args":[]}}}`, from, to)
}

func fork(parent, child string) string {
	return fmt.Sprintf(`{"time":"2026-09-13T17:00:00Z","process":%s,"event":{"fork":{"child":%s}}}`, parent, child)
}

func exit(p string) string {
	return fmt.Sprintf(`{"time":"2026-09-13T17:00:00Z","process":%s,"event":{"exit":{"stat":0}}}`, p)
}

func TestTrim(t *testing.T) {
	node := proc(10, 1, "/x/node")
	helper := proc(11, 2, "/x/cursorsandbox")
	child := proc(12, 3, "/x/cursorsandbox")
	sbx := proc(12, 4, "/usr/bin/sandbox-exec")
	zsh := proc(12, 5, "/bin/zsh")
	other := proc(20, 1, "/usr/bin/security")
	es := strings.Join([]string{
		fork(node, proc(11, 1, "/x/node")),
		exec(proc(11, 1, "/x/node"), helper), // tree starts here
		fork(helper, child),
		exec(child, sbx),
		exec(sbx, zsh),
		exec(proc(19, 1, "/bin/zsh"), other), // unrelated
		exit(zsh),
		exit(other),
		`not json`,
	}, "\n") + "\n"

	var out bytes.Buffer
	pids, err := trimES(strings.NewReader(es), &out, "cursorsandbox")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(got) != 5 {
		t.Fatalf("kept %d events, want 5 (helper exec, fork, 2 execs, exit):\n%s", len(got), out.String())
	}
	if strings.Contains(out.String(), "security") {
		t.Error("unrelated process kept")
	}
	if !pids[11] || !pids[12] || pids[20] || pids[10] {
		t.Errorf("pids = %v", pids)
	}

	log := strings.Join([]string{
		`Filtering the log data using "sender == \"Sandbox\""`,
		`{"eventMessage":"Sandbox: touch(12) deny(1) file-write-create /Users/Shared/x","timestamp":"2026-09-13 17:00:00.000000-0700","machTimestamp":1}`,
		`{"eventMessage":"Sandbox: security(20) deny(1) mach-lookup com.apple.x","timestamp":"2026-09-13 17:00:00.000000-0700","machTimestamp":2}`,
	}, "\n") + "\n"
	out.Reset()
	if err := trimLog(strings.NewReader(log), &out, pids); err != nil {
		t.Fatal(err)
	}
	if kept := strings.TrimSpace(out.String()); !strings.Contains(kept, "touch(12)") || strings.Contains(kept, "security") || strings.Contains(kept, "Filtering") {
		t.Errorf("log kept:\n%s", kept)
	}
}
