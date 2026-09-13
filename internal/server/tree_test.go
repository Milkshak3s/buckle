package server

import (
	"fmt"
	"strings"
	"testing"

	"buckle/internal/serverdb"
)

func i64(n int64) *int64 { return &n }

// proc builds a process row. parent and prev are process row ids (0 for none); start is ns (0 for
// unknown).
func proc(id, pid int64, path string, parent, prev, start int64) serverdb.Process {
	p := serverdb.Process{ID: id, PID: pid, Path: path, ArgsJSON: `["` + path + `"]`}
	if parent != 0 {
		p.ParentProcessID = i64(parent)
	}
	if prev != 0 {
		p.ExecPrevProcessID = i64(prev)
	}
	if start != 0 {
		p.StartedAt = i64(start)
	}
	return p
}

// shape renders a node as "path→path{denials}[fork](child, child)" for compact comparison.
func shape(n *treeNode) string {
	var b strings.Builder
	for i, im := range n.Images {
		if i > 0 {
			b.WriteString("→")
		}
		b.WriteString(im.Process.Path)
	}
	if n.Denials > 0 {
		fmt.Fprintf(&b, "{%d}", n.Denials)
	}
	if n.ForkOnly {
		b.WriteString("[fork]")
	}
	if len(n.Children) > 0 {
		cs := make([]string, len(n.Children))
		for i, c := range n.Children {
			cs[i] = shape(c)
		}
		b.WriteString("(" + strings.Join(cs, ", ") + ")")
	}
	return b.String()
}

func treeShape(t procTree) (root string, unrecorded []string) {
	if t.Root != nil {
		root = shape(t.Root)
	}
	for _, n := range t.Unrecorded {
		unrecorded = append(unrecorded, shape(n))
	}
	return root, unrecorded
}

func TestProcessTreeCollapsesExecChainPerPid(t *testing.T) {
	d := serverdb.RunDetail{Processes: []serverdb.Process{
		proc(1, 100, "sandbox-exec", 0, 0, 10),
		proc(2, 100, "sh", 0, 1, 20),
		proc(3, 101, "sh", 2, 0, 30), // forked by sh
		proc(4, 100, "bash", 0, 2, 40),
		proc(5, 102, "bash", 4, 0, 50), // forked by bash, after the exec
		proc(6, 102, "cat", 4, 5, 60),
	}}
	root, unrec := treeShape(processTree(d))
	if want := "sandbox-exec→sh→bash(sh[fork], bash→cat)"; root != want {
		t.Errorf("root = %s\nwant %s", root, want)
	}
	if len(unrec) != 0 {
		t.Errorf("unrecorded = %v, want none", unrec)
	}
	tr := processTree(d)
	if tr.Root == nil {
		t.Fatal("no root")
	}
	if got := tr.Root.Args.Text; got != "bash" {
		t.Errorf("root args = %q, want final image's %q", got, "bash")
	}
	if len(tr.Root.Images) != 3 || tr.Root.Images[0].Args.Text != "sandbox-exec" {
		t.Errorf("root images lack per-image args: %+v", tr.Root.Images)
	}
}

func TestProcessTreeSeparatesReusedPid(t *testing.T) {
	d := serverdb.RunDetail{Processes: []serverdb.Process{
		proc(1, 100, "zsh", 0, 0, 10),
		proc(2, 200, "zsh", 1, 0, 20),
		proc(3, 200, "ls", 1, 2, 25),
		proc(4, 200, "zsh", 1, 0, 30), // pid 200 reused by a later fork
		proc(5, 200, "cat", 1, 4, 35),
	}}
	if root, _ := treeShape(processTree(d)); root != "zsh(zsh→ls, zsh→cat)" {
		t.Errorf("root = %s", root)
	}
}

func TestProcessTreeOrdersSiblingsByStartTime(t *testing.T) {
	d := serverdb.RunDetail{Processes: []serverdb.Process{
		proc(1, 100, "zsh", 0, 0, 10),
		proc(2, 101, "untimed-a", 1, 0, 0),
		proc(3, 102, "late", 1, 0, 90),
		proc(4, 103, "early", 1, 0, 20),
		proc(5, 104, "untimed-b", 1, 0, 0),
	}}
	root, _ := treeShape(processTree(d))
	if want := "zsh(early[fork], late[fork], untimed-a[fork], untimed-b[fork])"; root != want {
		t.Errorf("root = %s\nwant %s", root, want)
	}
}

func TestProcessTreeRootIsEarliestParentless(t *testing.T) {
	d := serverdb.RunDetail{Processes: []serverdb.Process{
		proc(1, 300, "adopted-late", 0, 0, 50),
		proc(2, 100, "sandbox-exec", 0, 0, 10),
		proc(3, 400, "untimed", 0, 0, 0),
		proc(4, 500, "orphan-child", 99, 0, 60), // parent row not in this run
		proc(5, 101, "child", 2, 0, 20),
		proc(6, 600, "exec-of-missing", 7, 98, 70), // previous image not in this run
	}}
	root, unrec := treeShape(processTree(d))
	if want := "sandbox-exec(child[fork])"; root != want {
		t.Errorf("root = %s\nwant %s", root, want)
	}
	want := []string{"adopted-late", "orphan-child[fork]", "exec-of-missing", "untimed"}
	if fmt.Sprint(unrec) != fmt.Sprint(want) {
		t.Errorf("unrecorded = %v\nwant %v", unrec, want)
	}
}

func TestProcessTreeRootTieBreaksOnRowID(t *testing.T) {
	d := serverdb.RunDetail{Processes: []serverdb.Process{
		proc(1, 100, "first", 0, 0, 0),
		proc(2, 200, "second", 0, 0, 0),
	}}
	root, unrec := treeShape(processTree(d))
	if root != "first" || fmt.Sprint(unrec) != "[second]" {
		t.Errorf("root = %s, unrecorded = %v", root, unrec)
	}
}

func TestProcessTreeSumsDenialsAcrossImages(t *testing.T) {
	d := serverdb.RunDetail{
		Processes: []serverdb.Process{
			proc(1, 100, "sh", 0, 0, 10),
			proc(2, 100, "bash", 0, 1, 20),
			proc(3, 101, "cat", 2, 0, 30),
		},
		Denials: []serverdb.Denial{
			{ID: 1, ProcessID: 1, Count: 2},
			{ID: 2, ProcessID: 2, Count: 3},
			{ID: 3, ProcessID: 3, Count: 1},
			{ID: 4, ProcessID: 42, Count: 7}, // process not in this run: ignored
		},
	}
	if root, _ := treeShape(processTree(d)); root != "sh→bash{5}(cat{1}[fork])" {
		t.Errorf("root = %s", root)
	}
}

func TestProcessTreeEndIsFinalImages(t *testing.T) {
	ended := func(p serverdb.Process, reason string, status *int64) serverdb.Process {
		p.EndReason, p.ExitStatus = reason, status
		return p
	}
	d := serverdb.RunDetail{Processes: []serverdb.Process{
		ended(proc(1, 100, "sh", 0, 0, 10), "exec", nil),
		ended(proc(2, 100, "bash", 0, 1, 20), "exit", i64(3)),
		ended(proc(3, 101, "a", 2, 0, 30), "exit", nil),
		ended(proc(4, 102, "b", 2, 0, 40), "watch_stopped", nil),
		proc(5, 103, "c", 2, 0, 50),
		ended(proc(6, 104, "d", 2, 0, 60), "exec", nil), // next image joined another run
	}}
	tr := processTree(d)
	if tr.Root == nil {
		t.Fatal("no root")
	}
	got := []string{tr.Root.End}
	for _, c := range tr.Root.Children {
		got = append(got, c.End)
	}
	want := []string{"exit (status 3)", "exit", "watch stopped, end unknown", "running", "exec'd, next image not in this run"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("ends = %q\nwant %q", got, want)
	}
}

func TestProcessTreeEmpty(t *testing.T) {
	tr := processTree(serverdb.RunDetail{})
	if tr.Root != nil || len(tr.Unrecorded) != 0 {
		t.Errorf("tree = %+v, want empty", tr)
	}
}

func TestProcessTreeIgnoresForwardLinks(t *testing.T) {
	// Links always point at earlier rows; a malformed forward or self link must not form a cycle.
	d := serverdb.RunDetail{Processes: []serverdb.Process{
		proc(1, 100, "a", 2, 0, 10),
		proc(2, 101, "b", 1, 0, 20),
		proc(3, 102, "c", 3, 3, 30),
	}}
	root, unrec := treeShape(processTree(d))
	if root != "a[fork](b[fork])" || fmt.Sprint(unrec) != "[c]" {
		t.Errorf("root = %s, unrecorded = %v", root, unrec)
	}
}
