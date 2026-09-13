package server

import (
	"fmt"
	"sort"

	"buckle/internal/serverdb"
)

// procTree is a run's processes arranged by fork lineage. Root is the earliest-started process with
// no parent in the run; any other parentless processes are Unrecorded.
type procTree struct {
	Root       *treeNode
	Unrecorded []*treeNode
}

// treeNode is one forked process: its first image and every image it exec'd into, in order.
type treeNode struct {
	Images   []treeImage
	Children []*treeNode // ordered by start time, untimed last
	Denials  int64       // summed over all images
	ForkOnly bool        // a fork that never exec'd, still running its parent's image
	Args     *argsView   // the final image's arguments
	End      string      // how the final image ended
}

type treeImage struct {
	Process *serverdb.Process
	Args    *argsView
}

// treeNodeView pairs a node with its run's start time for the recursive tree-node template.
type treeNodeView struct {
	N     *treeNode
	Start int64
}

func newTreeNodeView(n *treeNode, start int64) treeNodeView { return treeNodeView{N: n, Start: start} }

// link resolves a process reference to the node holding it. Only references to earlier rows count:
// buckle writes a process after its parent and previous image, and requiring this keeps malformed
// data from forming cycles.
func link(byID map[int64]*treeNode, ref *int64, self int64) (*treeNode, bool) {
	if ref == nil || *ref >= self {
		return nil, false
	}
	n, ok := byID[*ref]
	return n, ok
}

func endLabel(p *serverdb.Process) string {
	switch p.EndReason {
	case "exit":
		if p.ExitStatus != nil {
			return fmt.Sprintf("exit (status %d)", *p.ExitStatus)
		}
		return "exit"
	case "watch_stopped":
		return "watch stopped, end unknown"
	case "exec":
		return "exec'd, next image not in this run"
	case "":
		return "running"
	}
	return p.EndReason
}

// processTree groups d.Processes (in row id order) into one node per forked process and nests
// nodes under their parents. Denials count toward the node of their process; denials whose process
// isn't in the run are left out.
func processTree(d serverdb.RunDetail) procTree {
	byID := make(map[int64]*treeNode, len(d.Processes))
	var nodes []*treeNode
	for i := range d.Processes {
		p := &d.Processes[i]
		im := treeImage{Process: p, Args: newArgsView(p.Path, p.ArgsJSON)}
		if n, ok := link(byID, p.ExecPrevProcessID, p.ID); ok {
			n.Images = append(n.Images, im)
			byID[p.ID] = n
			continue
		}
		n := &treeNode{Images: []treeImage{im}}
		byID[p.ID] = n
		nodes = append(nodes, n)
	}

	var roots []*treeNode
	for _, n := range nodes {
		first, last := n.Images[0], n.Images[len(n.Images)-1]
		n.ForkOnly = len(n.Images) == 1 && first.Process.ExecPrevProcessID == nil && first.Process.ParentProcessID != nil
		n.Args, n.End = last.Args, endLabel(last.Process)
		if parent, ok := link(byID, first.Process.ParentProcessID, first.Process.ID); ok {
			parent.Children = append(parent.Children, n)
		} else {
			roots = append(roots, n)
		}
	}
	for _, dn := range d.Denials {
		if n, ok := byID[dn.ProcessID]; ok {
			n.Denials += dn.Count
		}
	}

	for _, n := range nodes {
		sortNodes(n.Children)
	}
	sortNodes(roots)
	var t procTree
	if len(roots) > 0 {
		t.Root, t.Unrecorded = roots[0], roots[1:]
	}
	return t
}

// sortNodes orders nodes by their first image's start time, untimed last, then by row id.
func sortNodes(ns []*treeNode) {
	sort.SliceStable(ns, func(i, j int) bool {
		a, b := ns[i].Images[0].Process, ns[j].Images[0].Process
		switch {
		case a.StartedAt == nil && b.StartedAt == nil:
			return a.ID < b.ID
		case a.StartedAt == nil:
			return false
		case b.StartedAt == nil:
			return true
		case *a.StartedAt != *b.StartedAt:
			return *a.StartedAt < *b.StartedAt
		}
		return a.ID < b.ID
	})
}
