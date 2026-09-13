package correlate

import (
	"fmt"

	"buckle/internal/sbx"
	"buckle/internal/store"
)

// eligible reports whether img may be a sandbox_init() user (DESIGN §4.4): its exec was seen
// during this watch and it is not a platform binary, or it was forked (no exec) from such an image.
func eligible(img *image) bool {
	for ; img != nil; img = img.parent {
		if img.noToken || img.proc.IsPlatform {
			return false
		}
		if img.execSeen {
			return true
		}
		if img.parent == nil || img.parent.proc.Path != img.proc.Path {
			return false
		}
	}
	return false
}

// candidateRun returns the sandbox-init run img belongs to, creating it after an entitlement
// check, or nil if img is not a candidate.
func (c *Correlator) candidateRun(img *image) (*run, error) {
	if !eligible(img) {
		return nil, nil
	}
	// Path from the exec'd root down to img along fork edges.
	var path []*image
	root := img
	for ; ; root = root.parent {
		path = append(path, root)
		if root.execSeen {
			break
		}
	}
	r := root.run
	if r == nil {
		key := root.proc.CDHash
		if key == "" {
			key = "path:" + root.proc.Path
		}
		appSandbox, ok := c.entCache[key]
		if !ok {
			var err error
			appSandbox, err = c.deps.Entitlements.HasAppSandbox(root.proc.Path, root.proc.CDHash)
			if err != nil {
				c.deps.Warn(fmt.Sprintf("entitlement check for %s failed (treating as not app-sandboxed): %v", root.proc.Path, err))
				appSandbox = false
			}
			c.entCache[key] = appSandbox
		}
		if appSandbox {
			return nil, nil
		}
		id, err := c.sink.InsertRun(store.Run{
			WatchID:       c.cfg.WatchID,
			Kind:          kindSandboxInit,
			StartedAt:     root.start,
			ProfileSource: string(sbx.SourceUnknown),
			Command:       root.args,
			Cwd:           root.cwd,
		})
		if err != nil {
			return nil, err
		}
		r = &run{id: id, kind: kindSandboxInit, live: map[*image]struct{}{}}
		c.runs = append(c.runs, r)
	}
	for i := len(path) - 1; i >= 0; i-- {
		if err := c.join(path[i], r); err != nil {
			return nil, err
		}
	}
	return r, c.maybeEndRun(r)
}
