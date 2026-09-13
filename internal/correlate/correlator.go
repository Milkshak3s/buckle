// Package correlate joins eslogger process events with Sandbox denial logs into runs.
//
// The Correlator is single-goroutine: the watcher (or a replay test) calls HandleES,
// HandleDenial and Tick in arrival order, then Shutdown once.
package correlate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"buckle/internal/eslog"
	"buckle/internal/sbx"
	"buckle/internal/store"
	"buckle/internal/ulog"
)

// Sink receives the rows the correlator produces. *store.Store implements it.
type Sink interface {
	EnsureSession(kind, key string, t time.Time) (int64, error)
	InsertRun(r store.Run) (int64, error)
	SetRunSession(runID, sessionID int64, tag, tagCommand string) error
	EndRun(runID int64, t *time.Time, status string) error
	InsertProcess(p store.Process) (int64, error)
	EndProcess(id int64, t *time.Time, reason string, exitStatus *int) error
	InsertDenial(d store.Denial) (int64, error)
	AddDenialCount(id int64, n int) error
	InsertOrphan(o store.Orphan) (int64, error)
}

// EntitlementChecker reports whether a binary has the App Sandbox entitlement.
type EntitlementChecker interface {
	HasAppSandbox(path, cdhash string) (bool, error)
}

type Config struct {
	WatchID    int64
	WatchStart time.Time
	Buffer     time.Duration // how long an unattributed denial waits for its process events
}

type Deps struct {
	ReadFile     func(string) ([]byte, error) // default os.ReadFile
	Entitlements EntitlementChecker           // nil disables sandbox_init candidates
	Warn         func(string)                 // default: discard
}

const (
	sessionKindClaude = "claude-code"

	kindSandboxExec = "sandbox-exec"
	kindSandboxInit = "sandbox-init"
	kindAdopted     = "adopted"

	// timeSlack absorbs ordering jitter between the two sources' wall clocks.
	timeSlack = 5 * time.Millisecond
	// minRetention is how long ended process images stay resolvable.
	minRetention = 30 * time.Second
)

// image is one process image (audit token).
type image struct {
	proc       eslog.Proc
	args       []string
	cwd        string
	execSeen   bool
	noToken    bool   // adoption stub for a pid with no eslogger events; pidversion unknown
	parent     *image // fork parent
	prev       *image // image this one exec'd from
	start      time.Time
	end        *time.Time
	endReason  string
	exitStatus *int
	run        *run
	rowID      int64
}

type run struct {
	id         int64
	kind       string
	live       map[*image]struct{}
	lastEnd    time.Time
	hasSession bool
	ended      bool
}

type denialKey struct {
	pid        int
	op, target string
}

type pending struct {
	d       ulog.Denial
	count   int
	arrived time.Time
}

type seenInfo struct {
	path       string
	pidversion int
}

type Correlator struct {
	cfg  Config
	sink Sink
	deps Deps

	// esWatermark is the latest eslogger event time. A denial at t is only resolved once the
	// watermark passes t, so a burst of exec events can't be attributed half-applied.
	esWatermark time.Time

	images  map[eslog.Token]*image
	byPID   map[int][]*image // ordered by start
	seen    map[int]seenInfo // every pid in an exec/fork event this watch
	runs    []*run
	adopted map[string]*run // by raw tag

	pendingByPID map[int][]*pending
	lastPending  map[denialKey]*pending
	lastStored   map[denialKey]int64

	entCache map[string]bool
}

func New(cfg Config, sink Sink, deps Deps) *Correlator {
	if deps.ReadFile == nil {
		deps.ReadFile = os.ReadFile
	}
	if deps.Warn == nil {
		deps.Warn = func(string) {}
	}
	return &Correlator{
		cfg:          cfg,
		sink:         sink,
		deps:         deps,
		images:       map[eslog.Token]*image{},
		byPID:        map[int][]*image{},
		seen:         map[int]seenInfo{},
		adopted:      map[string]*run{},
		pendingByPID: map[int][]*pending{},
		lastPending:  map[denialKey]*pending{},
		lastStored:   map[denialKey]int64{},
		entCache:     map[string]bool{},
	}
}

// HandleES applies one exec, fork or exit event.
func (c *Correlator) HandleES(ev eslog.Event) error {
	if ev.Time.After(c.esWatermark) {
		c.esWatermark = ev.Time
	}
	switch ev.Kind {
	case eslog.KindFork:
		return c.handleFork(ev)
	case eslog.KindExec:
		return c.handleExec(ev)
	case eslog.KindExit:
		return c.handleExit(ev)
	}
	return nil
}

func (c *Correlator) handleFork(ev eslog.Event) error {
	parent := c.imageFor(ev.Process)
	c.markSeen(ev.Process)
	c.markSeen(ev.Target)
	if _, dup := c.images[ev.Target.Token]; dup {
		return nil
	}
	child := &image{proc: ev.Target, args: parent.args, cwd: parent.cwd, parent: parent, start: ev.Time}
	c.register(child)
	if parent.run != nil {
		return c.join(child, parent.run)
	}
	return nil
}

func (c *Correlator) handleExec(ev eslog.Event) error {
	actor := c.imageFor(ev.Process)
	c.markSeen(ev.Process)
	c.markSeen(ev.Target)
	if _, dup := c.images[ev.Target.Token]; dup {
		return nil
	}
	img := &image{proc: ev.Target, args: ev.Args, cwd: ev.Cwd, execSeen: true, parent: actor.parent, prev: actor, start: ev.Time}
	c.register(img)
	switch {
	case ev.Target.Path == sbx.SandboxExecPath:
		r, err := c.startSandboxExecRun(ev, actor.run)
		if err != nil {
			return err
		}
		if err := c.join(img, r); err != nil {
			return err
		}
	case actor.run != nil:
		if err := c.join(img, actor.run); err != nil {
			return err
		}
	}
	// Join the new image before ending the old one so the run never looks empty mid-exec.
	return c.endImage(actor, ev.Time, "exec", nil)
}

func (c *Correlator) handleExit(ev eslog.Event) error {
	img, ok := c.images[ev.Process.Token]
	if !ok {
		return nil
	}
	status := ev.ExitStatus
	return c.endImage(img, ev.Time, "exit", &status)
}

func (c *Correlator) startSandboxExecRun(ev eslog.Event, parent *run) (*run, error) {
	spec := sbx.ParseArgs(ev.Args)
	sr := store.Run{
		WatchID:       c.cfg.WatchID,
		Kind:          kindSandboxExec,
		StartedAt:     ev.Time,
		ProfileSource: string(spec.Source),
		ProfileError:  spec.Err,
		Params:        spec.Params,
		Extra:         spec.Extra,
		Command:       spec.Command,
		Cwd:           ev.Cwd,
	}
	if parent != nil {
		sr.ParentRunID = &parent.id
	}
	switch spec.Source {
	case sbx.SourceInline:
		sr.ProfileText = spec.Inline
	case sbx.SourceFile:
		p := spec.File
		if !filepath.IsAbs(p) && ev.Cwd != "" {
			p = filepath.Join(ev.Cwd, p)
		}
		sr.ProfilePath = p
		b, err := c.deps.ReadFile(p)
		if err != nil {
			sr.ProfileError = fmt.Sprintf("read profile: %v", err)
		} else {
			sr.ProfileText = string(b)
		}
	case sbx.SourceNamed:
		sr.ProfileName = spec.Name
	}
	r := &run{kind: kindSandboxExec, live: map[*image]struct{}{}}
	if tag, ok := sbx.FindTag(sr.ProfileText); ok {
		sid, err := c.sink.EnsureSession(sessionKindClaude, tag.Suffix, ev.Time)
		if err != nil {
			return nil, err
		}
		sr.SessionID, sr.Tag, sr.TagCommand = &sid, tag.Raw, tag.Command
		r.hasSession = true
	}
	id, err := c.sink.InsertRun(sr)
	if err != nil {
		return nil, err
	}
	r.id = id
	c.runs = append(c.runs, r)
	return r, nil
}

// imageFor returns the tracked image for an event's actor, creating an untracked-origin entry
// (exec not seen) for processes that predate the watch.
func (c *Correlator) imageFor(p eslog.Proc) *image {
	if img, ok := c.images[p.Token]; ok {
		return img
	}
	img := &image{proc: p, start: p.StartTime}
	c.register(img)
	return img
}

func (c *Correlator) register(img *image) {
	if !img.noToken {
		c.images[img.proc.Token] = img
	}
	pid := img.proc.Token.PID
	list := append(c.byPID[pid], img)
	sort.SliceStable(list, func(i, j int) bool { return list[i].start.Before(list[j].start) })
	c.byPID[pid] = list
}

func (c *Correlator) markSeen(p eslog.Proc) {
	c.seen[p.Token.PID] = seenInfo{path: p.Path, pidversion: p.Token.PIDVersion}
}

// join adds img to r and writes its process row.
func (c *Correlator) join(img *image, r *run) error {
	if img.run != nil {
		return nil
	}
	img.run = r
	row := store.Process{
		RunID:     r.id,
		PID:       img.proc.Token.PID,
		PPID:      img.proc.PPID,
		Path:      img.proc.Path,
		Args:      img.args,
		SigningID: img.proc.SigningID,
		TeamID:    img.proc.TeamID,
		CDHash:    img.proc.CDHash,
	}
	if !img.noToken {
		pv, plat := img.proc.Token.PIDVersion, img.proc.IsPlatform
		row.PIDVersion, row.IsPlatform = &pv, &plat
	}
	if !img.start.IsZero() {
		st := img.start
		row.StartedAt = &st
	}
	if img.parent != nil && img.parent.run == r {
		row.ParentProcessID = &img.parent.rowID
	}
	if img.prev != nil && img.prev.run == r {
		row.ExecPrevProcessID = &img.prev.rowID
	}
	id, err := c.sink.InsertProcess(row)
	if err != nil {
		return err
	}
	img.rowID = id
	if img.end == nil {
		r.live[img] = struct{}{}
		return nil
	}
	if err := c.sink.EndProcess(id, img.end, img.endReason, img.exitStatus); err != nil {
		return err
	}
	if img.end.After(r.lastEnd) {
		r.lastEnd = *img.end
	}
	return nil
}

func (c *Correlator) endImage(img *image, t time.Time, reason string, status *int) error {
	if img.end != nil {
		return nil
	}
	img.end, img.endReason, img.exitStatus = &t, reason, status
	r := img.run
	if r == nil {
		return nil
	}
	if err := c.sink.EndProcess(img.rowID, &t, reason, status); err != nil {
		return err
	}
	delete(r.live, img)
	if t.After(r.lastEnd) {
		r.lastEnd = t
	}
	return c.maybeEndRun(r)
}

// maybeEndRun marks a run exited once it has no live members. Adopted runs never end this way:
// their pre-existing ancestors are invisible, so liveness is unknowable.
func (c *Correlator) maybeEndRun(r *run) error {
	if r.ended || r.kind == kindAdopted || len(r.live) > 0 {
		return nil
	}
	r.ended = true
	end := r.lastEnd
	return c.sink.EndRun(r.id, &end, "exited")
}

// resolve finds the image that was pid at time t.
func (c *Correlator) resolve(pid int, t time.Time) *image {
	list := c.byPID[pid]
	for i := len(list) - 1; i >= 0; i-- {
		img := list[i]
		if img.start.After(t.Add(timeSlack)) {
			continue
		}
		if img.end != nil && img.end.Before(t.Add(-timeSlack)) {
			return nil
		}
		return img
	}
	return nil
}

// HandleDenial attributes a denial now or buffers it. now is the arrival time.
func (c *Correlator) HandleDenial(d ulog.Denial, now time.Time) error {
	key := denialKey{d.PID, d.Operation, d.Target}
	count := d.DenyN
	if d.Duplicate > 0 {
		if p := c.lastPending[key]; p != nil {
			p.count += d.Duplicate
			return nil
		}
		if id, ok := c.lastStored[key]; ok {
			return c.sink.AddDenialCount(id, d.Duplicate)
		}
		count = d.Duplicate
	}
	if count < 1 {
		count = 1
	}
	p := &pending{d: d, count: count, arrived: now}
	if c.caughtUp(d.Time) {
		if img := c.resolve(d.PID, d.Time); img != nil && img.run != nil {
			return c.attribute(p, img)
		}
	}
	c.pendingByPID[d.PID] = append(c.pendingByPID[d.PID], p)
	c.lastPending[key] = p
	return nil
}

func (c *Correlator) attribute(p *pending, img *image) error {
	r := img.run
	d := p.d
	id, err := c.sink.InsertDenial(store.Denial{
		RunID:       r.id,
		ProcessID:   img.rowID,
		Time:        d.Time,
		ProcessName: d.Name,
		PID:         d.PID,
		Operation:   d.Operation,
		Target:      d.Target,
		Message:     d.Message,
		Count:       p.count,
	})
	if err != nil {
		return err
	}
	key := denialKey{d.PID, d.Operation, d.Target}
	c.lastStored[key] = id
	if c.lastPending[key] == p {
		delete(c.lastPending, key)
	}
	if r.hasSession {
		return nil
	}
	if tag, ok := sbx.FindTag(d.Message); ok {
		sid, err := c.sink.EnsureSession(sessionKindClaude, tag.Suffix, d.Time)
		if err != nil {
			return err
		}
		if err := c.sink.SetRunSession(r.id, sid, tag.Raw, tag.Command); err != nil {
			return err
		}
		r.hasSession = true
	}
	return nil
}

func (c *Correlator) caughtUp(t time.Time) bool {
	return c.esWatermark.After(t.Add(timeSlack))
}

func (c *Correlator) setPending(pid int, list []*pending) {
	if len(list) == 0 {
		delete(c.pendingByPID, pid)
		return
	}
	c.pendingByPID[pid] = list
}

// Tick retries buffered denials the eslogger stream has caught up with, finalizes those older
// than the buffer window, and evicts old ended images.
func (c *Correlator) Tick(now time.Time) error {
	for pid, list := range c.pendingByPID {
		kept := list[:0]
		for _, p := range list {
			switch {
			case now.Sub(p.arrived) >= c.cfg.Buffer:
				if err := c.finalize(p); err != nil {
					return err
				}
			case c.caughtUp(p.d.Time):
				img := c.resolve(pid, p.d.Time)
				if img == nil || img.run == nil {
					kept = append(kept, p)
					continue
				}
				if err := c.attribute(p, img); err != nil {
					return err
				}
			default:
				kept = append(kept, p)
			}
		}
		c.setPending(pid, kept)
	}
	c.evict(now)
	return nil
}

// finalize decides the fate of a denial whose buffer window is over:
// attribute, adopt (Claude tag), sandbox_init candidate, orphan, or drop.
func (c *Correlator) finalize(p *pending) error {
	d := p.d
	key := denialKey{d.PID, d.Operation, d.Target}
	if c.lastPending[key] == p {
		delete(c.lastPending, key)
	}
	img := c.resolve(d.PID, d.Time)
	if img != nil && img.run != nil {
		return c.attribute(p, img)
	}
	if tag, ok := sbx.FindTag(d.Message); ok {
		r, err := c.adopt(tag, d)
		if err != nil {
			return err
		}
		if img == nil {
			img = &image{proc: eslog.Proc{Token: eslog.Token{PID: d.PID}}, noToken: true}
			c.register(img)
		}
		if err := c.join(img, r); err != nil {
			return err
		}
		return c.attribute(p, img)
	}
	if img != nil && c.deps.Entitlements != nil {
		r, err := c.candidateRun(img)
		if err != nil {
			return err
		}
		if r != nil {
			return c.attribute(p, img)
		}
	}
	if s, ok := c.seen[d.PID]; ok {
		pv := s.pidversion
		_, err := c.sink.InsertOrphan(store.Orphan{
			WatchID:        c.cfg.WatchID,
			Time:           d.Time,
			ProcessName:    d.Name,
			PID:            d.PID,
			Operation:      d.Operation,
			Target:         d.Target,
			Message:        d.Message,
			Count:          p.count,
			LastPath:       s.path,
			LastPIDVersion: &pv,
		})
		return err
	}
	return nil
}

func (c *Correlator) adopt(tag sbx.Tag, d ulog.Denial) (*run, error) {
	if r, ok := c.adopted[tag.Raw]; ok {
		return r, nil
	}
	sid, err := c.sink.EnsureSession(sessionKindClaude, tag.Suffix, d.Time)
	if err != nil {
		return nil, err
	}
	id, err := c.sink.InsertRun(store.Run{
		WatchID:            c.cfg.WatchID,
		Kind:               kindAdopted,
		SessionID:          &sid,
		Tag:                tag.Raw,
		TagCommand:         tag.Command,
		StartedAt:          d.Time,
		StartedBeforeWatch: true,
		ProfileSource:      string(sbx.SourceUnknown),
	})
	if err != nil {
		return nil, err
	}
	r := &run{id: id, kind: kindAdopted, live: map[*image]struct{}{}, hasSession: true}
	c.runs = append(c.runs, r)
	c.adopted[tag.Raw] = r
	return r, nil
}

func (c *Correlator) evict(now time.Time) {
	retention := minRetention
	if 3*c.cfg.Buffer > retention {
		retention = 3 * c.cfg.Buffer
	}
	cutoff := now.Add(-retention)
	for tok, img := range c.images {
		if img.end != nil && img.end.Before(cutoff) {
			delete(c.images, tok)
		}
	}
	for pid, list := range c.byPID {
		kept := list[:0]
		for _, img := range list {
			if img.end == nil || !img.end.Before(cutoff) {
				kept = append(kept, img)
			}
		}
		if len(kept) == 0 {
			delete(c.byPID, pid)
		} else {
			c.byPID[pid] = kept
		}
	}
}

// Shutdown finalizes every buffered denial and closes open runs and processes as watch_stopped.
func (c *Correlator) Shutdown(now time.Time) error {
	for pid, list := range c.pendingByPID {
		for _, p := range list {
			if err := c.finalize(p); err != nil {
				return err
			}
		}
		delete(c.pendingByPID, pid)
	}
	for _, r := range c.runs {
		for img := range r.live {
			if err := c.sink.EndProcess(img.rowID, nil, "watch_stopped", nil); err != nil {
				return err
			}
			delete(r.live, img)
		}
		if !r.ended {
			r.ended = true
			if err := c.sink.EndRun(r.id, nil, "watch_stopped"); err != nil {
				return err
			}
		}
	}
	return nil
}
