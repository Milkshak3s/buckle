// Package watch runs `buckle watch`: it spawns eslogger and log stream, feeds the correlator,
// and records everything in the invoking user's database.
package watch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"buckle/internal/codesign"
	"buckle/internal/correlate"
	"buckle/internal/eslog"
	"buckle/internal/store"
	"buckle/internal/ulog"
)

const (
	Retention       = 30 * 24 * time.Hour
	stopGrace       = 3 * time.Second
	tickInterval    = 500 * time.Millisecond
	signalRaceGrace = 250 * time.Millisecond
)

var (
	DefaultESLoggerArgs = []string{"exec", "fork", "exit"}
	DefaultLogArgs      = []string{"stream", "--predicate", `sender == "Sandbox"`, "--style", "ndjson"}
)

// Owner is the user who should own the database files.
type Owner struct {
	UID, GID int
	Home     string
	Name     string
}

// SudoOwner resolves the user who invoked sudo. It fails unless running as root under sudo.
func SudoOwner(command, reason string) (*Owner, error) {
	name := os.Getenv("SUDO_USER")
	if os.Geteuid() != 0 || name == "" || name == "root" {
		return nil, fmt.Errorf("buckle %s must be run with sudo from your user account (%s)", command, reason)
	}
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("look up SUDO_USER %q: %w", name, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, err
	}
	return &Owner{UID: uid, GID: gid, Home: u.HomeDir, Name: name}, nil
}

type Options struct {
	DBPath       string
	Owner        *Owner // nil: don't chown (tests)
	Buffer       time.Duration
	ESLoggerPath string
	ESLoggerArgs []string
	LogPath      string
	LogArgs      []string
	OSVersion    string
	Entitlements correlate.EntitlementChecker
	Stderr       io.Writer
	Now          func() time.Time
}

func (o *Options) defaults() {
	if o.Buffer <= 0 {
		o.Buffer = 5 * time.Second
	}
	if o.ESLoggerPath == "" {
		o.ESLoggerPath = "/usr/bin/eslogger"
	}
	if o.ESLoggerArgs == nil {
		o.ESLoggerArgs = DefaultESLoggerArgs
	}
	if o.LogPath == "" {
		o.LogPath = "/usr/bin/log"
	}
	if o.LogArgs == nil {
		o.LogArgs = DefaultLogArgs
	}
	if o.Entitlements == nil {
		o.Entitlements = codesign.New()
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// OSVersion returns the macOS product version, or "" if unavailable.
func OSVersion() string {
	out, err := exec.Command("/usr/sbin/sysctl", "-n", "kern.osproductversion").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Run watches until ctx is cancelled (clean stop, nil error) or a source dies (error).
func Run(ctx context.Context, o Options) (retErr error) {
	o.defaults()
	logf := func(format string, args ...any) { fmt.Fprintf(o.Stderr, "buckle: "+format+"\n", args...) }

	// Only hand ownership of the directory to the user if buckle creates it; --db may point into
	// a shared directory such as /private/tmp.
	dir := filepath.Dir(o.DBPath)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		chown(o.Owner, dir)
	}
	s, err := store.Open(o.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	chown(o.Owner, o.DBPath)
	defer func() {
		if err := s.Close(); err != nil && retErr == nil {
			retErr = err
		}
		chown(o.Owner, o.DBPath, o.DBPath+"-journal")
	}()

	start := o.Now()
	st, err := s.Prune(start, Retention)
	if err != nil {
		return fmt.Errorf("prune: %w", err)
	}
	if st.Runs+st.Orphans > 0 {
		logf("pruned %d runs and %d orphans older than 30 days", st.Runs, st.Orphans)
	}
	watchID, err := s.BeginWatch(start, o.OSVersion, o.Buffer)
	if err != nil {
		return err
	}

	warn := newWarner(logf)
	c := correlate.New(correlate.Config{WatchID: watchID, WatchStart: start, Buffer: o.Buffer}, s, correlate.Deps{
		Entitlements: o.Entitlements,
		Warn:         func(m string) { warn.once(m, m) },
	})

	es, err := startSource("eslogger", o.ESLoggerPath, o.ESLoggerArgs)
	if err != nil {
		s.EndWatch(watchID, o.Now(), "failed to start eslogger")
		return err
	}
	lg, err := startSource("log", o.LogPath, o.LogArgs)
	if err != nil {
		es.abandon(stopGrace)
		s.EndWatch(watchID, o.Now(), "failed to start log stream")
		return err
	}
	logf("watching; database %s; denial buffer %s", o.DBPath, o.Buffer)
	logf("note: %s", "stored denials are a lower bound; the kernel drops many from non-platform binaries")

	loopErr, reason := loop(ctx, o, c, es, lg, warn)

	if err := c.Shutdown(o.Now()); err != nil && loopErr == nil {
		loopErr = err
	}
	if err := s.EndWatch(watchID, o.Now(), reason); err != nil && loopErr == nil {
		loopErr = err
	}
	if loopErr == nil {
		printSummary(s, watchID, logf)
	}
	return loopErr
}

// loop consumes both sources until a clean stop or a failure. It returns the error and the
// watch end_reason.
func loop(ctx context.Context, o Options, c *correlate.Correlator, es, lg *source, warn *warner) (error, string) {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	esLines, logLines := es.lines, lg.lines
	done := ctx.Done()
	var deadline <-chan time.Time
	stopping := false

	stop := func() {
		if stopping {
			return
		}
		stopping = true
		done = nil
		es.interrupt()
		lg.interrupt()
		deadline = time.After(stopGrace)
	}
	// died handles a source whose output ended while we weren't stopping. A Ctrl-C reaches the
	// children at the same moment as buckle, so give the signal a moment to show up first.
	died := func(dead, other *source) (error, string, bool) {
		select {
		case <-ctx.Done():
			stop()
			return nil, "", false
		case <-time.After(signalRaceGrace):
		}
		other.abandon(stopGrace)
		err := dead.exitError()
		if dead.name == "eslogger" && strings.Contains(err.Error(), "NOT_PERMITTED") {
			err = fmt.Errorf("eslogger was denied: grant Full Disk Access to the terminal app running buckle "+
				"(System Settings → Privacy & Security → Full Disk Access), restart it, and try again\n%w", err)
		}
		return err, "source died: " + dead.name, true
	}

	for esLines != nil || logLines != nil {
		var err error
		select {
		case line, ok := <-esLines:
			if !ok {
				esLines = nil
				if !stopping {
					if e, reason, fatal := died(es, lg); fatal {
						return e, reason
					}
				}
				continue
			}
			ev, perr := eslog.Parse(line)
			var drift *eslog.DriftError
			switch {
			case perr == nil:
				err = c.HandleES(ev)
			case errors.Is(perr, eslog.ErrSkip):
			case errors.As(perr, &drift):
				warn.once("drift:"+drift.Field, perr.Error())
			default:
				warn.once("eslog-parse", fmt.Sprintf("unparseable eslogger line (further ones not reported): %v", perr))
			}
			if perr == nil && ev.SchemaVersion != 1 {
				warn.once("schema", fmt.Sprintf("eslogger schema_version %d (buckle was built against 1); continuing best effort", ev.SchemaVersion))
			}
		case line, ok := <-logLines:
			if !ok {
				logLines = nil
				if !stopping {
					if e, reason, fatal := died(lg, es); fatal {
						return e, reason
					}
				}
				continue
			}
			d, perr := ulog.Parse(line)
			switch {
			case perr == nil:
				err = c.HandleDenial(d, o.Now())
			case errors.Is(perr, ulog.ErrSkip):
			default:
				warn.once("ulog-parse", fmt.Sprintf("unparseable log line (further ones not reported): %v", perr))
			}
		case <-ticker.C:
			err = c.Tick(o.Now())
		case <-done:
			stop()
		case <-deadline:
			es.kill()
			lg.kill()
			deadline = nil
		}
		if err != nil {
			es.abandon(stopGrace)
			lg.abandon(stopGrace)
			return fmt.Errorf("record: %w", err), "error: " + err.Error()
		}
	}
	<-es.done
	<-lg.done
	return nil, "stopped"
}

type warner struct {
	seen map[string]bool
	logf func(string, ...any)
}

func newWarner(logf func(string, ...any)) *warner {
	return &warner{seen: map[string]bool{}, logf: logf}
}

func (w *warner) once(key, msg string) {
	if w.seen[key] {
		return
	}
	w.seen[key] = true
	w.logf("warning: %s", msg)
}

func chown(o *Owner, paths ...string) {
	if o == nil {
		return
	}
	for _, p := range paths {
		if err := os.Lchown(p, o.UID, o.GID); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "buckle: warning: chown %s: %v\n", p, err)
		}
	}
}

func printSummary(s *store.Store, watchID int64, logf func(string, ...any)) {
	var runs, denials, orphans int64
	err := s.DB.QueryRow(`SELECT
		(SELECT count(*) FROM runs WHERE watch_id = ?),
		(SELECT coalesce(sum(d.count), 0) FROM denials d JOIN runs r ON r.id = d.run_id WHERE r.watch_id = ?),
		(SELECT count(*) FROM orphans WHERE watch_id = ?)`, watchID, watchID, watchID).Scan(&runs, &denials, &orphans)
	if err != nil {
		logf("stopped")
		return
	}
	logf("stopped: %d runs, %d denials, %d orphan denials recorded", runs, denials, orphans)
}
