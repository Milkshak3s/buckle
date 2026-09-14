// Command buckle audits macOS Seatbelt (sandbox-exec) runs and their denials.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"buckle/internal/report"
	"buckle/internal/server"
	"buckle/internal/serverdb"
	"buckle/internal/ship"
	"buckle/internal/store"
	"buckle/internal/watch"
)

const version = "0.1.0-dev"

const usage = `usage:
  sudo buckle watch [--buffer 5s] [--db PATH]
  buckle migrate [--db PATH]
  buckle serve [--addr 127.0.0.1:8080] [--db PATH] [--refresh 10s]
  sudo buckle ship [--server http://127.0.0.1:8080] [--interval 10s] [--db PATH]
  buckle query sessions [filters] [--format json|jsonl|csv]
  buckle query runs     [filters] [--format json|jsonl|csv]
  buckle query run <id>           [--format json|jsonl|csv]
  buckle report denials [filters] [--by operation|target|operation,target] [--top N] [--format ...]
  buckle version

filters:
  --since TIME      RFC 3339 time or a duration ago (e.g. 24h)
  --until TIME      RFC 3339 time or a duration ago
  --session KEY     session key: Claude Code tag suffix (e.g. _k3j9x0q2m_SBX) or Cursor conversation id
  --command TEXT    substring of the run's command or its session detail (tag_command)
  --has-denials     only runs with at least one denial
  --db PATH         database (default: ~/Library/Application Support/buckle/buckle.db)

Denial counts are lower bounds: the kernel drops many denial log lines, mostly from
non-platform binaries.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, "buckle", version)
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	case "watch":
		err = cmdWatch(args[1:], stderr)
	case "migrate":
		err = cmdMigrate(args[1:], stdout, stderr)
	case "serve":
		err = cmdServe(args[1:], stderr)
	case "ship":
		err = cmdShip(args[1:], stderr)
	case "query":
		err = cmdQuery(args[1:], stdout, stderr)
	case "report":
		err = cmdReport(args[1:], stdout, stderr)
	default:
		err = usageError{fmt.Sprintf("unknown command %q", args[0])}
	}
	var ue usageError
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &ue):
		fmt.Fprintf(stderr, "buckle: %s\n\n%s", ue.msg, usage)
		return 2
	default:
		fmt.Fprintf(stderr, "buckle: %v\n", err)
		return 1
	}
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func cmdWatch(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	buffer := fs.Duration("buffer", 5*time.Second, "how long unattributed denials wait for process events")
	dbPath := fs.String("db", "", "database path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usageError{"watch takes no arguments"}
	}
	owner, err := watch.SudoOwner("watch", "eslogger needs root")
	if err != nil {
		return err
	}
	path := *dbPath
	if path == "" {
		path = store.PathForHome(owner.Home)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return watch.Run(ctx, watch.Options{
		DBPath:    path,
		Owner:     owner,
		Buffer:    *buffer,
		OSVersion: watch.OSVersion(),
		Stderr:    stderr,
	})
}

func cmdMigrate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dbPath := fs.String("db", "", "database path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usageError{"migrate takes no arguments"}
	}
	if os.Geteuid() == 0 {
		return errors.New("buckle migrate must run without sudo: it upgrades your own database and must leave it owned by you")
	}
	path := *dbPath
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path = store.PathForHome(home)
	}
	inst, migrated, err := store.Migrate(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no buckle database at %s", path)
	}
	if err != nil {
		return err
	}
	if migrated {
		fmt.Fprintf(stdout, "migrated %s to schema v%d (db_instance %s)\n", path, store.SchemaVersion, inst)
	} else {
		fmt.Fprintf(stdout, "%s is already schema v%d (db_instance %s)\n", path, store.SchemaVersion, inst)
	}
	return nil
}

func cmdServe(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address (no auth: keep it on loopback)")
	dbPath := fs.String("db", "", "server database path")
	refresh := fs.Duration("refresh", 10*time.Second, "list page auto-refresh interval; 0 disables")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usageError{"serve takes no arguments"}
	}
	if *refresh < 0 {
		return usageError{"--refresh must not be negative"}
	}
	// serve runs fine either way. Under sudo (SUDO_USER set), it keeps the server database owned
	// by the invoking user rather than root, the same way watch.go does for the endpoint database.
	var owner *watch.Owner
	if os.Geteuid() == 0 && os.Getenv("SUDO_USER") != "" {
		var err error
		if owner, err = watch.SudoOwner("serve", "it must leave your server database owned by you"); err != nil {
			return err
		}
	}
	path := *dbPath
	if path == "" {
		home, err := invokingHome()
		if err != nil {
			return err
		}
		path = serverdb.PathForHome(home)
	}
	logf := func(format string, a ...any) { fmt.Fprintf(stderr, "buckle: "+format+"\n", a...) }
	dir := filepath.Dir(path)
	_, statErr := os.Stat(dir)
	dirCreated := errors.Is(statErr, os.ErrNotExist)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if owner != nil && dirCreated {
		chownServe(owner, stderr, dir)
	}
	db, err := serverdb.Open(path)
	if err != nil {
		return fmt.Errorf("open server database: %w", err)
	}
	defer db.Close()
	if owner != nil {
		chownServe(owner, stderr, path)
	}
	if host, _, err := net.SplitHostPort(*addr); err != nil {
		return usageError{"--addr: " + err.Error()}
	} else if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		logf("warning: %s is not a loopback address and buckle serve has no authentication", *addr)
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           server.New(server.Options{DB: db, Refresh: *refresh, Log: logf}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownDone := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownDone <- srv.Shutdown(shutdown)
	}()
	logf("serving http://%s; database %s", *addr, path)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		stop() // release the shutdown goroutine; we're not waiting for it
		return err
	}
	if err := <-shutdownDone; err != nil {
		logf("shutdown: %v", err)
		srv.Close()
		return err
	}
	return nil
}

// chownServe hands ownership of the server database (and, on first creation, its directory) to
// the sudo invoker, mirroring internal/watch/watch.go's chown helper: os.Lchown, warn and continue
// on any error other than the path not existing yet.
func chownServe(o *watch.Owner, stderr io.Writer, paths ...string) {
	for _, p := range paths {
		if err := os.Lchown(p, o.UID, o.GID); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "buckle: warning: chown %s: %v\n", p, err)
		}
	}
}

func cmdShip(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("ship", flag.ContinueOnError)
	fs.SetOutput(stderr)
	serverURL := fs.String("server", "http://127.0.0.1:8080", "buckle serve base URL")
	interval := fs.Duration("interval", 10*time.Second, "time between shipments")
	dbPath := fs.String("db", "", "database path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usageError{"ship takes no arguments"}
	}
	if *interval <= 0 {
		return usageError{"--interval must be positive"}
	}
	owner, err := watch.SudoOwner("ship", "the database's WAL files are root-owned while buckle watch runs")
	if err != nil {
		return err
	}
	path := *dbPath
	if path == "" {
		path = store.PathForHome(owner.Home)
	}
	s, err := store.OpenReadOnly(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no buckle database at %s; run `sudo buckle watch` first", path)
	}
	if err != nil {
		return err
	}
	defer s.Close()
	inst, err := s.DBInstance()
	if err != nil {
		return fmt.Errorf("read db_instance: %w", err)
	}
	host, err := ship.HostIdentity()
	if err != nil {
		return fmt.Errorf("host identity: %w", err)
	}
	logf := func(format string, a ...any) { fmt.Fprintf(stderr, "buckle: "+format+"\n", a...) }
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	base := strings.TrimRight(*serverURL, "/")
	logf("shipping %s (host %s %s, db_instance %s) to %s every %s", path, host.Name, host.UUID, inst, base, *interval)
	return ship.Run(ctx, ship.Options{
		Store: s, Host: host, DBInstance: inst, Server: base, Interval: *interval,
		Client: &http.Client{Timeout: 30 * time.Second}, Logf: logf,
	})
}

type queryFlags struct {
	fs         *flag.FlagSet
	db         string
	format     string
	since      string
	until      string
	session    string
	command    string
	hasDenials bool
}

func newQueryFlags(name string, stderr io.Writer, filters bool) *queryFlags {
	q := &queryFlags{fs: flag.NewFlagSet(name, flag.ContinueOnError)}
	q.fs.SetOutput(stderr)
	q.fs.StringVar(&q.db, "db", "", "database path")
	q.fs.StringVar(&q.format, "format", report.FormatJSON, "json, jsonl or csv")
	if filters {
		q.fs.StringVar(&q.since, "since", "", "RFC 3339 time or duration ago")
		q.fs.StringVar(&q.until, "until", "", "RFC 3339 time or duration ago")
		q.fs.StringVar(&q.session, "session", "", "session key")
		q.fs.StringVar(&q.command, "command", "", "command substring")
		q.fs.BoolVar(&q.hasDenials, "has-denials", false, "only runs with denials")
	}
	return q
}

func (q *queryFlags) parse(args []string) error {
	if err := q.fs.Parse(args); err != nil {
		return err
	}
	if q.fs.NArg() > 0 {
		return usageError{fmt.Sprintf("unexpected argument %q", q.fs.Arg(0))}
	}
	if !report.ValidFormat(q.format) {
		return usageError{fmt.Sprintf("unknown format %q", q.format)}
	}
	return nil
}

func (q *queryFlags) filter(now time.Time) (report.Filter, error) {
	f := report.Filter{Session: q.session, Command: q.command, HasDenials: q.hasDenials}
	var err error
	if f.Since, err = parseWhen(q.since, now); err != nil {
		return f, usageError{"--since: " + err.Error()}
	}
	if f.Until, err = parseWhen(q.until, now); err != nil {
		return f, usageError{"--until: " + err.Error()}
	}
	return f, nil
}

func (q *queryFlags) open() (*store.Store, error) {
	path := q.db
	if path == "" {
		home, err := invokingHome()
		if err != nil {
			return nil, err
		}
		path = store.PathForHome(home)
	}
	s, err := store.OpenReadOnly(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no buckle database at %s; run `sudo buckle watch` first", path)
	}
	return s, err
}

// invokingHome is SUDO_USER's home under sudo, otherwise the current user's.
func invokingHome() (string, error) {
	if name := os.Getenv("SUDO_USER"); name != "" && os.Geteuid() == 0 {
		u, err := user.Lookup(name)
		if err != nil {
			return "", err
		}
		return u.HomeDir, nil
	}
	return os.UserHomeDir()
}

func parseWhen(s string, now time.Time) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return nil, fmt.Errorf("%q is neither an RFC 3339 time nor a duration", s)
	}
	t := now.Add(-d)
	return &t, nil
}

func cmdQuery(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError{"query needs sessions, runs or run <id>"}
	}
	switch args[0] {
	case "sessions", "runs":
		q := newQueryFlags("query "+args[0], stderr, true)
		if err := q.parse(args[1:]); err != nil {
			return err
		}
		f, err := q.filter(time.Now())
		if err != nil {
			return err
		}
		s, err := q.open()
		if err != nil {
			return err
		}
		defer s.Close()
		list := report.Runs
		if args[0] == "sessions" {
			list = report.Sessions
		}
		recs, cols, err := list(s.DB, f)
		if err != nil {
			return err
		}
		return report.WriteRecords(stdout, q.format, cols, recs)
	case "run":
		if len(args) < 2 {
			return usageError{"query run needs a run id"}
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return usageError{fmt.Sprintf("invalid run id %q", args[1])}
		}
		q := newQueryFlags("query run", stderr, false)
		if err := q.parse(args[2:]); err != nil {
			return err
		}
		s, err := q.open()
		if err != nil {
			return err
		}
		defer s.Close()
		if q.format == report.FormatCSV {
			recs, cols, err := report.Denials(s.DB, id)
			if err != nil {
				return err
			}
			fmt.Fprintf(stderr, "buckle: CSV run detail lists denials only; %s\n", report.LowerBoundNote)
			return report.WriteRecords(stdout, q.format, cols, recs)
		}
		rec, err := report.RunDetail(s.DB, id)
		if err != nil {
			return err
		}
		return report.WriteObject(stdout, q.format, rec)
	}
	return usageError{fmt.Sprintf("unknown query %q", args[0])}
}

func cmdReport(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "denials" {
		return usageError{"report needs denials"}
	}
	q := newQueryFlags("report denials", stderr, true)
	by := q.fs.String("by", "operation,target", "group by operation, target, or both")
	top := q.fs.Int("top", 50, "maximum rows")
	if err := q.parse(args[1:]); err != nil {
		return err
	}
	f, err := q.filter(time.Now())
	if err != nil {
		return err
	}
	s, err := q.open()
	if err != nil {
		return err
	}
	defer s.Close()
	recs, cols, err := report.Aggregate(s.DB, f, strings.Split(*by, ","), *top)
	if err != nil {
		return usageError{err.Error()}
	}
	fmt.Fprintf(stderr, "buckle: %s\n", report.LowerBoundNote)
	return report.WriteRecords(stdout, q.format, cols, recs)
}
