package watch

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"buckle/internal/store"
	"buckle/internal/testutil"
)

type noEnts struct{}

func (noEnts) HasAppSandbox(string, string) (bool, error) { return false, nil }

func script(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func options(t *testing.T, esScript, logScript string) (Options, *bytes.Buffer) {
	t.Helper()
	dir := testutil.FixtureDir(t, "macos14.2")
	items := testutil.LoadFixture(t, dir)
	end := items[len(items)-1].Time.Add(time.Second)
	var stderr bytes.Buffer
	return Options{
		DBPath:       filepath.Join(t.TempDir(), "sub", "buckle.db"),
		Buffer:       5 * time.Second,
		ESLoggerPath: script(t, "eslogger", strings.ReplaceAll(esScript, "FIXTURE", dir)),
		LogPath:      script(t, "log", strings.ReplaceAll(logScript, "FIXTURE", dir)),
		OSVersion:    "14.2",
		Entitlements: noEnts{},
		Stderr:       &stderr,
		// Fixture times: keep the clock at the end of the capture so nothing is evicted or expired early.
		Now: func() time.Time { return end },
	}, &stderr
}

func dbCount(t *testing.T, path, q string) int {
	t.Helper()
	s, err := store.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var n int
	if err := s.DB.QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRunReplaysAndStopsCleanly(t *testing.T) {
	o, stderr := options(t, `cat FIXTURE/es.jsonl; exec sleep 30`, `cat FIXTURE/log.ndjson; exec sleep 30`)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- Run(ctx, o) }()
	time.Sleep(1500 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Run: %v\n%s", err, stderr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	if n := dbCount(t, o.DBPath, `SELECT count(*) FROM runs WHERE kind = 'sandbox-exec' AND status = 'exited'`); n != 6 {
		t.Errorf("exited sandbox-exec runs = %d, want 6\n%s", n, stderr)
	}
	if n := dbCount(t, o.DBPath, `SELECT count(*) FROM runs WHERE kind = 'adopted' AND status = 'watch_stopped'`); n != 1 {
		t.Errorf("adopted runs = %d, want 1", n)
	}
	if n := dbCount(t, o.DBPath, `SELECT count(*) FROM denials`); n != 8 {
		t.Errorf("denials = %d, want 8", n)
	}
	if n := dbCount(t, o.DBPath, `SELECT count(*) FROM watches WHERE end_reason = 'stopped' AND ended_at IS NOT NULL AND os_version = '14.2'`); n != 1 {
		t.Error("watch row not closed as stopped")
	}
	if !strings.Contains(stderr.String(), "stopped: 7 runs, 8 denials") {
		t.Errorf("summary missing:\n%s", stderr)
	}
}

func TestRunFullDiskAccessError(t *testing.T) {
	o, _ := options(t,
		`echo "Failed to create ES client: Not permitted to create an ES Client, responsible process needs TCC Full Disk Access authorization (ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED)" >&2; exit 1`,
		`exec sleep 30`)
	err := runWithTimeout(t, o)
	if err == nil || !strings.Contains(err.Error(), "grant Full Disk Access") {
		t.Fatalf("err = %v", err)
	}
	if n := dbCount(t, o.DBPath, `SELECT count(*) FROM watches WHERE end_reason = 'source died: eslogger'`); n != 1 {
		t.Error("watch end_reason not recorded")
	}
}

func TestRunLogSourceDies(t *testing.T) {
	o, _ := options(t, `cat FIXTURE/es.jsonl; exec sleep 30`, `echo boom >&2; exit 3`)
	err := runWithTimeout(t, o)
	if err == nil || !strings.Contains(err.Error(), "source died: log") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
}

func runWithTimeout(t *testing.T, o Options) error {
	t.Helper()
	errc := make(chan error, 1)
	go func() { errc <- Run(context.Background(), o) }()
	select {
	case err := <-errc:
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}
