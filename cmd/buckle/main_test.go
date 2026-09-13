package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"buckle/internal/store"
)

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestUsageAndErrors(t *testing.T) {
	if code, out, _ := runCLI("version"); code != 0 || !strings.HasPrefix(out, "buckle ") {
		t.Errorf("version: %d %q", code, out)
	}
	if code, _, _ := runCLI(); code != 2 {
		t.Errorf("no args: %d", code)
	}
	if code, _, errs := runCLI("frob"); code != 2 || !strings.Contains(errs, `unknown command "frob"`) {
		t.Errorf("unknown: %d %q", code, errs)
	}
	if code, _, errs := runCLI("query", "runs", "--db", filepath.Join(t.TempDir(), "none.db")); code != 1 || !strings.Contains(errs, "run `sudo buckle watch` first") {
		t.Errorf("missing db: %d %q", code, errs)
	}
	if code, _, _ := runCLI("query", "runs", "--format", "xml"); code != 2 {
		t.Errorf("bad format: %d", code)
	}
	if code, _, _ := runCLI("query", "run", "abc"); code != 2 {
		t.Errorf("bad id: %d", code)
	}
	if code, _, errs := runCLI("watch"); code != 1 || !strings.Contains(errs, "sudo") {
		t.Errorf("watch without sudo: %d %q", code, errs)
	}
}

func TestQueryEmptyDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "buckle.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if code, out, errs := runCLI("query", "runs", "--db", path, "--since", "24h"); code != 0 || strings.TrimSpace(out) != "[]" {
		t.Errorf("runs: %d %q %q", code, out, errs)
	}
	if code, out, _ := runCLI("query", "sessions", "--db", path, "--format", "csv"); code != 0 || !strings.HasPrefix(out, "id,kind,key,") {
		t.Errorf("sessions csv: %d %q", code, out)
	}
	if code, _, errs := runCLI("report", "denials", "--db", path, "--by", "operation", "--format", "jsonl"); code != 0 || !strings.Contains(errs, "lower bounds") {
		t.Errorf("report: %d %q", code, errs)
	}
	if code, _, errs := runCLI("query", "run", "1", "--db", path); code != 1 || !strings.Contains(errs, "not found") {
		t.Errorf("run detail missing: %d %q", code, errs)
	}
}

func TestParseWhen(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	if got, err := parseWhen("2h", now); err != nil || !got.Equal(now.Add(-2*time.Hour)) {
		t.Errorf("duration: %v %v", got, err)
	}
	if got, err := parseWhen("2026-09-01T00:00:00Z", now); err != nil || got.Day() != 1 {
		t.Errorf("rfc3339: %v %v", got, err)
	}
	if _, err := parseWhen("yesterday", now); err == nil {
		t.Error("want error")
	}
	if got, err := parseWhen("", now); got != nil || err != nil {
		t.Error("empty should be nil")
	}
}
