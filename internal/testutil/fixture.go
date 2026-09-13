// Package testutil loads recorded eslogger + unified-log fixtures for replay tests.
package testutil

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"buckle/internal/eslog"
	"buckle/internal/ulog"
)

// Item is one event from either source. Exactly one of ES and Denial is set.
type Item struct {
	Time   time.Time
	ES     *eslog.Event
	Denial *ulog.Denial
}

// FixtureDir returns testdata/fixtures/<name> relative to the module root.
func FixtureDir(t testing.TB, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "testdata", "fixtures", name)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// LoadFixture parses dir/es.jsonl and dir/log.ndjson and merges them by time.
// On equal times the eslogger event sorts first.
func LoadFixture(t testing.TB, dir string) []Item {
	t.Helper()
	var items []Item
	scan(t, filepath.Join(dir, "es.jsonl"), func(b []byte) {
		ev, err := eslog.Parse(b)
		if errors.Is(err, eslog.ErrSkip) {
			return
		}
		if err != nil {
			t.Fatalf("es.jsonl: %v", err)
		}
		items = append(items, Item{Time: ev.Time, ES: &ev})
	})
	scan(t, filepath.Join(dir, "log.ndjson"), func(b []byte) {
		d, err := ulog.Parse(b)
		if errors.Is(err, ulog.ErrSkip) {
			return
		}
		if err != nil {
			t.Fatalf("log.ndjson: %v", err)
		}
		items = append(items, Item{Time: d.Time, Denial: &d})
	})
	sort.SliceStable(items, func(i, j int) bool {
		if !items[i].Time.Equal(items[j].Time) {
			return items[i].Time.Before(items[j].Time)
		}
		return items[i].ES != nil && items[j].ES == nil
	})
	return items
}

func scan(t testing.TB, path string, fn func([]byte)) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		fn(sc.Bytes())
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
}
