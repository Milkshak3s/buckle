package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"buckle/internal/correlate"
	"buckle/internal/store"
	"buckle/internal/testutil"
)

type noEnts struct{}

func (noEnts) HasAppSandbox(string, string) (bool, error) { return false, nil }

// fixtureDB replays the 14.2 fixture into a temp DB and returns it opened read-only.
func fixtureDB(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "buckle.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	items := testutil.LoadFixture(t, testutil.FixtureDir(t, "macos14.2"))
	start := items[0].Time
	w, err := s.BeginWatch(start, "14.2", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c := correlate.New(correlate.Config{WatchID: w, WatchStart: start, Buffer: 5 * time.Second}, s, correlate.Deps{
		ReadFile: func(p string) ([]byte, error) {
			if p == "/private/tmp/buckle-capture.3s465f/param.sb" {
				return []byte("(version 1)(allow default)"), nil
			}
			return nil, fs.ErrNotExist
		},
		Entitlements: noEnts{},
	})
	for _, it := range items {
		if it.ES != nil {
			err = c.HandleES(*it.ES)
		} else {
			err = c.HandleDenial(*it.Denial, it.Time)
		}
		if err == nil {
			err = c.Tick(it.Time)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Shutdown(items[len(items)-1].Time.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	ro, err := store.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ro.Close() })
	return ro
}

func TestRunsFilters(t *testing.T) {
	s := fixtureDB(t)
	future := time.Now().Add(24 * time.Hour)
	cases := []struct {
		name string
		f    Filter
		want int
	}{
		{"all", Filter{}, 7},
		{"session", Filter{Session: "_k3j9x0q2m_SBX"}, 2},
		{"command substring spans args and tag command", Filter{Command: "head -1"}, 2},
		{"command with ampersand", Filter{Command: "(cat /etc/hosts &)"}, 1},
		{"has denials", Filter{HasDenials: true}, 6},
		{"since future", Filter{Since: &future}, 0},
		{"until future", Filter{Until: &future}, 7},
	}
	for _, c := range cases {
		recs, _, err := Runs(s.DB, c.f)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(recs) != c.want {
			t.Errorf("%s: %d runs, want %d", c.name, len(recs), c.want)
		}
	}
}

func TestRunsRecordShape(t *testing.T) {
	s := fixtureDB(t)
	recs, cols, err := Runs(s.DB, Filter{Command: "(cat /etc/hosts &)"})
	if err != nil || len(recs) != 1 {
		t.Fatalf("%v %d", err, len(recs))
	}
	r := recs[0]
	if r.Get("process_count") != int64(10) || r.Get("denial_count") != int64(2) || r.Get("session") != "_k3j9x0q2m_SBX" {
		t.Errorf("record = %v", r)
	}
	if r.Get("started_before_watch") != false {
		t.Errorf("started_before_watch = %#v", r.Get("started_before_watch"))
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Get("started_at").(string)); err != nil {
		t.Errorf("started_at: %v", err)
	}
	want := "id,kind,status,started_at,ended_at,started_before_watch,session,tag_command,command,profile_source,profile_name,profile_path,parent_run_id,process_count,nonplatform_process_count,denial_count"
	if strings.Join(cols, ",") != want {
		t.Errorf("columns = %s", strings.Join(cols, ","))
	}
}

func TestSessions(t *testing.T) {
	s := fixtureDB(t)
	recs, _, err := Sessions(s.DB, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Get("key") != "_k3j9x0q2m_SBX" || recs[0].Get("run_count") != int64(2) || recs[0].Get("denial_count") != int64(3) {
		t.Errorf("sessions = %v", recs)
	}
	recs, _, err = Sessions(s.DB, Filter{Command: "no such command"})
	if err != nil || len(recs) != 0 {
		t.Errorf("filtered sessions = %v, %v", recs, err)
	}
}

func TestRunDetail(t *testing.T) {
	s := fixtureDB(t)
	recs, _, err := Runs(s.DB, Filter{Command: "(cat /etc/hosts &)"})
	if err != nil || len(recs) != 1 {
		t.Fatal(err)
	}
	id := recs[0].Get("id").(int64)
	d, err := RunDetail(s.DB, id)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(d.Get("processes").([]Record)); n != 10 {
		t.Errorf("processes = %d", n)
	}
	if n := len(d.Get("denials").([]Record)); n != 2 {
		t.Errorf("denials = %d", n)
	}
	if !strings.Contains(d.Get("profile_text").(string), "LogTag") {
		t.Errorf("profile_text = %v", d.Get("profile_text"))
	}
	if d.Get("note") != LowerBoundNote {
		t.Error("lower-bound note missing")
	}
	var buf bytes.Buffer
	if err := WriteObject(&buf, FormatJSON, d); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("detail JSON invalid: %v\n%s", err, buf.String())
	}
	if cmd, ok := decoded["command"].([]any); !ok || len(cmd) != 3 {
		t.Errorf("command should be a JSON array: %#v", decoded["command"])
	}
	if _, err := RunDetail(s.DB, 99999); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing run err = %v", err)
	}
}

func TestAggregate(t *testing.T) {
	s := fixtureDB(t)
	recs, _, err := Aggregate(s.DB, Filter{}, []string{"target"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	top := recs[0]
	if top.Get("target") != "/private/etc/hosts" || top.Get("total_count") != int64(5) || top.Get("run_count") != int64(4) || top.Get("nonplatform_count") != int64(0) {
		t.Errorf("top = %v", top)
	}
	recs, _, err = Aggregate(s.DB, Filter{}, []string{"operation"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Get("operation") != "file-read-data" || recs[1].Get("operation") != "network-outbound" || recs[1].Get("total_count") != int64(2) {
		t.Errorf("by operation = %v", recs)
	}
	recs, _, err = Aggregate(s.DB, Filter{Session: "_k3j9x0q2m_SBX"}, nil, 0)
	if err != nil || len(recs) != 1 || recs[0].Get("total_count") != int64(3) {
		t.Errorf("session aggregate = %v %v", recs, err)
	}
	if _, _, err := Aggregate(s.DB, Filter{}, []string{"pid"}, 0); err == nil {
		t.Error("group by pid should be rejected")
	}
}

func TestWriteRecordsFormats(t *testing.T) {
	s := fixtureDB(t)
	recs, cols, err := Runs(s.DB, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteRecords(&buf, FormatJSONL, cols, recs); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 7 {
		t.Errorf("jsonl lines = %d", len(lines))
	}
	for _, l := range lines {
		if !json.Valid([]byte(l)) {
			t.Errorf("invalid jsonl line %s", l)
		}
	}

	buf.Reset()
	if err := WriteRecords(&buf, FormatCSV, cols, recs); err != nil {
		t.Fatal(err)
	}
	csvLines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if csvLines[0] != strings.Join(cols, ",") {
		t.Errorf("csv header = %s", csvLines[0])
	}
	if !strings.Contains(buf.String(), `"[""/bin/cat"",""/etc/hosts""]"`) {
		t.Errorf("csv command column not JSON text:\n%s", buf.String())
	}

	buf.Reset()
	if err := WriteRecords(&buf, FormatJSON, cols, nil); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("empty json = %q", buf.String())
	}
	buf.Reset()
	if err := WriteRecords(&buf, FormatCSV, cols, nil); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != strings.Join(cols, ",") {
		t.Errorf("empty csv = %q", buf.String())
	}
}
