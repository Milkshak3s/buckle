package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"buckle/internal/wire"
)

func get(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d %s", url, resp.StatusCode, b)
	}
	return string(b)
}

func TestAgentLabels(t *testing.T) {
	ts, d := newTestServer(t, 0)
	ns := time.Date(2026, 9, 13, 18, 0, 0, 0, time.UTC).UnixNano()
	session := func(rev, id int64, kind, key string) wire.Row {
		return fullRow("sessions", rev, map[string]any{"id": id, "kind": kind, "key": key, "first_seen": ns, "last_seen": ns})
	}
	run := func(rev, id, session int64, detail string) wire.Row {
		return fullRow("runs", rev, map[string]any{"id": id, "kind": "sandbox-exec", "session_id": session, "status": "exited",
			"started_at": ns, "tag_command": detail, "command_json": `["/bin/zsh"]`, "params_json": "[]", "profile_source": "inline"})
	}
	b := wire.Batch{Host: wire.Host{UUID: "H", Name: "mac"}, DBInstance: "I", SchemaVersion: wire.SchemaVersion, Rows: []wire.Row{
		session(1, 1, "claude-code", "_k3j9x0q2m_SBX"),
		session(2, 2, "cursor", "e5ea23fc-ee23-4fad-acb0-0a0db9c3e6cc"),
		session(3, 3, "future-agent", "k"),
		run(4, 1, 1, "toolu_01"),
		run(5, 2, 2, "efbe69ab-92e7-459b-aa1f-61b305bdc45f"),
		run(6, 3, 3, "x"),
	}}
	if _, err := d.Apply(b, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}

	index := get(t, ts.URL+"/")
	for _, want := range []string{"<th>Session</th>", `<span class="tag">Claude Code</span>`, `<span class="tag">Cursor</span>`, `<span class="tag">future-agent</span>`} {
		if !strings.Contains(index, want) {
			t.Errorf("index missing %q", want)
		}
	}
	if strings.Contains(index, "Claude session") {
		t.Error("index still says Claude session")
	}
	if page := get(t, ts.URL+"/hosts/H/I/sessions/2"); !strings.Contains(page, `<span class="tag">Cursor</span>`) {
		t.Error("session page missing Cursor badge")
	}
	for id, label := range map[string]string{"1": "<dt>Claude tool use</dt>", "2": "<dt>Cursor request</dt>", "3": "<dt>Tag detail</dt>"} {
		if page := get(t, ts.URL+"/hosts/H/I/runs/"+id); !strings.Contains(page, label) {
			t.Errorf("run %s missing %q", id, label)
		}
	}
}
