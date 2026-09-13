package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"buckle/internal/serverdb"
	"buckle/internal/wire"
)

func newTestServer(t *testing.T, maxBody int64) (*httptest.Server, *serverdb.DB) {
	t.Helper()
	d, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	ts := httptest.NewServer(New(Options{DB: d, MaxBody: maxBody, Now: func() time.Time { return time.Unix(1, 0) }}))
	t.Cleanup(ts.Close)
	return ts, d
}

func fullRow(table string, rev int64, kv map[string]any) wire.Row {
	data := map[string]any{}
	for _, c := range wire.Columns[table] {
		data[c] = nil
	}
	for k, v := range kv {
		data[k] = v
	}
	data["rev"] = rev
	return wire.Row{Table: table, Rev: rev, Data: data}
}

func postJSON(t *testing.T, url string, body string) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func marshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const exactNS int64 = 1757783318775921977 // above 2^53: float64 decoding would corrupt it

func TestCursorEndpoint(t *testing.T) {
	ts, _ := newTestServer(t, 0)
	resp, _ := http.Get(ts.URL + "/api/v1/cursor")
	if resp.StatusCode != 400 {
		t.Errorf("missing params: %d, want 400", resp.StatusCode)
	}
	resp, err := http.Get(ts.URL + "/api/v1/cursor?host=H&db_instance=I")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var cr wire.CursorResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil || resp.StatusCode != 200 || cr.Rev != 0 {
		t.Errorf("unknown cursor: %d %+v %v", resp.StatusCode, cr, err)
	}
}

func TestIngestRoundTrip(t *testing.T) {
	ts, d := newTestServer(t, 0)
	b := wire.Batch{Host: wire.Host{UUID: "H", Name: "mac"}, DBInstance: "I", SchemaVersion: wire.SchemaVersion,
		Rows: []wire.Row{fullRow("watches", 3, map[string]any{"id": 1, "started_at": exactNS, "buffer_ns": 5000000000, "os_version": "14.2"})}}
	code, body := postJSON(t, ts.URL+"/api/v1/ingest", marshal(t, b))
	if code != 200 || strings.TrimSpace(body) != `{"cursor":3}` {
		t.Fatalf("ingest: %d %s", code, body)
	}
	var got int64
	if err := d.DB.QueryRow(`SELECT started_at FROM watches WHERE host_uuid = 'H'`).Scan(&got); err != nil || got != exactNS {
		t.Errorf("started_at = %d, %v; want exactly %d", got, err, exactNS)
	}
	if cur, _ := d.Cursor("H", "I"); cur != 3 {
		t.Errorf("cursor = %d, want 3", cur)
	}
}

func TestIngestErrors(t *testing.T) {
	ts, _ := newTestServer(t, 0)
	good := func() wire.Batch {
		return wire.Batch{Host: wire.Host{UUID: "H"}, DBInstance: "I", SchemaVersion: wire.SchemaVersion,
			Rows: []wire.Row{fullRow("runs", 1, map[string]any{"id": 1})}}
	}
	schema := good()
	schema.SchemaVersion = 1
	table := good()
	table.Rows[0].Table = "users"
	column := good()
	column.Rows[0].Data["bogus"] = 1
	cases := []struct {
		name string
		body string
		want int
	}{
		{"schema mismatch", marshal(t, schema), 409},
		{"unknown table", marshal(t, table), 400},
		{"unknown column", marshal(t, column), 400},
		{"malformed", `{"rows": [`, 400},
	}
	for _, c := range cases {
		if code, body := postJSON(t, ts.URL+"/api/v1/ingest", c.body); code != c.want || !strings.Contains(body, `"error"`) {
			t.Errorf("%s: %d %s, want %d with an error body", c.name, code, body, c.want)
		}
	}
	small, _ := newTestServer(t, 256)
	big := good()
	big.Rows[0].Data["cwd"] = strings.Repeat("x", 1024)
	if code, _ := postJSON(t, small.URL+"/api/v1/ingest", marshal(t, big)); code != 413 {
		t.Errorf("oversize: %d, want 413", code)
	}
}
