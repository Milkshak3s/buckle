// Package wire defines the JSON protocol between `buckle ship` and `buckle serve`.
package wire

import (
	"encoding/json"
	"fmt"
	"io"
)

// SchemaVersion is the endpoint database schema a batch's rows come from.
const SchemaVersion = 2

// MaxRows caps the rows in one ingest request.
const MaxRows = 1000

// Tables lists the shipped tables in revision backfill order.
var Tables = []string{"watches", "sessions", "profiles", "runs", "processes", "denials", "orphans"}

// Columns is each shipped table's exact column set in schema order. The server builds its mirror
// tables and SQL from it, so client-supplied names never reach SQL.
var Columns = map[string][]string{
	"watches":  {"id", "started_at", "ended_at", "end_reason", "os_version", "buffer_ns", "rev"},
	"sessions": {"id", "kind", "key", "first_seen", "last_seen", "rev"},
	"profiles": {"hash", "text", "rev"},
	"runs": {"id", "watch_id", "kind", "parent_run_id", "session_id", "tag", "tag_command", "started_at", "ended_at",
		"status", "started_before_watch", "profile_source", "profile_hash", "profile_path", "profile_name", "profile_error",
		"params_json", "extra_json", "command_json", "cwd", "rev"},
	"processes": {"id", "run_id", "pid", "pidversion", "parent_process_id", "exec_prev_process_id", "ppid", "path", "args_json",
		"is_platform_binary", "signing_id", "team_id", "cdhash", "started_at", "ended_at", "end_reason", "exit_status", "rev"},
	"denials": {"id", "run_id", "process_id", "time", "process_name", "pid", "operation", "target", "message", "count", "rev"},
	"orphans": {"id", "watch_id", "time", "process_name", "pid", "operation", "target", "message", "count", "last_path",
		"last_pidversion", "rev"},
}

// References are columns buckle only ever sets from NULL to a value. A later NULL comes from endpoint
// pruning (ON DELETE SET NULL) and must not erase server history.
var References = map[string]bool{
	"parent_run_id": true, "session_id": true, "parent_process_id": true, "exec_prev_process_id": true, "profile_hash": true,
}

// Key is the table's local primary key column.
func Key(table string) string {
	if table == "profiles" {
		return "hash"
	}
	return "id"
}

type Host struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type Row struct {
	Table string         `json:"table"`
	Rev   int64          `json:"rev"`
	Data  map[string]any `json:"data"`
}

type Batch struct {
	Host          Host   `json:"host"`
	DBInstance    string `json:"db_instance"`
	SchemaVersion int    `json:"schema_version"`
	Rows          []Row  `json:"rows"`
}

type CursorResponse struct {
	Rev int64 `json:"rev"`
}

type IngestResponse struct {
	Cursor int64 `json:"cursor"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// Decode reads one batch. Integral JSON numbers become int64 so nanosecond timestamps stay exact;
// other numbers become float64.
func Decode(r io.Reader) (Batch, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	var b Batch
	if err := dec.Decode(&b); err != nil {
		return b, err
	}
	for i := range b.Rows {
		for k, v := range b.Rows[i].Data {
			n, ok := v.(json.Number)
			if !ok {
				continue
			}
			if iv, err := n.Int64(); err == nil {
				b.Rows[i].Data[k] = iv
			} else if fv, err := n.Float64(); err == nil {
				b.Rows[i].Data[k] = fv
			} else {
				return b, fmt.Errorf("rows[%d].%s: invalid number %q", i, k, n)
			}
		}
	}
	return b, nil
}
