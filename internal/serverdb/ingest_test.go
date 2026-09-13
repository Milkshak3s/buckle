package serverdb

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"buckle/internal/wire"
)

const (
	hostA = "6F1C2A3B-0000-4000-8000-00000000000A"
	instA = "11111111-1111-4111-8111-111111111111"
	instB = "22222222-2222-4222-8222-222222222222"
)

var now = time.Date(2026, 9, 13, 18, 0, 0, 0, time.UTC)

func openTemp(t *testing.T) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// row builds a complete row: every column NULL except the key, rev and the kv pairs. Go ints become
// int64, as wire.Decode produces.
func row(table string, rev int64, key any, kv ...any) wire.Row {
	data := map[string]any{}
	for _, c := range wire.Columns[table] {
		data[c] = nil
	}
	norm := func(v any) any {
		if n, ok := v.(int); ok {
			return int64(n)
		}
		return v
	}
	data[wire.Key(table)] = norm(key)
	data["rev"] = rev
	for i := 0; i < len(kv); i += 2 {
		data[kv[i].(string)] = norm(kv[i+1])
	}
	return wire.Row{Table: table, Rev: rev, Data: data}
}

func batch(inst string, rows ...wire.Row) wire.Batch {
	return wire.Batch{Host: wire.Host{UUID: hostA, Name: "mac-a"}, DBInstance: inst, SchemaVersion: wire.SchemaVersion, Rows: rows}
}

func apply(t *testing.T, d *DB, b wire.Batch) int64 {
	t.Helper()
	cur, err := d.Apply(b, now)
	if err != nil {
		t.Fatal(err)
	}
	return cur
}

func scalar[T any](t *testing.T, d *DB, q string, args ...any) T {
	t.Helper()
	var v T
	if err := d.DB.QueryRow(q, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return v
}

func TestCursor(t *testing.T) {
	d := openTemp(t)
	if cur, err := d.Cursor(hostA, instA); err != nil || cur != 0 {
		t.Fatalf("unknown cursor = %d, %v; want 0", cur, err)
	}
	cur := apply(t, d, batch(instA, row("watches", 3, 1, "started_at", 1, "buffer_ns", 5), row("runs", 7, 1, "status", "running")))
	if cur != 7 {
		t.Errorf("cursor after batch = %d, want 7", cur)
	}
	if got, _ := d.Cursor(hostA, instA); got != 7 {
		t.Errorf("Cursor = %d, want 7", got)
	}
	if cur := apply(t, d, batch(instA)); cur != 7 {
		t.Errorf("heartbeat cursor = %d, want 7", cur)
	}
	if cur := apply(t, d, batch(instA, row("runs", 5, 2, "status", "running"))); cur != 7 {
		t.Errorf("lower-rev batch moved cursor to %d", cur)
	}
	if n := scalar[int64](t, d, `SELECT last_report_at FROM hosts WHERE uuid = ?`, hostA); n != now.UnixNano() {
		t.Errorf("last_report_at = %d", n)
	}
}

func TestApplyIdempotent(t *testing.T) {
	d := openTemp(t)
	b := batch(instA, row("sessions", 1, 1, "kind", "claude-code", "key", "_a_SBX"), row("runs", 2, 1, "session_id", 1, "status", "running"))
	apply(t, d, b)
	apply(t, d, b)
	if n := scalar[int](t, d, `SELECT count(*) FROM runs`); n != 1 {
		t.Errorf("runs = %d, want 1", n)
	}
	if n := scalar[int](t, d, `SELECT count(*) FROM sessions`); n != 1 {
		t.Errorf("sessions = %d, want 1", n)
	}
}

func TestStaleRowIgnored(t *testing.T) {
	d := openTemp(t)
	apply(t, d, batch(instA, row("runs", 9, 1, "status", "exited")))
	apply(t, d, batch(instA, row("runs", 4, 1, "status", "running")))
	if s := scalar[string](t, d, `SELECT status FROM runs`); s != "exited" {
		t.Errorf("status = %q, want exited (rev 9 wins)", s)
	}
}

func TestReferenceColumnsKept(t *testing.T) {
	d := openTemp(t)
	apply(t, d, batch(instA, row("runs", 5, 2, "parent_run_id", 1, "session_id", 3, "status", "exited")))
	apply(t, d, batch(instA, row("runs", 8, 2, "parent_run_id", nil, "session_id", nil, "status", "exited", "ended_at", 42)))
	var parent, session, ended, rev int64
	if err := d.DB.QueryRow(`SELECT parent_run_id, session_id, ended_at, rev FROM runs`).Scan(&parent, &session, &ended, &rev); err != nil {
		t.Fatal(err)
	}
	if parent != 1 || session != 3 || ended != 42 || rev != 8 {
		t.Errorf("got parent=%d session=%d ended=%d rev=%d; want 1 3 42 8", parent, session, ended, rev)
	}
}

func TestChildBeforeParent(t *testing.T) {
	d := openTemp(t)
	apply(t, d, batch(instA, row("denials", 10, 1, "run_id", 5, "process_id", 9, "time", 1, "process_name", "cat",
		"pid", 100, "operation", "file-read-data", "target", "/x", "count", 1)))
	apply(t, d, batch(instA, row("runs", 3, 5, "status", "exited")))
	if n := scalar[int](t, d, `SELECT count(*) FROM denials`); n != 1 {
		t.Errorf("denials = %d", n)
	}
	if n := scalar[int](t, d, `SELECT count(*) FROM runs`); n != 1 {
		t.Errorf("late parent run not stored: %d", n)
	}
}

func TestRecreatedInstanceKeepsHistory(t *testing.T) {
	d := openTemp(t)
	apply(t, d, batch(instA, row("runs", 1, 1, "status", "exited", "command_json", `["/bin/old"]`)))
	apply(t, d, batch(instB, row("runs", 1, 1, "status", "running", "command_json", `["/bin/new"]`)))
	if n := scalar[int](t, d, `SELECT count(*) FROM runs`); n != 2 {
		t.Errorf("runs = %d, want 2", n)
	}
	if c := scalar[string](t, d, `SELECT command_json FROM runs WHERE db_instance = ?`, instA); c != `["/bin/old"]` {
		t.Errorf("old instance overwritten: %s", c)
	}
}

func TestApplyValidation(t *testing.T) {
	d := openTemp(t)
	good := func() wire.Row { return row("runs", 1, 1, "status", "running") }
	mutate := func(f func(r *wire.Row)) wire.Batch { r := good(); f(&r); return batch(instA, r) }
	tooMany := batch(instA)
	for i := 0; i <= wire.MaxRows; i++ {
		tooMany.Rows = append(tooMany.Rows, row("runs", int64(i+1), i+1))
	}
	cases := map[string]wire.Batch{
		"unknown table":    mutate(func(r *wire.Row) { r.Table = "users" }),
		"unknown column":   mutate(func(r *wire.Row) { r.Data["bogus"] = int64(1) }),
		"missing column":   mutate(func(r *wire.Row) { delete(r.Data, "cwd") }),
		"null key":         mutate(func(r *wire.Row) { r.Data["id"] = nil }),
		"rev mismatch":     mutate(func(r *wire.Row) { r.Data["rev"] = int64(99) }),
		"non-scalar":       mutate(func(r *wire.Row) { r.Data["cwd"] = map[string]any{"x": 1} }),
		"missing host":     func() wire.Batch { b := batch(instA, good()); b.Host.UUID = ""; return b }(),
		"missing instance": batch("", good()),
		"too many rows":    tooMany,
	}
	for name, b := range cases {
		var ve *ValidationError
		if _, err := d.Apply(b, now); !errors.As(err, &ve) {
			t.Errorf("%s: err = %v, want ValidationError", name, err)
		}
	}
	b := batch(instA, good())
	b.SchemaVersion = 1
	if _, err := d.Apply(b, now); !errors.Is(err, ErrSchemaVersion) {
		t.Errorf("schema 1: err = %v, want ErrSchemaVersion", err)
	}
	if n := scalar[int](t, d, `SELECT count(*) FROM runs`); n != 0 {
		t.Errorf("rejected batches wrote %d runs", n)
	}
}
