package serverdb

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenUpgradesV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.db")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	apply(t, d, batch(instA, row("runs", 1, 1, "status", "exited")))
	d.Close()

	// Turn it back into a schema 1 server database, which had no run_env mirror.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DROP TABLE run_env; PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	d, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if v := scalar[int](t, d, `PRAGMA user_version`); v != schemaVersion {
		t.Errorf("user_version = %d, want %d", v, schemaVersion)
	}
	if n := scalar[int](t, d, `SELECT count(*) FROM runs`); n != 1 {
		t.Errorf("existing runs lost: %d", n)
	}
	apply(t, d, batch(instA, row("run_env", 2, 1, "run_id", 1, "name", "CURSOR_AGENT", "value", "1")))
	if v := scalar[string](t, d, `SELECT value FROM run_env WHERE run_id = 1`); v != "1" {
		t.Errorf("run_env value = %q", v)
	}
	if idx := scalar[string](t, d, `SELECT group_concat(name) FROM pragma_index_list('run_env')`); !strings.Contains(idx, "run_env_run") {
		t.Errorf("run_env indexes = %q", idx)
	}
}
