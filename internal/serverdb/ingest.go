package serverdb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"buckle/internal/wire"
)

// ValidationError is a batch the server refuses as malformed (HTTP 400).
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// ErrSchemaVersion is a batch from an endpoint schema this server doesn't mirror (HTTP 409).
var ErrSchemaVersion = errors.New("unsupported schema_version")

var upserts = func() map[string]string {
	m := map[string]string{}
	for _, t := range wire.Tables {
		cols := wire.Columns[t]
		key := wire.Key(t)
		quoted := make([]string, len(cols))
		marks := make([]string, len(cols))
		var sets []string
		for i, c := range cols {
			quoted[i] = quote(c)
			marks[i] = "?"
			switch {
			case c == key:
			case wire.References[c]:
				sets = append(sets, fmt.Sprintf("%s = coalesce(excluded.%s, %s.%s)", quote(c), quote(c), quote(t), quote(c)))
			default:
				sets = append(sets, fmt.Sprintf("%s = excluded.%s", quote(c), quote(c)))
			}
		}
		m[t] = fmt.Sprintf(`INSERT INTO %s (host_uuid, db_instance, %s) VALUES (?, ?, %s)
			ON CONFLICT (host_uuid, db_instance, %s) DO UPDATE SET %s WHERE excluded.rev > %s.rev`,
			quote(t), strings.Join(quoted, ", "), strings.Join(marks, ", "), quote(key), strings.Join(sets, ", "), quote(t))
	}
	return m
}()

func validateRow(r wire.Row) error {
	cols, ok := wire.Columns[r.Table]
	if !ok {
		return fmt.Errorf("unknown table %q", r.Table)
	}
	allowed := make(map[string]bool, len(cols))
	for _, c := range cols {
		allowed[c] = true
		if _, ok := r.Data[c]; !ok {
			return fmt.Errorf("%s: missing column %q", r.Table, c)
		}
	}
	for c, v := range r.Data {
		if !allowed[c] {
			return fmt.Errorf("%s: unknown column %q", r.Table, c)
		}
		switch v.(type) {
		case nil, string, int64, float64, bool:
		default:
			return fmt.Errorf("%s.%s: unsupported value type %T", r.Table, c, v)
		}
	}
	if r.Data[wire.Key(r.Table)] == nil {
		return fmt.Errorf("%s: key %q is null", r.Table, wire.Key(r.Table))
	}
	if rev, _ := r.Data["rev"].(int64); rev != r.Rev {
		return fmt.Errorf("%s: data.rev %v does not match rev %d", r.Table, r.Data["rev"], r.Rev)
	}
	return nil
}

// Apply stores one batch atomically: rows upsert by (host, instance, key) when their rev is newer,
// the host's last report time is refreshed, and the cursor advances to the highest rev seen. It
// returns the new cursor.
func (d *DB) Apply(b wire.Batch, now time.Time) (int64, error) {
	if b.SchemaVersion != wire.SchemaVersion {
		return 0, fmt.Errorf("%w %d (this server mirrors %d)", ErrSchemaVersion, b.SchemaVersion, wire.SchemaVersion)
	}
	if b.Host.UUID == "" || b.DBInstance == "" {
		return 0, &ValidationError{"host.uuid and db_instance are required"}
	}
	if len(b.Rows) > wire.MaxRows {
		return 0, &ValidationError{fmt.Sprintf("%d rows exceeds the limit of %d", len(b.Rows), wire.MaxRows)}
	}
	for i, r := range b.Rows {
		if err := validateRow(r); err != nil {
			return 0, &ValidationError{fmt.Sprintf("rows[%d]: %v", i, err)}
		}
	}
	tx, err := d.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	ns := now.UnixNano()
	if _, err := tx.Exec(`INSERT INTO hosts (uuid, name, first_seen, last_report_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (uuid) DO UPDATE SET name = excluded.name, last_report_at = excluded.last_report_at`,
		b.Host.UUID, b.Host.Name, ns, ns); err != nil {
		return 0, err
	}
	var maxRev int64
	for _, r := range b.Rows {
		cols := wire.Columns[r.Table]
		args := make([]any, 0, len(cols)+2)
		args = append(args, b.Host.UUID, b.DBInstance)
		for _, c := range cols {
			v := r.Data[c]
			if bv, ok := v.(bool); ok {
				v = map[bool]int64{false: 0, true: 1}[bv]
			}
			args = append(args, v)
		}
		if _, err := tx.Exec(upserts[r.Table], args...); err != nil {
			return 0, fmt.Errorf("serverdb: upsert %s: %w", r.Table, err)
		}
		maxRev = max(maxRev, r.Rev)
	}
	if _, err := tx.Exec(`INSERT INTO sync_state (host_uuid, db_instance, rev, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (host_uuid, db_instance) DO UPDATE SET rev = max(sync_state.rev, excluded.rev), updated_at = excluded.updated_at`,
		b.Host.UUID, b.DBInstance, maxRev, ns); err != nil {
		return 0, err
	}
	var cur int64
	if err := tx.QueryRow(`SELECT rev FROM sync_state WHERE host_uuid = ? AND db_instance = ?`, b.Host.UUID, b.DBInstance).Scan(&cur); err != nil {
		return 0, err
	}
	return cur, tx.Commit()
}

// Cursor is the highest revision stored for an endpoint database, 0 if none.
func (d *DB) Cursor(hostUUID, dbInstance string) (int64, error) {
	var cur int64
	err := d.DB.QueryRow(`SELECT rev FROM sync_state WHERE host_uuid = ? AND db_instance = ?`, hostUUID, dbInstance).Scan(&cur)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return cur, err
}
