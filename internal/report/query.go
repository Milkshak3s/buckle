package report

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// LowerBoundNote accompanies denial output (DESIGN §4.6).
const LowerBoundNote = "denial counts are lower bounds: the kernel drops many denial log lines, mostly from non-platform binaries"

type Filter struct {
	Since, Until *time.Time
	Session      string // session key, e.g. _k3j9x0q2m_SBX or a Cursor conversation id
	Command      string // substring of the space-joined command or the run's tag_command
	HasDenials   bool
}

// runWhere builds conditions over runs r LEFT JOIN sessions s.
func runWhere(f Filter, timeCol string) (string, []any) {
	var conds []string
	var args []any
	if f.Since != nil {
		conds = append(conds, timeCol+" >= ?")
		args = append(args, f.Since.UnixNano())
	}
	if f.Until != nil {
		conds = append(conds, timeCol+" < ?")
		args = append(args, f.Until.UnixNano())
	}
	if f.Session != "" {
		conds = append(conds, "s.key = ?")
		args = append(args, f.Session)
	}
	if f.Command != "" {
		conds = append(conds, `(instr(coalesce((SELECT group_concat(value, ' ') FROM json_each(r.command_json)), ''), ?) > 0
			OR instr(coalesce(r.tag_command, ''), ?) > 0)`)
		args = append(args, f.Command, f.Command)
	}
	if f.HasDenials {
		conds = append(conds, "EXISTS (SELECT 1 FROM denials d WHERE d.run_id = r.id)")
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// Runs lists runs matching f, oldest first.
func Runs(db *sql.DB, f Filter) ([]Record, []string, error) {
	where, args := runWhere(f, "r.started_at")
	return query(db, `SELECT r.id, r.kind, r.status, r.started_at, r.ended_at, r.started_before_watch,
		s.key AS session, r.tag_command, r.command_json, r.profile_source, r.profile_name, r.profile_path,
		r.parent_run_id,
		(SELECT count(*) FROM processes p WHERE p.run_id = r.id) AS process_count,
		(SELECT count(*) FROM processes p WHERE p.run_id = r.id AND p.is_platform_binary = 0) AS nonplatform_process_count,
		(SELECT coalesce(sum(d.count), 0) FROM denials d WHERE d.run_id = r.id) AS denial_count
		FROM runs r LEFT JOIN sessions s ON s.id = r.session_id`+where+`
		ORDER BY r.started_at, r.id`, args...)
}

// Sessions lists sessions that have at least one run matching f.
func Sessions(db *sql.DB, f Filter) ([]Record, []string, error) {
	where, args := runWhere(f, "r.started_at")
	match := "SELECT r.id FROM runs r LEFT JOIN sessions s ON s.id = r.session_id" + where
	if where == "" {
		match += " WHERE r.session_id = sess.id"
	} else {
		match += " AND r.session_id = sess.id"
	}
	q := `SELECT sess.id, sess.kind, sess.key, sess.first_seen, sess.last_seen,
		(SELECT count(*) FROM (` + match + `)) AS run_count,
		(SELECT coalesce(sum(d.count), 0) FROM denials d WHERE d.run_id IN (` + match + `)) AS denial_count
		FROM sessions sess
		WHERE EXISTS (` + match + `)
		ORDER BY sess.first_seen, sess.id`
	all := append(append(append([]any{}, args...), args...), args...)
	return query(db, q, all...)
}

var ErrNotFound = errors.New("not found")

// RunDetail returns one run with its profile text, processes and denials.
func RunDetail(db *sql.DB, id int64) (Record, error) {
	runs, _, err := query(db, `SELECT r.id, r.kind, r.status, r.started_at, r.ended_at, r.started_before_watch,
		r.parent_run_id, s.kind AS session_kind, s.key AS session, r.tag, r.tag_command,
		r.command_json, r.cwd, r.profile_source, r.profile_name, r.profile_path, r.profile_error,
		r.profile_hash, p.text AS profile_text, r.params_json, r.extra_json, r.watch_id
		FROM runs r LEFT JOIN sessions s ON s.id = r.session_id LEFT JOIN profiles p ON p.hash = r.profile_hash
		WHERE r.id = ?`, id)
	if err != nil {
		return nil, err
	}
	if len(runs) == 0 {
		return nil, fmt.Errorf("run %d: %w", id, ErrNotFound)
	}
	procs, _, err := query(db, `SELECT id, pid, pidversion, parent_process_id, exec_prev_process_id, ppid, path,
		args_json, is_platform_binary, signing_id, team_id, cdhash, started_at, ended_at, end_reason, exit_status
		FROM processes WHERE run_id = ? ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	denials, _, err := Denials(db, id)
	if err != nil {
		return nil, err
	}
	rec := runs[0]
	rec = append(rec,
		Field{"processes", nonNil(procs)},
		Field{"denials", nonNil(denials)},
		Field{"note", LowerBoundNote})
	return rec, nil
}

// Denials lists one run's denials with their process identity.
func Denials(db *sql.DB, runID int64) ([]Record, []string, error) {
	return query(db, `SELECT d.id, d.time, d.process_name, d.pid, p.pidversion, p.id AS process_id, p.path,
		p.is_platform_binary, d.operation, d.target, d.message, d.count
		FROM denials d JOIN processes p ON p.id = d.process_id
		WHERE d.run_id = ? ORDER BY d.time, d.id`, runID)
}

// Aggregate groups denials across runs by operation and/or target, most frequent first.
func Aggregate(db *sql.DB, f Filter, by []string, top int) ([]Record, []string, error) {
	if len(by) == 0 {
		by = []string{"operation", "target"}
	}
	var cols []string
	for _, b := range by {
		switch b {
		case "operation", "target":
			cols = append(cols, "d."+b)
		default:
			return nil, nil, fmt.Errorf("cannot group by %q (want operation and/or target)", b)
		}
	}
	group := strings.Join(cols, ", ")
	f.HasDenials = false
	where, args := runWhere(f, "d.time")
	if top <= 0 {
		top = 50
	}
	args = append(args, top)
	return query(db, `SELECT `+group+`, sum(d.count) AS total_count, count(DISTINCT d.run_id) AS run_count,
		sum(CASE WHEN p.is_platform_binary = 0 THEN d.count ELSE 0 END) AS nonplatform_count,
		min(d.time) AS first_seen, max(d.time) AS last_seen
		FROM denials d JOIN runs r ON r.id = d.run_id JOIN processes p ON p.id = d.process_id
		LEFT JOIN sessions s ON s.id = r.session_id`+where+`
		GROUP BY `+group+` ORDER BY total_count DESC, `+group+` LIMIT ?`, args...)
}

func query(db *sql.DB, q string, args ...any) ([]Record, []string, error) {
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, nil, err
	}
	return scanRecords(rows)
}

func nonNil(r []Record) []Record {
	if r == nil {
		return []Record{}
	}
	return r
}
