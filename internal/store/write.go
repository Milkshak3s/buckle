package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"
)

// PathForHome is the database location inside a user's home directory.
func PathForHome(home string) string {
	return filepath.Join(home, "Library", "Application Support", "buckle", "buckle.db")
}

// Run is a new row in runs. ProfileText, when non-empty, is stored in profiles by SHA-256.
type Run struct {
	WatchID            int64
	Kind               string // sandbox-exec | sandbox-init | adopted
	ParentRunID        *int64
	SessionID          *int64
	Tag, TagCommand    string
	StartedAt          time.Time
	StartedBeforeWatch bool
	ProfileSource      string // inline | file | named | unknown
	ProfileText        string
	ProfilePath        string
	ProfileName        string
	ProfileError       string
	Params             [][2]string
	Extra              []string
	Command            []string
	Cwd                string
}

// Process is a new row in processes: one process image (audit token).
type Process struct {
	RunID             int64
	PID               int
	PIDVersion        *int
	ParentProcessID   *int64
	ExecPrevProcessID *int64
	PPID              int
	Path              string
	Args              []string
	IsPlatform        *bool
	SigningID         string
	TeamID            string
	CDHash            string
	StartedAt         *time.Time
}

type Denial struct {
	RunID, ProcessID int64
	Time             time.Time
	ProcessName      string
	PID              int
	Operation        string
	Target           string
	Message          string
	Count            int
}

type Orphan struct {
	WatchID        int64
	Time           time.Time
	ProcessName    string
	PID            int
	Operation      string
	Target         string
	Message        string
	Count          int
	LastPath       string
	LastPIDVersion *int
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UnixNano()
}

// jsonArray encodes v without HTML escaping, so substring filters on commands like `a && b` work.
func jsonArray(v any, empty bool) string {
	if empty {
		return "[]"
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "[]"
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) BeginWatch(start time.Time, osVersion string, buffer time.Duration) (int64, error) {
	res, err := s.DB.Exec(`INSERT INTO watches (started_at, os_version, buffer_ns) VALUES (?, ?, ?)`,
		start.UnixNano(), nullStr(osVersion), int64(buffer))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) EndWatch(id int64, t time.Time, reason string) error {
	_, err := s.DB.Exec(`UPDATE watches SET ended_at = ?, end_reason = ? WHERE id = ?`, t.UnixNano(), reason, id)
	return err
}

// EnsureSession returns the id for (kind, key), creating it or bumping last_seen.
func (s *Store) EnsureSession(kind, key string, t time.Time) (int64, error) {
	var id int64
	err := s.DB.QueryRow(`INSERT INTO sessions (kind, key, first_seen, last_seen) VALUES (?, ?, ?, ?)
		ON CONFLICT (kind, key) DO UPDATE SET
		  last_seen = max(last_seen, excluded.last_seen),
		  first_seen = min(first_seen, excluded.first_seen)
		RETURNING id`, kind, key, t.UnixNano(), t.UnixNano()).Scan(&id)
	return id, err
}

func (s *Store) InsertRun(r Run) (int64, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var hash any
	if r.ProfileText != "" {
		sum := sha256.Sum256([]byte(r.ProfileText))
		h := hex.EncodeToString(sum[:])
		if _, err := tx.Exec(`INSERT OR IGNORE INTO profiles (hash, text) VALUES (?, ?)`, h, r.ProfileText); err != nil {
			return 0, err
		}
		hash = h
	}
	res, err := tx.Exec(`INSERT INTO runs (watch_id, kind, parent_run_id, session_id, tag, tag_command, started_at, status,
		started_before_watch, profile_source, profile_hash, profile_path, profile_name, profile_error,
		params_json, extra_json, command_json, cwd)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.WatchID, r.Kind, r.ParentRunID, r.SessionID, nullStr(r.Tag), nullStr(r.TagCommand), r.StartedAt.UnixNano(),
		boolInt(r.StartedBeforeWatch), r.ProfileSource, hash, nullStr(r.ProfilePath), nullStr(r.ProfileName), nullStr(r.ProfileError),
		jsonArray(r.Params, len(r.Params) == 0), jsonArray(r.Extra, len(r.Extra) == 0), jsonArray(r.Command, len(r.Command) == 0),
		nullStr(r.Cwd))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// SetRunSession attaches a session to a run that has none yet.
func (s *Store) SetRunSession(runID, sessionID int64, tag, tagCommand string) error {
	_, err := s.DB.Exec(`UPDATE runs SET session_id = ?, tag = ?, tag_command = ? WHERE id = ? AND session_id IS NULL`,
		sessionID, nullStr(tag), nullStr(tagCommand), runID)
	return err
}

// EndRun sets a run's final status. t is nil when the end time is unknown (watch stopped).
func (s *Store) EndRun(runID int64, t *time.Time, status string) error {
	_, err := s.DB.Exec(`UPDATE runs SET ended_at = ?, status = ? WHERE id = ?`, nullTime(t), status, runID)
	return err
}

func (s *Store) InsertProcess(p Process) (int64, error) {
	var plat any
	if p.IsPlatform != nil {
		plat = boolInt(*p.IsPlatform)
	}
	res, err := s.DB.Exec(`INSERT INTO processes (run_id, pid, pidversion, parent_process_id, exec_prev_process_id, ppid, path,
		args_json, is_platform_binary, signing_id, team_id, cdhash, started_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.RunID, p.PID, p.PIDVersion, p.ParentProcessID, p.ExecPrevProcessID, p.PPID, nullStr(p.Path),
		jsonArray(p.Args, len(p.Args) == 0), plat, nullStr(p.SigningID), nullStr(p.TeamID), nullStr(p.CDHash), nullTime(p.StartedAt))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// EndProcess records how a process image ended. t is nil when unknown (watch stopped).
func (s *Store) EndProcess(id int64, t *time.Time, reason string, exitStatus *int) error {
	_, err := s.DB.Exec(`UPDATE processes SET ended_at = ?, end_reason = ?, exit_status = ? WHERE id = ?`,
		nullTime(t), reason, exitStatus, id)
	return err
}

func (s *Store) InsertDenial(d Denial) (int64, error) {
	res, err := s.DB.Exec(`INSERT INTO denials (run_id, process_id, time, process_name, pid, operation, target, message, count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.RunID, d.ProcessID, d.Time.UnixNano(), d.ProcessName, d.PID, d.Operation, d.Target, nullStr(d.Message), d.Count)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) AddDenialCount(id int64, n int) error {
	_, err := s.DB.Exec(`UPDATE denials SET count = count + ? WHERE id = ?`, n, id)
	return err
}

func (s *Store) InsertOrphan(o Orphan) (int64, error) {
	res, err := s.DB.Exec(`INSERT INTO orphans (watch_id, time, process_name, pid, operation, target, message, count, last_path, last_pidversion)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.WatchID, o.Time.UnixNano(), o.ProcessName, o.PID, o.Operation, o.Target, nullStr(o.Message), o.Count,
		nullStr(o.LastPath), o.LastPIDVersion)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}
