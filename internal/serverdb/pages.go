package serverdb

import (
	"database/sql"
	"errors"
)

var ErrNotFound = errors.New("not found")

type Host struct {
	UUID, Name            string
	FirstSeen, LastReport int64
	OSVersion             string
	Groups                []Group
}

type Group struct {
	DBInstance   string
	Sessions     []SessionSummary
	UntaggedRuns int64
}

type SessionSummary struct {
	ID                    int64
	Kind, Key             string
	FirstSeen, LastSeen   int64
	RunCount, DenialCount int64
}

type RunSummary struct {
	ID                        int64
	Kind, Status              string
	StartedAt                 int64
	EndedAt                   *int64
	CommandJSON               string
	ProcessCount, DenialCount int64
}

type Process struct {
	ID, PID                                        int64
	PIDVersion, ParentProcessID, ExecPrevProcessID *int64
	Path, ArgsJSON                                 string
	IsPlatform                                     *bool
	SigningID, TeamID                              string
	StartedAt, EndedAt                             *int64
	EndReason                                      string
	ExitStatus                                     *int64
}

type Denial struct {
	ID, ProcessID, Time        int64
	ProcessName                string
	PID                        int64
	Operation, Target, Message string
	Count                      int64
	IsPlatform                 *bool
}

type RunDetail struct {
	HostUUID, HostName, DBInstance                                                  string
	ID                                                                              int64
	Kind, Status                                                                    string
	StartedAt                                                                       int64
	EndedAt                                                                         *int64
	StartedBeforeWatch                                                              bool
	Cwd, Tag, TagCommand, CommandJSON, ParamsJSON                                   string
	SessionID                                                                       *int64
	SessionKey                                                                      string
	ParentRunID                                                                     *int64
	Children                                                                        []int64
	ProfileSource, ProfileName, ProfilePath, ProfileError, ProfileHash, ProfileText string
	ProfileMissing                                                                  bool
	Processes                                                                       []Process
	Denials                                                                         []Denial
}

func i64p(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	return &n.Int64
}

func boolp(n sql.NullInt64) *bool {
	if !n.Valid {
		return nil
	}
	b := n.Int64 != 0
	return &b
}

// Hosts lists every host, newest report first, with its sessions and untagged-run count per
// database instance.
func (d *DB) Hosts() ([]Host, error) {
	rows, err := d.DB.Query(`SELECT h.uuid, h.name, h.first_seen, h.last_report_at,
		coalesce((SELECT w.os_version FROM watches w WHERE w.host_uuid = h.uuid ORDER BY w.started_at DESC LIMIT 1), '')
		FROM hosts h ORDER BY h.last_report_at DESC, h.uuid`)
	if err != nil {
		return nil, err
	}
	var hosts []Host
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.UUID, &h.Name, &h.FirstSeen, &h.LastReport, &h.OSVersion); err != nil {
			rows.Close()
			return nil, err
		}
		hosts = append(hosts, h)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range hosts {
		insts, err := d.stringList(`SELECT db_instance FROM sync_state WHERE host_uuid = ? ORDER BY updated_at DESC`, hosts[i].UUID)
		if err != nil {
			return nil, err
		}
		for _, inst := range insts {
			g := Group{DBInstance: inst}
			if g.Sessions, err = d.sessions(hosts[i].UUID, inst); err != nil {
				return nil, err
			}
			if err := d.DB.QueryRow(`SELECT count(*) FROM runs WHERE host_uuid = ? AND db_instance = ? AND session_id IS NULL`,
				hosts[i].UUID, inst).Scan(&g.UntaggedRuns); err != nil {
				return nil, err
			}
			hosts[i].Groups = append(hosts[i].Groups, g)
		}
	}
	return hosts, nil
}

// HostName returns a host's name, or "" for a host that has never reported.
func (d *DB) HostName(uuid string) (string, error) {
	var name string
	err := d.DB.QueryRow(`SELECT coalesce(name, '') FROM hosts WHERE uuid = ?`, uuid).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return name, err
}

func (d *DB) stringList(q string, args ...any) ([]string, error) {
	rows, err := d.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

const sessionCols = `s.id, coalesce(s.kind, ''), coalesce(s.key, ''), coalesce(s.first_seen, 0), coalesce(s.last_seen, 0),
	(SELECT count(*) FROM runs r WHERE r.host_uuid = s.host_uuid AND r.db_instance = s.db_instance AND r.session_id = s.id),
	(SELECT coalesce(sum(dn.count), 0) FROM denials dn JOIN runs r
	   ON r.host_uuid = dn.host_uuid AND r.db_instance = dn.db_instance AND r.id = dn.run_id
	 WHERE r.host_uuid = s.host_uuid AND r.db_instance = s.db_instance AND r.session_id = s.id)`

func scanSession(sc interface{ Scan(...any) error }) (SessionSummary, error) {
	var s SessionSummary
	err := sc.Scan(&s.ID, &s.Kind, &s.Key, &s.FirstSeen, &s.LastSeen, &s.RunCount, &s.DenialCount)
	return s, err
}

func (d *DB) sessions(host, inst string) ([]SessionSummary, error) {
	rows, err := d.DB.Query(`SELECT `+sessionCols+` FROM sessions s WHERE s.host_uuid = ? AND s.db_instance = ?
		ORDER BY s.last_seen DESC, s.id DESC`, host, inst)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionSummary
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) runSummaries(where string, args ...any) ([]RunSummary, error) {
	rows, err := d.DB.Query(`SELECT r.id, coalesce(r.kind, ''), coalesce(r.status, ''), coalesce(r.started_at, 0), r.ended_at,
		coalesce(r.command_json, '[]'),
		(SELECT count(*) FROM processes p WHERE p.host_uuid = r.host_uuid AND p.db_instance = r.db_instance AND p.run_id = r.id),
		(SELECT coalesce(sum(dn.count), 0) FROM denials dn WHERE dn.host_uuid = r.host_uuid AND dn.db_instance = r.db_instance AND dn.run_id = r.id)
		FROM runs r WHERE r.host_uuid = ? AND r.db_instance = ? AND `+where+` ORDER BY r.started_at, r.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunSummary
	for rows.Next() {
		var s RunSummary
		var ended sql.NullInt64
		if err := rows.Scan(&s.ID, &s.Kind, &s.Status, &s.StartedAt, &ended, &s.CommandJSON, &s.ProcessCount, &s.DenialCount); err != nil {
			return nil, err
		}
		s.EndedAt = i64p(ended)
		out = append(out, s)
	}
	return out, rows.Err()
}

// SessionRuns returns a session and its runs. A session whose row hasn't arrived yet comes back with
// only its ID set, as long as some run references it.
func (d *DB) SessionRuns(host, inst string, id int64) (SessionSummary, []RunSummary, error) {
	s, err := scanSession(d.DB.QueryRow(`SELECT `+sessionCols+` FROM sessions s WHERE s.host_uuid = ? AND s.db_instance = ? AND s.id = ?`, host, inst, id))
	if errors.Is(err, sql.ErrNoRows) {
		s, err = SessionSummary{ID: id}, nil
	}
	if err != nil {
		return s, nil, err
	}
	runs, err := d.runSummaries(`r.session_id = ?`, host, inst, id)
	if err != nil {
		return s, nil, err
	}
	if s.Key == "" && len(runs) == 0 {
		return s, nil, ErrNotFound
	}
	return s, runs, nil
}

// UntaggedRuns lists runs with no Claude session.
func (d *DB) UntaggedRuns(host, inst string) ([]RunSummary, error) {
	return d.runSummaries(`r.session_id IS NULL`, host, inst)
}

// Run returns one run with its profile, processes, denials and child runs. Missing parents render
// as unknown: the session key is empty, the profile marked missing, denial platform flags nil.
func (d *DB) Run(host, inst string, id int64) (RunDetail, error) {
	r := RunDetail{HostUUID: host, DBInstance: inst}
	var ended, session, parent, sbw sql.NullInt64
	var profileText sql.NullString
	err := d.DB.QueryRow(`SELECT r.id, coalesce(r.kind, ''), coalesce(r.status, ''), coalesce(r.started_at, 0), r.ended_at,
		r.started_before_watch, coalesce(r.cwd, ''), coalesce(r.tag, ''), coalesce(r.tag_command, ''),
		coalesce(r.command_json, '[]'), coalesce(r.params_json, '[]'), r.session_id, coalesce(s.key, ''), r.parent_run_id,
		coalesce(r.profile_source, ''), coalesce(r.profile_name, ''), coalesce(r.profile_path, ''), coalesce(r.profile_error, ''),
		coalesce(r.profile_hash, ''), pr.text, coalesce(h.name, '')
		FROM runs r
		LEFT JOIN sessions s ON s.host_uuid = r.host_uuid AND s.db_instance = r.db_instance AND s.id = r.session_id
		LEFT JOIN profiles pr ON pr.host_uuid = r.host_uuid AND pr.db_instance = r.db_instance AND pr.hash = r.profile_hash
		LEFT JOIN hosts h ON h.uuid = r.host_uuid
		WHERE r.host_uuid = ? AND r.db_instance = ? AND r.id = ?`, host, inst, id).Scan(
		&r.ID, &r.Kind, &r.Status, &r.StartedAt, &ended, &sbw, &r.Cwd, &r.Tag, &r.TagCommand,
		&r.CommandJSON, &r.ParamsJSON, &session, &r.SessionKey, &parent,
		&r.ProfileSource, &r.ProfileName, &r.ProfilePath, &r.ProfileError, &r.ProfileHash, &profileText, &r.HostName)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.EndedAt, r.SessionID, r.ParentRunID = i64p(ended), i64p(session), i64p(parent)
	r.StartedBeforeWatch = sbw.Valid && sbw.Int64 != 0
	r.ProfileText = profileText.String
	r.ProfileMissing = r.ProfileHash != "" && !profileText.Valid

	children, err := d.DB.Query(`SELECT id FROM runs WHERE host_uuid = ? AND db_instance = ? AND parent_run_id = ? ORDER BY started_at, id`, host, inst, id)
	if err != nil {
		return r, err
	}
	for children.Next() {
		var c int64
		if err := children.Scan(&c); err != nil {
			children.Close()
			return r, err
		}
		r.Children = append(r.Children, c)
	}
	if err := children.Close(); err != nil {
		return r, err
	}

	procs, err := d.DB.Query(`SELECT id, coalesce(pid, 0), pidversion, parent_process_id, exec_prev_process_id, coalesce(path, ''),
		coalesce(args_json, '[]'), is_platform_binary, coalesce(signing_id, ''), coalesce(team_id, ''), started_at, ended_at,
		coalesce(end_reason, ''), exit_status
		FROM processes WHERE host_uuid = ? AND db_instance = ? AND run_id = ? ORDER BY id`, host, inst, id)
	if err != nil {
		return r, err
	}
	for procs.Next() {
		var p Process
		var pv, pp, ep, plat, st, en, es sql.NullInt64
		if err := procs.Scan(&p.ID, &p.PID, &pv, &pp, &ep, &p.Path, &p.ArgsJSON, &plat, &p.SigningID, &p.TeamID, &st, &en, &p.EndReason, &es); err != nil {
			procs.Close()
			return r, err
		}
		p.PIDVersion, p.ParentProcessID, p.ExecPrevProcessID = i64p(pv), i64p(pp), i64p(ep)
		p.IsPlatform, p.StartedAt, p.EndedAt, p.ExitStatus = boolp(plat), i64p(st), i64p(en), i64p(es)
		r.Processes = append(r.Processes, p)
	}
	if err := procs.Close(); err != nil {
		return r, err
	}

	dens, err := d.DB.Query(`SELECT dn.id, coalesce(dn.process_id, 0), coalesce(dn.time, 0), coalesce(dn.process_name, ''), coalesce(dn.pid, 0),
		coalesce(dn.operation, ''), coalesce(dn.target, ''), coalesce(dn.message, ''), coalesce(dn.count, 0), p.is_platform_binary
		FROM denials dn LEFT JOIN processes p ON p.host_uuid = dn.host_uuid AND p.db_instance = dn.db_instance AND p.id = dn.process_id
		WHERE dn.host_uuid = ? AND dn.db_instance = ? AND dn.run_id = ? ORDER BY dn.time, dn.id`, host, inst, id)
	if err != nil {
		return r, err
	}
	defer dens.Close()
	for dens.Next() {
		var dn Denial
		var plat sql.NullInt64
		if err := dens.Scan(&dn.ID, &dn.ProcessID, &dn.Time, &dn.ProcessName, &dn.PID, &dn.Operation, &dn.Target, &dn.Message, &dn.Count, &plat); err != nil {
			return r, err
		}
		dn.IsPlatform = boolp(plat)
		r.Denials = append(r.Denials, dn)
	}
	return r, dens.Err()
}
