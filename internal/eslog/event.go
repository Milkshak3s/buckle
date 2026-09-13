// Package eslog parses eslogger(1) JSON lines for the exec, fork and exit events buckle needs.
//
// eslogger's output is explicitly not API, so only the fields buckle uses are decoded, and a
// missing required field is reported as a *DriftError rather than silently zero-valued.
package eslog

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Token identifies one process image: exec assigns a new pidversion to the same pid.
type Token struct {
	PID        int
	PIDVersion int
}

// Proc is the subset of es_process_t buckle uses.
type Proc struct {
	Token      Token
	Parent     Token
	PPID       int
	Path       string
	IsPlatform bool
	SigningID  string
	TeamID     string
	CDHash     string
	StartTime  time.Time
}

type Kind int

const (
	KindExec Kind = iota + 1
	KindFork
	KindExit
)

func (k Kind) String() string {
	switch k {
	case KindExec:
		return "exec"
	case KindFork:
		return "fork"
	case KindExit:
		return "exit"
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

// Event is one exec, fork or exit.
type Event struct {
	Kind          Kind
	Time          time.Time
	Seq           uint64
	Process       Proc     // exec: pre-exec image; fork: parent; exit: exiting image
	Target        Proc     // exec: new image; fork: child
	Args          []string // exec only
	Cwd           string   // exec only
	ExitStatus    int      // exit only
	SchemaVersion int
}

// ErrSkip is returned for well-formed events of a kind buckle doesn't handle.
var ErrSkip = errors.New("eslog: not an exec/fork/exit event")

// DriftError reports a required field that is missing or has an unexpected type.
type DriftError struct {
	Field string
}

func (e *DriftError) Error() string {
	return "eslogger schema drift: missing or invalid field " + e.Field
}

type rawToken struct {
	PID        *int `json:"pid"`
	PIDVersion *int `json:"pidversion"`
}

type rawProc struct {
	AuditToken       *rawToken `json:"audit_token"`
	ParentAuditToken *rawToken `json:"parent_audit_token"`
	PPID             int       `json:"ppid"`
	IsPlatformBinary bool      `json:"is_platform_binary"`
	SigningID        *string   `json:"signing_id"`
	TeamID           *string   `json:"team_id"`
	CDHash           string    `json:"cdhash"`
	Executable       *struct {
		Path *string `json:"path"`
	} `json:"executable"`
	StartTime string `json:"start_time"`
}

type rawMsg struct {
	SchemaVersion int                        `json:"schema_version"`
	Time          *string                    `json:"time"`
	Seq           uint64                     `json:"global_seq_num"`
	Process       json.RawMessage            `json:"process"`
	Event         map[string]json.RawMessage `json:"event"`
}

// Parse decodes one eslogger JSON line.
func Parse(line []byte) (Event, error) {
	var m rawMsg
	if err := json.Unmarshal(line, &m); err != nil {
		return Event{}, fmt.Errorf("eslog: %w", err)
	}
	var ev Event
	var body json.RawMessage
	for _, k := range []Kind{KindExec, KindFork, KindExit} {
		if b, ok := m.Event[k.String()]; ok {
			ev.Kind, body = k, b
			break
		}
	}
	if ev.Kind == 0 {
		return Event{}, ErrSkip
	}
	ev.SchemaVersion = m.SchemaVersion
	ev.Seq = m.Seq

	if m.Time == nil {
		return Event{}, &DriftError{Field: "time"}
	}
	t, err := time.Parse(time.RFC3339Nano, *m.Time)
	if err != nil {
		return Event{}, &DriftError{Field: "time"}
	}
	ev.Time = t

	if ev.Process, err = decodeProc(m.Process, "process", true); err != nil {
		return Event{}, err
	}

	prefix := "event." + ev.Kind.String()
	switch ev.Kind {
	case KindExec:
		var x struct {
			Target json.RawMessage `json:"target"`
			Args   *[]string       `json:"args"`
			Cwd    *struct {
				Path string `json:"path"`
			} `json:"cwd"`
		}
		if err := json.Unmarshal(body, &x); err != nil {
			return Event{}, &DriftError{Field: prefix}
		}
		if ev.Target, err = decodeProc(x.Target, prefix+".target", true); err != nil {
			return Event{}, err
		}
		if x.Args == nil {
			return Event{}, &DriftError{Field: prefix + ".args"}
		}
		ev.Args = *x.Args
		if x.Cwd != nil {
			ev.Cwd = x.Cwd.Path
		}
	case KindFork:
		var x struct {
			Child json.RawMessage `json:"child"`
		}
		if err := json.Unmarshal(body, &x); err != nil {
			return Event{}, &DriftError{Field: prefix}
		}
		if ev.Target, err = decodeProc(x.Child, prefix+".child", false); err != nil {
			return Event{}, err
		}
		if ev.Target.Path == "" {
			ev.Target.Path = ev.Process.Path
		}
	case KindExit:
		var x struct {
			Stat int `json:"stat"`
		}
		if err := json.Unmarshal(body, &x); err != nil {
			return Event{}, &DriftError{Field: prefix + ".stat"}
		}
		ev.ExitStatus = x.Stat
	}
	return ev, nil
}

func decodeProc(b json.RawMessage, field string, needPath bool) (Proc, error) {
	if len(b) == 0 || string(b) == "null" {
		return Proc{}, &DriftError{Field: field}
	}
	var r rawProc
	if err := json.Unmarshal(b, &r); err != nil {
		return Proc{}, &DriftError{Field: field}
	}
	if r.AuditToken == nil || r.AuditToken.PID == nil || r.AuditToken.PIDVersion == nil {
		return Proc{}, &DriftError{Field: field + ".audit_token"}
	}
	p := Proc{
		Token:      Token{*r.AuditToken.PID, *r.AuditToken.PIDVersion},
		PPID:       r.PPID,
		IsPlatform: r.IsPlatformBinary,
		CDHash:     r.CDHash,
	}
	if r.ParentAuditToken != nil && r.ParentAuditToken.PID != nil && r.ParentAuditToken.PIDVersion != nil {
		p.Parent = Token{*r.ParentAuditToken.PID, *r.ParentAuditToken.PIDVersion}
	}
	if r.SigningID != nil {
		p.SigningID = *r.SigningID
	}
	if r.TeamID != nil {
		p.TeamID = *r.TeamID
	}
	if r.Executable != nil && r.Executable.Path != nil {
		p.Path = *r.Executable.Path
	} else if needPath {
		return Proc{}, &DriftError{Field: field + ".executable.path"}
	}
	if r.StartTime != "" {
		if st, err := time.Parse(time.RFC3339Nano, r.StartTime); err == nil {
			p.StartTime = st
		}
	}
	return p, nil
}
