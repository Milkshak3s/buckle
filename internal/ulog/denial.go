// Package ulog parses kernel Sandbox denial lines from `log stream --style ndjson`.
package ulog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Denial is one `Sandbox: name(pid) deny(n) operation target` line, or a duplicate-report line.
type Denial struct {
	Time      time.Time
	MachTime  uint64
	Name      string
	PID       int
	DenyN     int
	Operation string
	Target    string // may be empty
	Message   string // text after the first newline, e.g. a `with message` tag
	Duplicate int    // N from "N duplicate report(s) for"; 0 for an original line
}

// ErrSkip is returned for lines that are not denials: the banner, the trailer, allow lines,
// System Policy lines, and anything else the Sandbox sender logs.
var ErrSkip = errors.New("ulog: not a denial")

const timeLayout = "2006-01-02 15:04:05.000000-0700"

var denialRE = regexp.MustCompile(`(?s)^(?:(\d+) duplicate reports? for )?Sandbox: (.+)\((\d+)\) deny\((\d+)\) (\S+)(?: ([^\n]*))?(?:\n(.*))?$`)

type rawLine struct {
	EventMessage  *string `json:"eventMessage"`
	Timestamp     string  `json:"timestamp"`
	MachTimestamp uint64  `json:"machTimestamp"`
}

// Parse decodes one ndjson line.
func Parse(line []byte) (Denial, error) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return Denial{}, ErrSkip
	}
	var r rawLine
	if err := json.Unmarshal(line, &r); err != nil {
		return Denial{}, fmt.Errorf("ulog: %w", err)
	}
	if r.EventMessage == nil {
		return Denial{}, ErrSkip
	}
	m := denialRE.FindStringSubmatch(*r.EventMessage)
	if m == nil {
		return Denial{}, ErrSkip
	}
	t, err := time.Parse(timeLayout, r.Timestamp)
	if err != nil {
		return Denial{}, fmt.Errorf("ulog: timestamp %q: %w", r.Timestamp, err)
	}
	d := Denial{
		Time:      t,
		MachTime:  r.MachTimestamp,
		Name:      m[2],
		Operation: m[5],
		Target:    m[6],
		Message:   strings.TrimSpace(m[7]),
	}
	if d.PID, err = strconv.Atoi(m[3]); err != nil {
		return Denial{}, ErrSkip
	}
	if d.DenyN, err = strconv.Atoi(m[4]); err != nil {
		return Denial{}, ErrSkip
	}
	if m[1] != "" {
		if d.Duplicate, err = strconv.Atoi(m[1]); err != nil {
			return Denial{}, ErrSkip
		}
	}
	return d, nil
}
