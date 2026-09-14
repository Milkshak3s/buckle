// Package detect recognizes which agent launched a sandbox run and which of its sessions the run
// belongs to. Detectors are compiled in; every one sees every run and the first match claims it.
//
// To add an agent: implement Detector (and DenialDetector if its denial log lines carry a
// recognizable tag), then append it to All. Kind values are stored in sessions.kind, so never
// rename one.
package detect

import (
	"slices"
	"strings"
)

// RunStart is what a detector sees when a sandbox-exec run starts.
type RunStart struct {
	ProfileText string
	Argv        []string
	Env         map[string]string // only the names in EnvNames()
}

// Match is a detector's verdict for one run.
type Match struct {
	Key    string // session key, unique within the detector's kind
	Detail string // stored in runs.tag_command and shown under DetailLabel
	Raw    string // stored in runs.tag; "" when the agent has no tag
}

type Detector interface {
	Kind() string        // sessions.kind value, e.g. "claude-code"
	DisplayName() string // e.g. "Claude Code"
	DetailLabel() string // label for Match.Detail, e.g. "Claude tool use"
	EnvVars() []string   // exact environment variable names to read and store
	DetectRun(RunStart) (Match, bool)
}

// DenialDetector is implemented by detectors whose denial messages identify the session. It lets
// buckle attach a session to a run from a later denial and adopt runs that started before watch.
type DenialDetector interface {
	Detector
	DetectDenial(message string) (Match, bool)
}

// All is the registry, in match order.
var All = []Detector{Claude{}, Cursor{}}

// Run returns the first detector that claims rs.
func Run(rs RunStart) (Detector, Match, bool) {
	for _, d := range All {
		if m, ok := d.DetectRun(rs); ok {
			return d, m, true
		}
	}
	return nil, Match{}, false
}

// Denial returns the first denial detector that recognizes message.
func Denial(message string) (DenialDetector, Match, bool) {
	if message == "" {
		return nil, Match{}, false
	}
	for _, d := range All {
		dd, ok := d.(DenialDetector)
		if !ok {
			continue
		}
		if m, ok := dd.DetectDenial(message); ok {
			return dd, m, true
		}
	}
	return nil, Match{}, false
}

// ByKind looks up a detector by its stored kind.
func ByKind(kind string) (Detector, bool) {
	for _, d := range All {
		if d.Kind() == kind {
			return d, true
		}
	}
	return nil, false
}

// EnvNames is the sorted union of every detector's EnvVars.
func EnvNames() []string {
	var names []string
	for _, d := range All {
		names = append(names, d.EnvVars()...)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// PickEnv keeps the declared variables from KEY=value entries. As with getenv, the first entry
// for a name wins. It returns nil when none are present.
func PickEnv(env []string) map[string]string {
	names := EnvNames()
	var out map[string]string
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !slices.Contains(names, k) {
			continue
		}
		if _, dup := out[k]; dup {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[k] = v
	}
	return out
}
