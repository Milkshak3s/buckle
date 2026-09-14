package detect

import "strings"

// Cursor recognizes cursor-agent's cursorsandbox helper, which runs sandbox-exec with an inline
// profile containing cursorFingerprint. The profile carries no session tag, so the session comes
// from the environment the agent sets on every shell command (verified with cursor-agent
// 2026.09.10). Its denials are untagged: no DetectDenial, so no pre-watch adoption.
type Cursor struct{}

const (
	cursorFingerprint = "; Added on top of Chrome profile"
	// CursorUnknownKey groups fingerprinted runs whose conversation id is missing.
	CursorUnknownKey = "unknown"
)

func (Cursor) Kind() string        { return "cursor" }
func (Cursor) DisplayName() string { return "Cursor" }
func (Cursor) DetailLabel() string { return "Cursor request" }

func (Cursor) EnvVars() []string {
	return []string{"CURSOR_AGENT", "CURSOR_CONVERSATION_ID", "CURSOR_REQUEST_ID", "CURSOR_SANDBOX"}
}

func (Cursor) DetectRun(rs RunStart) (Match, bool) {
	if !strings.Contains(rs.ProfileText, cursorFingerprint) {
		return Match{}, false
	}
	key := rs.Env["CURSOR_CONVERSATION_ID"]
	if key == "" {
		key = CursorUnknownKey
	}
	return Match{Key: key, Detail: rs.Env["CURSOR_REQUEST_ID"]}, true
}
