package detect

import "buckle/internal/sbx"

// Claude recognizes Claude Code's sandbox log tag (DESIGN §2), found in the profile text and in
// denial messages. The session key is the tag suffix; the detail is the decoded payload, which is
// the tool_use id.
type Claude struct{}

func (Claude) Kind() string        { return "claude-code" }
func (Claude) DisplayName() string { return "Claude Code" }
func (Claude) DetailLabel() string { return "Claude tool use" }
func (Claude) EnvVars() []string   { return nil }

func (c Claude) DetectRun(rs RunStart) (Match, bool) { return c.DetectDenial(rs.ProfileText) }

func (Claude) DetectDenial(text string) (Match, bool) {
	tag, ok := sbx.FindTag(text)
	if !ok {
		return Match{}, false
	}
	return Match{Key: tag.Suffix, Detail: tag.Command, Raw: tag.Raw}, true
}
