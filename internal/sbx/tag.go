package sbx

import (
	"encoding/base64"
	"regexp"
)

// Tag is a Claude Code sandbox log tag: CMD64_<base64 command>_END_<suffix>, where the suffix
// (_<random>_SBX) is fixed for one Claude Code process and serves as the session key.
type Tag struct {
	Raw        string
	CommandB64 string
	Command    string // "" if the base64 doesn't decode
	Suffix     string
}

var tagRE = regexp.MustCompile(`CMD64_([A-Za-z0-9+/=]*)_END_(_[A-Za-z0-9]+_SBX)`)

// FindTag returns the first Claude Code tag in text.
func FindTag(text string) (Tag, bool) {
	m := tagRE.FindStringSubmatch(text)
	if m == nil {
		return Tag{}, false
	}
	t := Tag{Raw: m[0], CommandB64: m[1], Suffix: m[2]}
	if b, err := base64.StdEncoding.DecodeString(m[1]); err == nil {
		t.Command = string(b)
	}
	return t, true
}
