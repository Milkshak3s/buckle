package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func argsJSON(t *testing.T, args ...string) string {
	t.Helper()
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNewArgsView(t *testing.T) {
	profile := strings.Repeat("(allow default)\n", 1500) // 24000 bytes, like Claude Code's profile
	long := strings.Repeat("a", 5000)
	medium := "source /Users/me/.claude/shell-snapshots/snapshot.sh && eval '" + strings.Repeat("echo hi; ", 45) + "'"

	cases := []struct {
		name, path string
		js         string
		text       string
		full       bool
	}{
		{
			name: "detached inline profile",
			path: "/usr/bin/sandbox-exec",
			js:   argsJSON(t, "/usr/bin/sandbox-exec", "-p", profile, "/bin/zsh", "-c", "echo hi"),
			text: "/usr/bin/sandbox-exec -p <inline profile, 24000 bytes: see Profile text> /bin/zsh -c 'echo hi'",
			full: true,
		},
		{
			name: "attached inline profile",
			path: "/usr/bin/sandbox-exec",
			js:   argsJSON(t, "/usr/bin/sandbox-exec", "-p"+profile, "/usr/bin/true"),
			text: "/usr/bin/sandbox-exec -p<inline profile, 24000 bytes: see Profile text> /usr/bin/true",
			full: true,
		},
		{
			name: "file profile untouched",
			path: "/usr/bin/sandbox-exec",
			js:   argsJSON(t, "/usr/bin/sandbox-exec", "-f", "/private/tmp/p.sb", "/bin/cat"),
			text: "/usr/bin/sandbox-exec -f /private/tmp/p.sb /bin/cat",
		},
		{
			name: "medium argument shown in full",
			path: "/bin/zsh",
			js:   argsJSON(t, "/bin/zsh", "-c", medium),
			text: argv(argsJSON(t, "/bin/zsh", "-c", medium)),
		},
		{
			name: "very long argument elided",
			path: "/bin/echo",
			js:   argsJSON(t, "/bin/echo", long),
			text: "/bin/echo " + strings.Repeat("a", 200) + "…<4800 more bytes>",
			full: true,
		},
		{
			name: "invalid JSON falls back to raw",
			path: "/bin/echo",
			js:   `not json`,
			text: `not json`,
		},
	}
	for _, c := range cases {
		v := newArgsView(c.path, c.js)
		if v.Text != c.text {
			t.Errorf("%s: Text = %q\nwant %q", c.name, v.Text, c.text)
		}
		if c.full != (v.Full != "") {
			t.Errorf("%s: Full set = %v, want %v", c.name, v.Full != "", c.full)
		}
		if c.full && v.Full != argv(c.js) {
			t.Errorf("%s: Full is not the complete quoted argv", c.name)
		}
	}
}
