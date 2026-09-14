package main

import (
	"strings"
	"testing"

	"buckle/internal/detect"
)

func TestStrip(t *testing.T) {
	in := `{"event":{"exec":{"env":["HOME=/Users/me","CURSOR_CONVERSATION_ID=c","GITHUB_TOKEN=secret","CURSOR_AGENT=1"],"args":["/bin/zsh","a && b"]}},"global_seq_num":18446744073709551615}`
	out, err := strip([]byte(in), detect.EnvNames())
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{`"env":["CURSOR_CONVERSATION_ID=c","CURSOR_AGENT=1"]`, `"a && b"`, `18446744073709551615`} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %s: %s", want, got)
		}
	}
	if strings.Contains(got, "secret") || strings.Contains(got, "HOME") {
		t.Errorf("undeclared variables kept: %s", got)
	}

	fork := `{"event":{"fork":{}}}`
	if out, _ := strip([]byte(fork), detect.EnvNames()); string(out) != fork {
		t.Errorf("line without env changed: %s", out)
	}
	if _, err := strip([]byte(`"env" not json`), detect.EnvNames()); err == nil {
		t.Error("garbage line containing env should fail")
	}
}
