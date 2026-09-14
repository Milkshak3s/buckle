package detect

import (
	"slices"
	"testing"
)

const claudeTag = "CMD64_dG9vbHVfMDE=_END__k3j9x0q2m_SBX"

const cursorProfile = "(version 1)\n; start with closed-by-default\n(deny default)\n; Added on top of Chrome profile\n(allow process-exec)\n"

func TestRunClaude(t *testing.T) {
	d, m, ok := Run(RunStart{ProfileText: "(version 1)\n(deny default (with message \"" + claudeTag + "\"))"})
	if !ok || d.Kind() != "claude-code" {
		t.Fatalf("Run = %v, %v", d, ok)
	}
	if m != (Match{Key: "_k3j9x0q2m_SBX", Detail: "toolu_01", Raw: claudeTag}) {
		t.Errorf("match = %+v", m)
	}
}

func TestRunCursor(t *testing.T) {
	env := map[string]string{"CURSOR_CONVERSATION_ID": "e5ea23fc-ee23-4fad-acb0-0a0db9c3e6cc", "CURSOR_REQUEST_ID": "efbe69ab-92e7-459b-aa1f-61b305bdc45f"}
	d, m, ok := Run(RunStart{ProfileText: cursorProfile, Env: env})
	if !ok || d.Kind() != "cursor" {
		t.Fatalf("Run = %v, %v", d, ok)
	}
	if m != (Match{Key: env["CURSOR_CONVERSATION_ID"], Detail: env["CURSOR_REQUEST_ID"]}) {
		t.Errorf("match = %+v", m)
	}

	_, m, ok = Run(RunStart{ProfileText: cursorProfile})
	if !ok || m != (Match{Key: CursorUnknownKey}) {
		t.Errorf("no env: %+v, %v; want the unknown sentinel session", m, ok)
	}
}

func TestRunNoMatch(t *testing.T) {
	// Cursor's env alone doesn't make a run Cursor's: the profile fingerprint decides.
	if d, _, ok := Run(RunStart{ProfileText: "(version 1)(allow default)", Env: map[string]string{"CURSOR_AGENT": "1"}}); ok {
		t.Errorf("Run matched %s", d.Kind())
	}
}

func TestRunOrderFirstMatchWins(t *testing.T) {
	d, _, ok := Run(RunStart{ProfileText: cursorProfile + "; " + claudeTag})
	if !ok || d.Kind() != "claude-code" {
		t.Errorf("Run = %v, %v; want claude-code, registered first", d, ok)
	}
}

func TestDenial(t *testing.T) {
	d, m, ok := Denial("Sandbox: cat(1) deny(1) file-read-data /x\n" + claudeTag)
	if !ok || d.Kind() != "claude-code" || m.Key != "_k3j9x0q2m_SBX" {
		t.Errorf("Denial = %v, %+v, %v", d, m, ok)
	}
	if _, _, ok := Denial(cursorProfile); ok {
		t.Error("Cursor has no denial detector")
	}
	if _, _, ok := Denial(""); ok {
		t.Error("empty message matched")
	}
}

func TestByKind(t *testing.T) {
	for _, d := range All {
		got, ok := ByKind(d.Kind())
		if !ok || got.DisplayName() != d.DisplayName() {
			t.Errorf("ByKind(%q) = %v, %v", d.Kind(), got, ok)
		}
	}
	if _, ok := ByKind("nope"); ok {
		t.Error("ByKind(unknown) matched")
	}
}

func TestEnvNames(t *testing.T) {
	want := []string{"CURSOR_AGENT", "CURSOR_CONVERSATION_ID", "CURSOR_REQUEST_ID", "CURSOR_SANDBOX"}
	if got := EnvNames(); !slices.Equal(got, want) {
		t.Errorf("EnvNames = %v, want %v", got, want)
	}
}

func TestPickEnv(t *testing.T) {
	got := PickEnv([]string{"PATH=/bin", "CURSOR_AGENT=1", "CURSOR_API_KEY=secret", "CURSOR_AGENT=2", "CURSOR_REQUEST_ID=a=b", "junk"})
	if len(got) != 2 || got["CURSOR_AGENT"] != "1" || got["CURSOR_REQUEST_ID"] != "a=b" {
		t.Errorf("PickEnv = %v", got)
	}
	if got := PickEnv([]string{"PATH=/bin"}); got != nil {
		t.Errorf("PickEnv(no declared) = %v, want nil", got)
	}
}
