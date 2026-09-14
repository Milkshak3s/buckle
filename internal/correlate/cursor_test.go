package correlate

import (
	"database/sql"
	"testing"

	"buckle/internal/eslog"
)

const cursorProfile = "(version 1)\n; start with closed-by-default\n(deny default)\n; Added on top of Chrome profile\n(allow process-exec)\n"

const (
	cursorConv = "e5ea23fc-ee23-4fad-acb0-0a0db9c3e6cc"
	cursorReq  = "efbe69ab-92e7-459b-aa1f-61b305bdc45f"
)

// sandboxEnv starts `sandbox-exec -p profile /bin/zsh -c true` as pid with the given exec env.
func (h *harness) sandboxEnv(pid, t0 int, profile string, env []string) (child, sbxImg eslog.Proc) {
	h.t.Helper()
	child = proc(pid, 1, "/bin/zsh", true)
	sbxImg = proc(pid, 2, "/usr/bin/sandbox-exec", true)
	h.fork(ms(t0), shell, child)
	h.es(eslog.Event{Kind: eslog.KindExec, Time: ms(t0 + 1), Process: child, Target: sbxImg, Cwd: "/w",
		Args: []string{"/usr/bin/sandbox-exec", "-p", profile, "-DWRITABLE_ROOT_0=/w", "/bin/zsh", "-c", "true"}, Env: env})
	return
}

func (h *harness) runEnv(runID int64) map[string]string {
	h.t.Helper()
	rows, err := h.s.DB.Query(`SELECT name, value FROM run_env WHERE run_id = ?`, runID)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		out[k] = v
	}
	return out
}

func TestCursorRunSession(t *testing.T) {
	h := newHarness(t, nil)
	h.sandboxEnv(300, 0, cursorProfile, []string{"PATH=/usr/bin", "CURSOR_AGENT=1", "CURSOR_CONVERSATION_ID=" + cursorConv,
		"CURSOR_REQUEST_ID=" + cursorReq, "CURSOR_SANDBOX=native", "CURSOR_API_KEY=secret"})
	h.sandboxEnv(301, 10, cursorProfile, []string{"CURSOR_CONVERSATION_ID=" + cursorConv, "CURSOR_REQUEST_ID=other"})

	var id, sessionID int64
	var tag sql.NullString
	var tagCmd string
	if err := h.s.DB.QueryRow(`SELECT id, session_id, tag, tag_command FROM runs ORDER BY id LIMIT 1`).Scan(&id, &sessionID, &tag, &tagCmd); err != nil {
		t.Fatal(err)
	}
	if tag.Valid || tagCmd != cursorReq {
		t.Errorf("tag = %v, tag_command = %q; want NULL and the request id", tag, tagCmd)
	}
	if n := h.n(`SELECT count(*) FROM sessions WHERE id = ? AND kind = 'cursor' AND key = ?`, sessionID, cursorConv); n != 1 {
		t.Error("run not in the conversation's cursor session")
	}
	if n := h.n(`SELECT count(DISTINCT session_id) FROM runs`); n != 1 {
		t.Errorf("two commands of one conversation span %d sessions", n)
	}
	env := h.runEnv(id)
	if len(env) != 4 || env["CURSOR_SANDBOX"] != "native" || env["CURSOR_CONVERSATION_ID"] != cursorConv {
		t.Errorf("run_env = %v; want only the four declared variables", env)
	}
}

func TestCursorMissingConversation(t *testing.T) {
	h := newHarness(t, nil)
	h.sandboxEnv(300, 0, cursorProfile, nil)
	if n := h.n(`SELECT count(*) FROM runs r JOIN sessions s ON s.id = r.session_id WHERE s.kind = 'cursor' AND s.key = 'unknown'`); n != 1 {
		t.Error("fingerprinted run without env should join the unknown cursor session")
	}
	if n := h.n(`SELECT count(*) FROM run_env`); n != 0 {
		t.Errorf("run_env rows = %d, want 0", n)
	}
}

func TestDeclaredEnvStoredOnUnmatchedRun(t *testing.T) {
	h := newHarness(t, nil)
	h.sandboxEnv(300, 0, "(version 1)(allow default)", []string{"CURSOR_AGENT=1", "HOME=/Users/me"})
	var id int64
	var session sql.NullInt64
	if err := h.s.DB.QueryRow(`SELECT id, session_id FROM runs`).Scan(&id, &session); err != nil {
		t.Fatal(err)
	}
	if session.Valid {
		t.Error("run without a fingerprint got a session")
	}
	if env := h.runEnv(id); len(env) != 1 || env["CURSOR_AGENT"] != "1" {
		t.Errorf("run_env = %v; want CURSOR_AGENT only", env)
	}
}

func TestCursorDenialNotAdopted(t *testing.T) {
	h := newHarness(t, nil)
	// A Cursor command that started before watch: no exec event, and its denials carry no tag.
	h.deny(ms(100), ms(100), 777, "/Users/Shared/x", "", 0)
	h.settle(ms(6000))
	h.tick(ms(6000))
	if n := h.n(`SELECT count(*) FROM runs`); n != 0 {
		t.Errorf("runs = %d, want 0 (no adoption without a denial tag)", n)
	}
}
