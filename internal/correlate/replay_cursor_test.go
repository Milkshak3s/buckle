package correlate

import (
	"testing"

	"buckle/internal/testutil"
)

// The macos14.2-cursor fixture is one cursor-agent conversation (2026.09.10, --sandbox enabled)
// with two turns: `touch buckle_cursor_ok` inside the workspace, then `sh probe.sh`, whose touch
// of /Users/Shared/buckle_cursor_probe Seatbelt denied.
const (
	fixtureCursorConv  = "e9df733c-22a9-4126-b60d-f01d5ea96364"
	fixtureCursorTurn1 = "db1ef735-25e3-4f30-856f-9ef262de02d5"
	fixtureCursorTurn2 = "4fc08a36-e39f-45b2-a05c-356735d48ee8"
)

func TestReplayCursorFixture(t *testing.T) {
	items := testutil.LoadFixture(t, testutil.FixtureDir(t, "macos14.2-cursor"))
	s := replay(t, items, Deps{Entitlements: &fakeEnts{}})
	db := s.DB

	if n := queryInt(t, db, `SELECT count(*) FROM runs WHERE kind = 'sandbox-exec'`); n != 2 {
		t.Errorf("sandbox-exec runs = %d, want 2 (one per shell command)", n)
	}
	if n := queryInt(t, db, `SELECT count(*) FROM sessions`); n != 1 {
		t.Errorf("sessions = %d, want 1", n)
	}
	if n := queryInt(t, db, `SELECT count(*) FROM sessions WHERE kind = 'cursor' AND key = ?`, fixtureCursorConv); n != 1 {
		t.Error("no cursor session for the conversation")
	}
	for _, turn := range []string{fixtureCursorTurn1, fixtureCursorTurn2} {
		n := queryInt(t, db, `SELECT count(*) FROM runs r JOIN sessions s ON s.id = r.session_id
			WHERE r.kind = 'sandbox-exec' AND r.status = 'exited' AND r.tag IS NULL AND r.tag_command = ? AND s.key = ?`, turn, fixtureCursorConv)
		if n != 1 {
			t.Errorf("runs for turn %s = %d, want 1", turn, n)
		}
	}

	if n := queryInt(t, db, `SELECT count(*) FROM run_env`); n != 8 {
		t.Errorf("run_env rows = %d, want 4 declared variables × 2 runs", n)
	}
	if n := queryInt(t, db, `SELECT count(*) FROM run_env WHERE name NOT IN ('CURSOR_AGENT', 'CURSOR_CONVERSATION_ID', 'CURSOR_REQUEST_ID', 'CURSOR_SANDBOX')`); n != 0 {
		t.Errorf("%d undeclared variables stored", n)
	}
	// cursorsandbox replaces node's CURSOR_SANDBOX=native before it execs sandbox-exec.
	if n := queryInt(t, db, `SELECT count(*) FROM run_env WHERE name = 'CURSOR_SANDBOX' AND value = 'seatbelt'`); n != 2 {
		t.Errorf("CURSOR_SANDBOX=seatbelt rows = %d, want 2", n)
	}

	if n := queryInt(t, db, `SELECT count(*) FROM denials d JOIN runs r ON r.id = d.run_id
		WHERE r.tag_command = ? AND d.process_name = 'touch' AND d.operation = 'file-write-create'
		AND d.target = '/Users/Shared/buckle_cursor_probe'`, fixtureCursorTurn2); n != 1 {
		t.Error("probe denial not attributed to the second turn's run")
	}
	if n := queryInt(t, db, `SELECT count(*) FROM denials d JOIN runs r ON r.id = d.run_id
		WHERE r.tag_command = ? AND d.target = '/Users/Shared/buckle_cursor_probe'`, fixtureCursorTurn1); n != 0 {
		t.Error("probe denial attributed to the first turn")
	}
}
