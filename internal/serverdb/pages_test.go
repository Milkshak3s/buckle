package serverdb

import (
	"errors"
	"testing"
)

func TestRunDetailWithMissingParents(t *testing.T) {
	d := openTemp(t)
	apply(t, d, batch(instA,
		row("runs", 4, 5, "watch_id", 1, "kind", "sandbox-exec", "session_id", 3, "status", "exited", "started_at", 1000,
			"profile_source", "inline", "profile_hash", "abc", "command_json", `["/bin/cat","/etc/hosts"]`, "params_json", "[]"),
		row("denials", 6, 1, "run_id", 5, "process_id", 9, "time", 1500, "process_name", "cat", "pid", 100,
			"operation", "file-read-data", "target", "/private/etc/hosts", "count", 2),
	))
	r, err := d.Run(hostA, instA, 5)
	if err != nil {
		t.Fatal(err)
	}
	if r.SessionID == nil || *r.SessionID != 3 || r.SessionKey != "" {
		t.Errorf("session: id=%v key=%q; want id 3 with unknown key", r.SessionID, r.SessionKey)
	}
	if !r.ProfileMissing || r.ProfileText != "" {
		t.Errorf("profile: missing=%v text=%q", r.ProfileMissing, r.ProfileText)
	}
	if len(r.Processes) != 0 || len(r.Denials) != 1 || r.Denials[0].IsPlatform != nil || r.Denials[0].Count != 2 {
		t.Errorf("processes=%d denials=%+v", len(r.Processes), r.Denials)
	}
	if r.HostName != "mac-a" {
		t.Errorf("host name = %q", r.HostName)
	}
	hosts, err := d.Hosts()
	if err != nil || len(hosts) != 1 || len(hosts[0].Groups) != 1 || hosts[0].Groups[0].UntaggedRuns != 0 {
		t.Errorf("Hosts = %+v, %v", hosts, err)
	}
	if _, runs, err := d.SessionRuns(hostA, instA, 3); err != nil || len(runs) != 1 || runs[0].DenialCount != 2 {
		t.Errorf("SessionRuns = %+v, %v", runs, err)
	}
	if _, err := d.Run(hostA, instA, 99); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing run: %v, want ErrNotFound", err)
	}
}
