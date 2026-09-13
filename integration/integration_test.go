//go:build integration

// End-to-end test against the real eslogger and unified log. Needs root, a sudo invoker and a
// terminal with Full Disk Access. Build as your user, run the binary with sudo:
//
//	go test -c -tags integration -o /tmp/buckle-itest ./integration && sudo /tmp/buckle-itest -test.v
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"buckle/internal/store"
	"buckle/internal/watch"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func randSuffix(t *testing.T) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	var sb strings.Builder
	for i := 0; i < 9; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			t.Fatal(err)
		}
		sb.WriteByte(alphabet[n.Int64()])
	}
	return "_" + sb.String() + "_SBX"
}

// workload runs a command as the sudo user in its own process group (eslogger hides its own group).
func workload(t *testing.T, owner *watch.Owner, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:    true,
		Credential: &syscall.Credential{Uid: uint32(owner.UID), Gid: uint32(owner.GID)},
	}
	out, err := cmd.CombinedOutput()
	t.Logf("%s %q: err=%v output=%q", name, args, err, out)
}

func TestWatchEndToEnd(t *testing.T) {
	owner, err := watch.SudoOwner()
	if err != nil {
		t.Skipf("needs sudo: %v", err)
	}
	work, err := os.MkdirTemp("/private/tmp", "buckle-itest.")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(work)
	os.Chmod(work, 0o777)
	dbPath := filepath.Join(work, "db", "buckle.db")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stderr syncBuffer
	errc := make(chan error, 1)
	go func() {
		errc <- watch.Run(ctx, watch.Options{DBPath: dbPath, Owner: owner, Buffer: 2 * time.Second, OSVersion: watch.OSVersion(), Stderr: &stderr})
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(stderr.String(), "watching;") {
		select {
		case err := <-errc:
			t.Fatalf("watch exited early: %v\n%s", err, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("watch did not start:\n%s", stderr.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(3 * time.Second) // let eslogger and log stream attach

	hostsDeny := `(version 1)(allow default)(deny file-read-data (literal "/private/etc/hosts"))`
	workload(t, owner, "/usr/bin/sandbox-exec", "-p", hostsDeny, "/bin/cat", "/etc/hosts")

	cmdText := "cat /etc/hosts | head -1"
	suffix := randSuffix(t)
	tag := "CMD64_" + base64.StdEncoding.EncodeToString([]byte(cmdText)) + "_END_" + suffix
	tagged := fmt.Sprintf("(version 1)\n(allow default)\n; LogTag: %s\n(deny file-read-data (literal \"/private/etc/hosts\") (with message %q))", tag, tag)
	workload(t, owner, "/usr/bin/sandbox-exec", "-p", tagged, "/bin/sh", "-c", cmdText)

	profilePath := filepath.Join(work, "param.sb")
	if err := os.WriteFile(profilePath, []byte(`(version 1)(allow default)(deny file-write* (subpath (param "OUT")))`), 0o644); err != nil {
		t.Fatal(err)
	}
	workload(t, owner, "/usr/bin/sandbox-exec", "-f", profilePath, "-D", "OUT="+work, "/usr/bin/touch", filepath.Join(work, "probe"))
	workload(t, owner, "/usr/bin/sandbox-exec", "-n", "no-network", "/usr/bin/curl", "-s", "-m", "2", "http://1.1.1.1/")

	time.Sleep(3 * time.Second)
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("watch: %v\n%s", err, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("watch did not stop")
	}
	t.Logf("watch stderr:\n%s", stderr.String())

	fi, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != owner.UID {
		t.Errorf("database owned by uid %d, want %d", st.Uid, owner.UID)
	}

	s, err := store.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	one := func(what, q string, args ...any) {
		t.Helper()
		var n int
		if err := s.DB.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if n < 1 {
			t.Errorf("%s: none found", what)
		}
	}
	one("inline cat run with attributed denial", `SELECT count(*) FROM runs r JOIN denials d ON d.run_id = r.id
		WHERE r.kind = 'sandbox-exec' AND r.profile_source = 'inline' AND r.status = 'exited'
		AND r.command_json = '["/bin/cat","/etc/hosts"]' AND d.target = '/private/etc/hosts'`)
	one("tagged run with session", `SELECT count(*) FROM runs r JOIN sessions s ON s.id = r.session_id
		WHERE s.key = ? AND r.tag_command = ?`, suffix, cmdText)
	one("file profile with param", `SELECT count(*) FROM runs WHERE profile_source = 'file' AND profile_path = ?
		AND params_json = ? AND profile_hash IS NOT NULL`, profilePath, fmt.Sprintf(`[["OUT",%q]]`, work))
	one("named profile", `SELECT count(*) FROM runs WHERE profile_source = 'named' AND profile_name = 'no-network'`)
	one("watch closed", `SELECT count(*) FROM watches WHERE end_reason = 'stopped'`)

	var orphans sql.NullInt64
	s.DB.QueryRow(`SELECT count(*) FROM orphans`).Scan(&orphans)
	t.Logf("orphans recorded: %d", orphans.Int64)
}
