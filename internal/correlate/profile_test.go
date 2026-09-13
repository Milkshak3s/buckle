package correlate

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadProfileFile(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "p.sb")
	if err := os.WriteFile(regular, []byte("(version 1)"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.sb")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	devLink := filepath.Join(dir, "zero.sb")
	if err := os.Symlink("/dev/zero", devLink); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo.sb")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.sb")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), maxProfileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{regular, link} {
		b, err := readProfileFile(p)
		if err != nil || string(b) != "(version 1)" {
			t.Errorf("%s: %q, %v", p, b, err)
		}
	}
	cases := []struct {
		path, want string
	}{
		{"/dev/fd/11", "file descriptor"},
		{"/dev/stdin", "file descriptor"},
		{"/dev/zero", "device"},
		{devLink, "device"},
		{fifo, "not a regular file"},
		{dir, "not a regular file"},
		{big, "larger than 1 MiB"},
	}
	for _, c := range cases {
		done := make(chan error, 1)
		go func() {
			_, err := readProfileFile(c.path)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: err = %v, want %q", c.path, err, c.want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: read blocked", c.path)
		}
	}
	if _, err := readProfileFile(filepath.Join(dir, "missing.sb")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
}

func TestProcessSubstitutionProfile(t *testing.T) {
	h := newHarness(t, nil)
	h.c.deps.ReadFile = readProfileFile
	child := proc(1300, 1, "/bin/zsh", true)
	h.fork(ms(0), shell, child)
	h.exec(ms(1), child, proc(1300, 2, "/usr/bin/sandbox-exec", true), "/usr/bin/sandbox-exec", "-f", "/dev/fd/11", "/bin/true")
	if n := h.n(`SELECT count(*) FROM runs WHERE profile_source = 'file' AND profile_path = '/dev/fd/11'
		AND profile_hash IS NULL AND profile_error LIKE '%file descriptor%'`); n != 1 {
		t.Error("process-substitution profile should be recorded as unavailable")
	}
}
