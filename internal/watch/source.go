package watch

import (
	"bufio"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// source is a line-producing subprocess (eslogger or log stream).
type source struct {
	name   string
	cmd    *exec.Cmd
	lines  chan []byte // closed at stdout EOF
	done   chan struct{}
	stderr *tail

	mu      sync.Mutex
	waitErr error
	scanErr error
}

func startSource(name, path string, args []string) (*source, error) {
	s := &source{
		name:   name,
		cmd:    exec.Command(path, args...),
		lines:  make(chan []byte, 1024),
		done:   make(chan struct{}),
		stderr: &tail{max: 64 << 10},
	}
	// Stay in buckle's process group: eslogger suppresses events from its own group, which hides
	// buckle's own codesign shell-outs, and Ctrl-C reaches every process at once.
	s.cmd.Stderr = s.stderr
	stdout, err := s.cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := s.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64<<10), 16<<20)
		for sc.Scan() {
			s.lines <- append([]byte(nil), sc.Bytes()...)
		}
		if err := sc.Err(); err != nil {
			s.mu.Lock()
			s.scanErr = err
			s.mu.Unlock()
			s.cmd.Process.Kill()
		}
		close(s.lines)
		err := s.cmd.Wait()
		s.mu.Lock()
		s.waitErr = err
		s.mu.Unlock()
		close(s.done)
	}()
	return s, nil
}

func (s *source) interrupt() {
	if s.cmd.Process != nil {
		s.cmd.Process.Signal(syscall.SIGINT)
	}
}

func (s *source) kill() {
	if s.cmd.Process != nil {
		s.cmd.Process.Kill()
	}
}

// abandon stops the process without consuming its remaining output.
func (s *source) abandon(grace time.Duration) {
	s.interrupt()
	go func() {
		for range s.lines {
		}
	}()
	select {
	case <-s.done:
	case <-time.After(grace):
		s.kill()
		<-s.done
	}
}

// exitError describes how the process ended, with the tail of its stderr.
func (s *source) exitError() error {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	msg := fmt.Sprintf("source died: %s", s.name)
	if s.scanErr != nil {
		msg += fmt.Sprintf(" (reading output: %v)", s.scanErr)
	}
	if s.waitErr != nil {
		msg += fmt.Sprintf(" (%v)", s.waitErr)
	} else {
		msg += " (exited 0)"
	}
	if t := s.stderr.String(); t != "" {
		msg += ": " + t
	}
	return fmt.Errorf("%s", msg)
}

// tail keeps the last max bytes written.
type tail struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(bytesTrimSpace(t.buf))
}

func bytesTrimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
