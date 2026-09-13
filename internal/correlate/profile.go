package correlate

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const maxProfileSize = 1 << 20

// readProfileFile reads a `sandbox-exec -f` profile, refusing anything but a regular file of
// reasonable size. It runs as root inside the correlator loop, so: /dev/fd/N (process
// substitution) would name buckle's own descriptors, and devices, FIFOs or huge files could block
// the loop or exhaust memory.
func readProfileFile(path string) ([]byte, error) {
	if err := devPathError(path, path); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	if err := devPathError(path, resolved); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file (%s)", path, fi.Mode().Type())
	}
	if fi.Size() > maxProfileSize {
		return nil, fmt.Errorf("%s is larger than 1 MiB", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxProfileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxProfileSize {
		return nil, fmt.Errorf("%s is larger than 1 MiB", path)
	}
	return b, nil
}

func devPathError(orig, p string) error {
	switch {
	case p == "/dev/stdin" || strings.HasPrefix(p, "/dev/fd/"):
		return fmt.Errorf("profile passed by file descriptor (%s); contents unavailable", orig)
	case p == "/dev" || strings.HasPrefix(p, "/dev/"):
		return fmt.Errorf("%s is a device, not a profile file", orig)
	}
	return nil
}
