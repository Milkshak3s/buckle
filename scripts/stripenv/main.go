// Command stripenv copies eslogger JSON lines from stdin to stdout, keeping only the exec
// environment variables buckle's session detectors declare. Fixtures must never carry the full
// environment, which holds tokens and paths.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"buckle/internal/detect"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "stripenv:", err)
		os.Exit(1)
	}
}

func run() error {
	names := detect.EnvNames()
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		line, err := strip(sc.Bytes(), names)
		if err != nil {
			return err
		}
		w.Write(line)
		w.WriteByte('\n')
	}
	return sc.Err()
}

// strip drops undeclared entries from event.exec.env. Lines without one are copied unchanged, and
// a line that isn't JSON is an error so nothing unfiltered slips through.
func strip(line []byte, names []string) ([]byte, error) {
	if !bytes.Contains(line, []byte(`"env"`)) {
		return line, nil
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	event, _ := m["event"].(map[string]any)
	exec, _ := event["exec"].(map[string]any)
	if env, ok := exec["env"].([]any); ok {
		kept := []any{}
		for _, e := range env {
			s, _ := e.(string)
			if k, _, ok := strings.Cut(s, "="); ok && slices.Contains(names, k) {
				kept = append(kept, s)
			}
		}
		exec["env"] = kept
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
