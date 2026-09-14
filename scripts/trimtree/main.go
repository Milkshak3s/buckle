// Command trimtree cuts a capture down to the process trees rooted at one executable: eslogger
// events for those images and their fork/exec descendants, and Sandbox log lines from their pids.
// eslogger records the whole Mac, so an untrimmed fixture carries unrelated apps' command lines.
//
//	trimtree -root cursorsandbox -es in/es.jsonl -log in/log.ndjson -out outdir
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"buckle/internal/eslog"
	"buckle/internal/ulog"
)

func main() {
	root := flag.String("root", "", "basename of the executable whose trees to keep")
	esIn := flag.String("es", "", "eslogger JSON lines")
	logIn := flag.String("log", "", "log stream ndjson")
	out := flag.String("out", "", "output directory (es.jsonl, log.ndjson)")
	flag.Parse()
	if *root == "" || *esIn == "" || *logIn == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*root, *esIn, *logIn, *out); err != nil {
		fmt.Fprintln(os.Stderr, "trimtree:", err)
		os.Exit(1)
	}
}

func run(root, esIn, logIn, out string) error {
	pids, err := filterFile(esIn, filepath.Join(out, "es.jsonl"), func(r io.Reader, w io.Writer) (map[int]bool, error) {
		return trimES(r, w, root)
	})
	if err != nil {
		return err
	}
	_, err = filterFile(logIn, filepath.Join(out, "log.ndjson"), func(r io.Reader, w io.Writer) (map[int]bool, error) {
		return nil, trimLog(r, w, pids)
	})
	return err
}

func filterFile(in, out string, f func(io.Reader, io.Writer) (map[int]bool, error)) (map[int]bool, error) {
	src, err := os.Open(in)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	tmp := out + ".tmp"
	dst, err := os.Create(tmp)
	if err != nil {
		return nil, err
	}
	pids, err := f(src, dst)
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return nil, err
	}
	return pids, os.Rename(tmp, out)
}

func lines(r io.Reader, fn func([]byte) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		if err := fn(sc.Bytes()); err != nil {
			return err
		}
	}
	return sc.Err()
}

// trimES copies events whose actor or target is in a kept tree and returns every pid seen in them.
// A tree starts at an exec of an executable named root and follows fork and exec edges by audit
// token, the same way buckle builds runs.
func trimES(r io.Reader, w io.Writer, root string) (map[int]bool, error) {
	keep := map[eslog.Token]bool{}
	pids := map[int]bool{}
	err := lines(r, func(line []byte) error {
		ev, err := eslog.Parse(line)
		if err != nil {
			return nil
		}
		in := keep[ev.Process.Token]
		switch ev.Kind {
		case eslog.KindExec:
			if in || filepath.Base(ev.Target.Path) == root {
				keep[ev.Target.Token], in = true, true
			}
		case eslog.KindFork:
			if in {
				keep[ev.Target.Token] = true
			}
		}
		if !in {
			return nil
		}
		pids[ev.Process.Token.PID] = true
		if ev.Kind != eslog.KindExit {
			pids[ev.Target.Token.PID] = true
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			return err
		}
		return nil
	})
	return pids, err
}

// trimLog copies denial lines from the kept pids and drops everything else.
func trimLog(r io.Reader, w io.Writer, pids map[int]bool) error {
	return lines(r, func(line []byte) error {
		d, err := ulog.Parse(line)
		if errors.Is(err, ulog.ErrSkip) || err != nil || !pids[d.PID] {
			return nil
		}
		_, err = w.Write(append(line, '\n'))
		return err
	})
}
