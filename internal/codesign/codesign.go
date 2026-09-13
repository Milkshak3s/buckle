// Package codesign checks a binary's entitlements with /usr/bin/codesign.
package codesign

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

const appSandboxKey = "com.apple.security.app-sandbox"

// Checker runs codesign. Run is replaceable for tests; it returns codesign's stdout.
type Checker struct {
	Run func(path string) ([]byte, error)
}

func New() *Checker {
	return &Checker{Run: func(path string) ([]byte, error) {
		cmd := exec.Command("/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", path)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("codesign %s: %v: %s", path, err, strings.TrimSpace(stderr.String()))
		}
		return stdout.Bytes(), nil
	}}
}

// HasAppSandbox reports whether the binary at path has com.apple.security.app-sandbox = true.
// cdhash is accepted for the correlator's cache key; codesign reads the file at path.
func (c *Checker) HasAppSandbox(path, cdhash string) (bool, error) {
	out, err := c.Run(path)
	if err != nil {
		return false, err
	}
	return ParseAppSandbox(out)
}

// ParseAppSandbox scans an entitlements plist for the app-sandbox key. Empty input means no entitlements.
func ParseAppSandbox(plist []byte) (bool, error) {
	if len(bytes.TrimSpace(plist)) == 0 {
		return false, nil
	}
	dec := xml.NewDecoder(bytes.NewReader(plist))
	dec.Strict = false
	inKey, pending := false, false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("codesign: parse entitlements: %w", err)
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			if pending {
				return tok.Name.Local == "true", nil
			}
			inKey = tok.Name.Local == "key"
		case xml.CharData:
			if inKey && strings.TrimSpace(string(tok)) == appSandboxKey {
				pending = true
			}
		case xml.EndElement:
			inKey = false
		}
	}
}
