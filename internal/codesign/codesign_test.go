package codesign

import (
	"errors"
	"testing"
)

func TestParseAppSandbox(t *testing.T) {
	const hdr = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">`
	cases := []struct {
		in   string
		want bool
	}{
		{hdr + `<plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/></dict></plist>`, true},
		{hdr + `<plist version="1.0"><dict><key>a</key><string>com.apple.security.app-sandbox</string><key>com.apple.security.app-sandbox</key><false/></dict></plist>`, false},
		{hdr + `<plist version="1.0"><dict><key>com.apple.security.network.client</key><true/></dict></plist>`, false},
		{"", false},
		{"\n", false},
	}
	for _, c := range cases {
		got, err := ParseAppSandbox([]byte(c.in))
		if err != nil || got != c.want {
			t.Errorf("%q: got %v, %v; want %v", c.in, got, err, c.want)
		}
	}
	if _, err := ParseAppSandbox([]byte("<plist><dict><key>")); err == nil {
		t.Error("truncated plist: want error")
	}
}

func TestHasAppSandboxUsesRun(t *testing.T) {
	c := &Checker{Run: func(path string) ([]byte, error) {
		if path == "/missing" {
			return nil, errors.New("no such file")
		}
		return []byte(`<plist><dict><key>com.apple.security.app-sandbox</key><true/></dict></plist>`), nil
	}}
	if ok, err := c.HasAppSandbox("/x", ""); !ok || err != nil {
		t.Errorf("got %v %v", ok, err)
	}
	if _, err := c.HasAppSandbox("/missing", ""); err == nil {
		t.Error("want error")
	}
}

func TestRealCodesign(t *testing.T) {
	c := New()
	ok, err := c.HasAppSandbox("/bin/cat", "")
	if err != nil || ok {
		t.Errorf("/bin/cat: %v %v", ok, err)
	}
	if _, err := c.HasAppSandbox("/nonexistent/buckle", ""); err == nil {
		t.Error("missing binary: want error")
	}
}
