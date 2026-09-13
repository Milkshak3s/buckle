package ulog

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func line(t *testing.T, msg string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"eventMessage":  msg,
		"timestamp":     "2026-09-13 10:08:38.776905-0700",
		"machTimestamp": 17943975177831,
		"messageType":   "Error",
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseDenials(t *testing.T) {
	tag := "CMD64_Y2F0IC9ldGMvaG9zdHMgfCBoZWFkIC0x_END__k3j9x0q2m_SBX"
	cases := []struct {
		msg  string
		want Denial
	}{
		{"Sandbox: cat(15505) deny(1) file-read-data /private/etc/hosts",
			Denial{Name: "cat", PID: 15505, DenyN: 1, Operation: "file-read-data", Target: "/private/etc/hosts"}},
		{"Sandbox: cat(15528) deny(1) file-read-data /private/etc/hosts\n" + tag,
			Denial{Name: "cat", PID: 15528, DenyN: 1, Operation: "file-read-data", Target: "/private/etc/hosts", Message: tag}},
		{"7 duplicate reports for Sandbox: imagent(544) deny(1) mach-lookup com.apple.contactsd.persistence",
			Denial{Name: "imagent", PID: 544, DenyN: 1, Operation: "mach-lookup", Target: "com.apple.contactsd.persistence", Duplicate: 7}},
		{"1 duplicate report for Sandbox: Family(13158) deny(1) mach-lookup com.apple.contactsd.persistence",
			Denial{Name: "Family", PID: 13158, DenyN: 1, Operation: "mach-lookup", Target: "com.apple.contactsd.persistence", Duplicate: 1}},
		{`Sandbox: nesessionmanager(678) deny(1) system-fsctl (_IO "h" 47)`,
			Denial{Name: "nesessionmanager", PID: 678, DenyN: 1, Operation: "system-fsctl", Target: `(_IO "h" 47)`}},
		{"Sandbox: Google Chrome Helper (Renderer)(812) deny(1) mach-lookup x",
			Denial{Name: "Google Chrome Helper (Renderer)", PID: 812, DenyN: 1, Operation: "mach-lookup", Target: "x"}},
		{"Sandbox: foo(9) deny(2) process-fork",
			Denial{Name: "foo", PID: 9, DenyN: 2, Operation: "process-fork"}},
	}
	for _, c := range cases {
		got, err := Parse(line(t, c.msg))
		if err != nil {
			t.Errorf("%q: %v", c.msg, err)
			continue
		}
		if got.Time.IsZero() || got.MachTime != 17943975177831 {
			t.Errorf("%q: time %v mach %d", c.msg, got.Time, got.MachTime)
		}
		got.Time, got.MachTime = c.want.Time, 0
		if got != c.want {
			t.Errorf("%q:\n got %+v\nwant %+v", c.msg, got, c.want)
		}
	}
}

func TestParseTime(t *testing.T) {
	d, err := Parse(line(t, "Sandbox: cat(1) deny(1) file-read-data /x"))
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Time.UTC().Format("2006-01-02T15:04:05.000000"); got != "2026-09-13T17:08:38.776905" {
		t.Errorf("time = %s", got)
	}
}

func TestParseSkips(t *testing.T) {
	skips := [][]byte{
		[]byte(`Filtering the log data using "sender == "Sandbox""`),
		[]byte(``),
		[]byte(`{"count":32,"finished":1}`),
		line(t, "System Policy: eslogger(14156) deny(1) system-privilege 1016"),
		line(t, "Sandbox: foo(9) allow(1) file-read-data /x"),
		line(t, "something else entirely"),
	}
	for _, s := range skips {
		if _, err := Parse(s); !errors.Is(err, ErrSkip) {
			t.Errorf("%q: err = %v, want ErrSkip", s, err)
		}
	}
}

func TestParseWholeFixture(t *testing.T) {
	f, err := os.Open("../../testdata/fixtures/macos14.2/log.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	workload := map[int]bool{15505: true, 15511: true, 15522: true, 15528: true, 15531: true, 15536: true, 15571: true}
	var n int
	var pids []int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		d, err := Parse(sc.Bytes())
		if errors.Is(err, ErrSkip) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		n++
		if workload[d.PID] {
			pids = append(pids, d.PID)
		}
	}
	if n != 32 {
		t.Errorf("denials = %d, want 32", n)
	}
	want := []int{15505, 15511, 15522, 15522, 15528, 15531, 15536, 15571}
	if len(pids) != len(want) {
		t.Fatalf("workload pids = %v", pids)
	}
	for i := range want {
		if pids[i] != want[i] {
			t.Fatalf("workload pids = %v", pids)
		}
	}
}
