package server

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"buckle/internal/detect"
	"buckle/internal/report"
	"buckle/internal/sbx"
	"buckle/internal/serverdb"
)

//go:embed templates/*.html
var templateFS embed.FS

type page struct {
	Title   string
	Refresh int     // seconds; 0 omits the meta refresh
	Crumbs  []crumb // header breadcrumbs, ending with the current page
	Data    any
}

// crumb is one header breadcrumb. The current page and hosts, which have no page, leave Href empty.
type crumb struct {
	Text, Href string
	Code       bool // monospace, for session keys
}

type runsPage struct {
	HostUUID, DBInstance      string
	Session                   *serverdb.SessionSummary // nil for untagged runs
	Runs                      []serverdb.RunSummary
	ProcessTotal, DenialTotal int64
}

type runPage struct {
	Run         serverdb.RunDetail
	Timeline    []entry
	Note        string
	DenialTotal int64
}

// entry is one timeline row: a process start or end, or a denial.
type entry struct {
	At      *int64
	Kind    string
	Label   string
	Process *serverdb.Process
	Denial  *serverdb.Denial
	Args    *argsView // process starts only
}

// stamp formats a nanosecond timestamp (int64 or *int64) as a full UTC time and a time of day in
// loc. A missing timestamp is "unknown" with no local part.
func stamp(v any, loc *time.Location) (utc, local string) {
	ns, ok := nsOf(v)
	if !ok || ns == 0 {
		return "unknown", ""
	}
	t := time.Unix(0, ns)
	return t.UTC().Format("2006-01-02 15:04:05.000 UTC"), t.In(loc).Format("15:04:05.000 MST")
}

// Denial counts at or above denialHot get a solid chip; lower nonzero counts get a tinted one.
const denialHot = 20

func denialClass(n int64) string {
	switch {
	case n >= denialHot:
		return "hot"
	case n > 0:
		return "warn"
	}
	return ""
}

// span formats the time between two nanosecond timestamps (int64 or *int64), or "unknown" when
// either is missing or they are out of order.
func span(start, end any) string {
	s, okS := nsOf(start)
	e, okE := nsOf(end)
	if !okS || !okE || s == 0 || e < s {
		return "unknown"
	}
	d := time.Duration(e - s)
	switch {
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1f s", d.Truncate(100*time.Millisecond).Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
}

func runTotals(runs []serverdb.RunSummary) (processes, denials int64) {
	for _, r := range runs {
		processes += r.ProcessCount
		denials += r.DenialCount
	}
	return processes, denials
}

func denialTotal(ds []serverdb.Denial) int64 {
	var n int64
	for _, d := range ds {
		n += d.Count
	}
	return n
}

func (s *server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /hosts/{host}/{inst}/sessions/{id}", s.session)
	mux.HandleFunc("GET /hosts/{host}/{inst}/untagged", s.untagged)
	mux.HandleFunc("GET /hosts/{host}/{inst}/runs/{id}", s.run)
}

var safeArg = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// Timeline arguments longer than argLimit bytes show only their first argHead bytes.
const (
	argLimit = 1024
	argHead  = 200
)

func quoteArg(a string) string {
	if safeArg.MatchString(a) {
		return a
	}
	return "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
}

// argv renders a stored JSON argv as a shell-quoted command line.
func argv(js string) string {
	var args []string
	if err := json.Unmarshal([]byte(js), &args); err != nil {
		return js
	}
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = quoteArg(a)
	}
	return strings.Join(q, " ")
}

// argsView is a process argv prepared for the timeline.
type argsView struct {
	Text string // shell-quoted, with an inline sandbox profile and very long arguments elided
	Full string // the complete shell-quoted argv; set only when Text elides something
}

// newArgsView shortens an argv for reading. sandbox-exec's inline profile (-p), which the run
// page already shows under Profile text, becomes a placeholder, and any other argument over
// argLimit bytes keeps only its first argHead bytes.
func newArgsView(path, js string) *argsView {
	var args []string
	if err := json.Unmarshal([]byte(js), &args); err != nil {
		return &argsView{Text: js}
	}
	var inline string
	if path == sbx.SandboxExecPath {
		inline = sbx.ParseArgs(args).Inline
	}
	q := make([]string, len(args))
	elided := false
	for i, a := range args {
		switch {
		case inline != "" && strings.HasSuffix(a, inline) && (a == inline || strings.HasPrefix(a, "-")):
			// Detached (-p PROFILE) or attached (-pPROFILE) profile value.
			if opt := strings.TrimSuffix(a, inline); opt != "" {
				q[i] = quoteArg(opt)
			}
			q[i] += fmt.Sprintf("<inline profile, %d bytes: see Profile text>", len(inline))
			elided = true
		case len(a) > argLimit:
			cut := argHead
			for cut > 0 && !utf8.RuneStart(a[cut]) {
				cut--
			}
			q[i] = quoteArg(a[:cut]) + fmt.Sprintf("…<%d more bytes>", len(a)-cut)
			elided = true
		default:
			q[i] = quoteArg(a)
		}
	}
	v := &argsView{Text: strings.Join(q, " ")}
	if elided {
		v.Full = argv(js)
	}
	return v
}

// agentName is a session kind's display name; kinds this build doesn't know show as stored.
func agentName(kind string) string {
	if d, ok := detect.ByKind(kind); ok {
		return d.DisplayName()
	}
	return kind
}

// detailLabel names a run's tag_command for its session kind.
func detailLabel(kind string) string {
	if d, ok := detect.ByKind(kind); ok {
		return d.DetailLabel()
	}
	return "Tag detail"
}

func nsOf(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case *int64:
		if x != nil {
			return *x, true
		}
	}
	return 0, false
}

func (s *server) funcs() template.FuncMap {
	return template.FuncMap{
		"ts": func(v any) string {
			utc, local := stamp(v, s.Location)
			if local == "" {
				return utc
			}
			return utc + " · " + local
		},
		"utc":         func(v any) string { utc, _ := stamp(v, s.Location); return utc },
		"local":       func(v any) string { _, local := stamp(v, s.Location); return local },
		"span":        span,
		"denialClass": denialClass,
		"offset": func(start int64, at *int64) template.HTML {
			if at == nil || start == 0 {
				return ""
			}
			// template.HTML because html/template escapes a bare "+" as "&#43;" in text
			// content; the formatted value is a computed float, so this is safe.
			return template.HTML(fmt.Sprintf("%+.3fs", float64(*at-start)/1e9))
		},
		"argv":        argv,
		"agent":       agentName,
		"detailLabel": detailLabel,
		"deref":       func(p *int64) int64 { return *p },
		"platform": func(b *bool) template.HTML {
			switch {
			case b == nil:
				return `<span class="badge">platform unknown</span>`
			case *b:
				return `<span class="badge">platform</span>`
			}
			return `<span class="badge np">non-platform: denials may be missing</span>`
		},
	}
}

func (s *server) render(w http.ResponseWriter, name string, p page) {
	t, err := template.New("").Funcs(s.funcs()).ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html")
	if err != nil {
		s.fail(w, err)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

func (s *server) fail(w http.ResponseWriter, err error) {
	if errors.Is(err, serverdb.ErrNotFound) {
		http.NotFound(w, nil)
		return
	}
	s.Log("page: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func (s *server) refreshSeconds() int { return int(s.Refresh / time.Second) }

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.DB.Hosts()
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "index", page{Title: "Hosts", Refresh: s.refreshSeconds(), Crumbs: []crumb{{Text: "Hosts"}}, Data: hosts})
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil
}

// hostCrumbs starts the breadcrumbs of a page under the named host.
func hostCrumbs(name string) []crumb {
	if name == "" {
		name = "unknown host"
	}
	return []crumb{{Text: "Hosts", Href: "/"}, {Text: name}}
}

func (s *server) session(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	host, inst := r.PathValue("host"), r.PathValue("inst")
	sess, runs, err := s.DB.SessionRuns(host, inst, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	name, err := s.DB.HostName(host)
	if err != nil {
		s.fail(w, err)
		return
	}
	title, last := "Session "+sess.Key, crumb{Text: sess.Key, Code: true}
	if sess.Key == "" {
		title = fmt.Sprintf("Session #%d (not received yet)", id)
		last = crumb{Text: fmt.Sprintf("session #%d", id)}
	}
	d := runsPage{HostUUID: host, DBInstance: inst, Session: &sess, Runs: runs}
	d.ProcessTotal, d.DenialTotal = runTotals(runs)
	s.render(w, "runs", page{Title: title, Refresh: s.refreshSeconds(), Crumbs: append(hostCrumbs(name), last), Data: d})
}

func (s *server) untagged(w http.ResponseWriter, r *http.Request) {
	host, inst := r.PathValue("host"), r.PathValue("inst")
	runs, err := s.DB.UntaggedRuns(host, inst)
	if err != nil {
		s.fail(w, err)
		return
	}
	name, err := s.DB.HostName(host)
	if err != nil {
		s.fail(w, err)
		return
	}
	d := runsPage{HostUUID: host, DBInstance: inst, Runs: runs}
	d.ProcessTotal, d.DenialTotal = runTotals(runs)
	s.render(w, "runs", page{Title: "Untagged runs", Refresh: s.refreshSeconds(),
		Crumbs: append(hostCrumbs(name), crumb{Text: "Untagged runs"}), Data: d})
}

func (s *server) run(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	d, err := s.DB.Run(r.PathValue("host"), r.PathValue("inst"), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	crumbs := hostCrumbs(d.HostName)
	switch {
	case d.SessionID == nil:
		crumbs = append(crumbs, crumb{Text: "Untagged runs", Href: fmt.Sprintf("/hosts/%s/%s/untagged", d.HostUUID, d.DBInstance)})
	case d.SessionKey == "":
		crumbs = append(crumbs, crumb{Text: fmt.Sprintf("session #%d", *d.SessionID),
			Href: fmt.Sprintf("/hosts/%s/%s/sessions/%d", d.HostUUID, d.DBInstance, *d.SessionID)})
	default:
		crumbs = append(crumbs, crumb{Text: d.SessionKey, Code: true,
			Href: fmt.Sprintf("/hosts/%s/%s/sessions/%d", d.HostUUID, d.DBInstance, *d.SessionID)})
	}
	crumbs = append(crumbs, crumb{Text: fmt.Sprintf("Run %d", id)})
	s.render(w, "run", page{Title: fmt.Sprintf("Run %d", id), Crumbs: crumbs,
		Data: runPage{Run: d, Timeline: timeline(d), Note: report.LowerBoundNote, DenialTotal: denialTotal(d.Denials)}})
}

// timeline interleaves process starts and ends with denials by time. Entries without a time go
// last, in process id order then denial order. Exec ends are omitted: the next image's exec entry
// shows them.
func timeline(d serverdb.RunDetail) []entry {
	var es []entry
	for i := range d.Processes {
		p := &d.Processes[i]
		label := "start"
		switch {
		case p.ExecPrevProcessID != nil:
			label = "exec"
		case p.ParentProcessID != nil:
			label = "fork"
		}
		es = append(es, entry{At: p.StartedAt, Kind: label, Label: label, Process: p, Args: newArgsView(p.Path, p.ArgsJSON)})
		switch p.EndReason {
		case "exit":
			l := "exit"
			if p.ExitStatus != nil {
				l = fmt.Sprintf("exit (status %d)", *p.ExitStatus)
			}
			es = append(es, entry{At: p.EndedAt, Kind: "exit", Label: l, Process: p})
		case "watch_stopped":
			es = append(es, entry{Kind: "stopped", Label: "watch stopped, end unknown", Process: p})
		}
	}
	for i := range d.Denials {
		es = append(es, entry{At: &d.Denials[i].Time, Kind: "denial", Label: "denial", Denial: &d.Denials[i]})
	}
	sort.SliceStable(es, func(i, j int) bool {
		a, b := es[i].At, es[j].At
		switch {
		case a == nil:
			return false
		case b == nil:
			return true
		}
		return *a < *b
	})
	return es
}
