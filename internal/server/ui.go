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

	"buckle/internal/report"
	"buckle/internal/serverdb"
)

//go:embed templates/*.html
var templateFS embed.FS

type page struct {
	Title   string
	Refresh int // seconds; 0 omits the meta refresh
	Data    any
}

type runsPage struct {
	Heading              string
	HostUUID, DBInstance string
	Session              *serverdb.SessionSummary
	Runs                 []serverdb.RunSummary
}

type runPage struct {
	Run      serverdb.RunDetail
	Timeline []entry
	Note     string
}

// entry is one timeline row: a process start or end, or a denial.
type entry struct {
	At       *int64
	Label    string
	Process  *serverdb.Process
	Denial   *serverdb.Denial
	ShowArgs bool
}

func (s *server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /hosts/{host}/{inst}/sessions/{id}", s.session)
	mux.HandleFunc("GET /hosts/{host}/{inst}/untagged", s.untagged)
	mux.HandleFunc("GET /hosts/{host}/{inst}/runs/{id}", s.run)
}

var safeArg = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// argv renders a stored JSON argv as a shell-quoted command line.
func argv(js string) string {
	var args []string
	if err := json.Unmarshal([]byte(js), &args); err != nil {
		return js
	}
	q := make([]string, len(args))
	for i, a := range args {
		if safeArg.MatchString(a) {
			q[i] = a
		} else {
			q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
	}
	return strings.Join(q, " ")
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
			ns, ok := nsOf(v)
			if !ok || ns == 0 {
				return "unknown"
			}
			t := time.Unix(0, ns)
			return t.UTC().Format("2006-01-02 15:04:05.000 UTC") + " · " + t.In(s.Location).Format("15:04:05.000 MST")
		},
		"offset": func(start int64, at *int64) template.HTML {
			if at == nil || start == 0 {
				return ""
			}
			// template.HTML because html/template escapes a bare "+" as "&#43;" in text
			// content; the formatted value is a computed float, so this is safe.
			return template.HTML(fmt.Sprintf("%+.3fs", float64(*at-start)/1e9))
		},
		"argv":  argv,
		"deref": func(p *int64) int64 { return *p },
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
	s.render(w, "index", page{Title: "Hosts", Refresh: s.refreshSeconds(), Data: hosts})
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil
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
	heading := "Session " + sess.Key
	if sess.Key == "" {
		heading = fmt.Sprintf("Session #%d (not received yet)", id)
	}
	s.render(w, "runs", page{Title: heading, Refresh: s.refreshSeconds(),
		Data: runsPage{Heading: heading, HostUUID: host, DBInstance: inst, Session: &sess, Runs: runs}})
}

func (s *server) untagged(w http.ResponseWriter, r *http.Request) {
	host, inst := r.PathValue("host"), r.PathValue("inst")
	runs, err := s.DB.UntaggedRuns(host, inst)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "runs", page{Title: "Untagged runs", Refresh: s.refreshSeconds(),
		Data: runsPage{Heading: "Untagged runs", HostUUID: host, DBInstance: inst, Runs: runs}})
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
	s.render(w, "run", page{Title: fmt.Sprintf("Run %d", id),
		Data: runPage{Run: d, Timeline: timeline(d), Note: report.LowerBoundNote}})
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
		es = append(es, entry{At: p.StartedAt, Label: label, Process: p, ShowArgs: true})
		switch p.EndReason {
		case "exit":
			l := "exit"
			if p.ExitStatus != nil {
				l = fmt.Sprintf("exit (status %d)", *p.ExitStatus)
			}
			es = append(es, entry{At: p.EndedAt, Label: l, Process: p})
		case "watch_stopped":
			es = append(es, entry{Label: "watch stopped, end unknown", Process: p})
		}
	}
	for i := range d.Denials {
		es = append(es, entry{At: &d.Denials[i].Time, Label: "denial", Denial: &d.Denials[i]})
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
