// Package server is buckle serve's HTTP layer: the ingest API for `buckle ship` and the review pages.
package server

import (
	"encoding/json"
	"net/http"
	"time"

	"buckle/internal/serverdb"
	"buckle/internal/wire"
)

const DefaultMaxBody = 64 << 20

type Options struct {
	DB       *serverdb.DB
	Refresh  time.Duration
	MaxBody  int64
	Now      func() time.Time
	Location *time.Location
	Log      func(format string, args ...any)
}

type server struct {
	Options
}

// New returns the handler serving the API and pages.
func New(o Options) http.Handler {
	if o.MaxBody <= 0 {
		o.MaxBody = DefaultMaxBody
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Location == nil {
		o.Location = time.Local
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	s := &server{o}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/cursor", s.cursor)
	mux.HandleFunc("POST /api/v1/ingest", s.ingest)
	s.routes(mux)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, wire.ErrorResponse{Error: msg})
}

// routes registers the review pages (Task 5).
func (s *server) routes(mux *http.ServeMux) {}
