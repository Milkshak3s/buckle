package server

import (
	"errors"
	"net/http"

	"buckle/internal/serverdb"
	"buckle/internal/wire"
)

func (s *server) cursor(w http.ResponseWriter, r *http.Request) {
	host, inst := r.URL.Query().Get("host"), r.URL.Query().Get("db_instance")
	if host == "" || inst == "" {
		writeError(w, http.StatusBadRequest, "host and db_instance are required")
		return
	}
	rev, err := s.DB.Cursor(host, inst)
	if err != nil {
		s.Log("cursor: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, wire.CursorResponse{Rev: rev})
}

func (s *server) ingest(w http.ResponseWriter, r *http.Request) {
	b, err := wire.Decode(http.MaxBytesReader(w, r.Body, s.MaxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			writeError(w, http.StatusBadRequest, "malformed batch: "+err.Error())
		}
		return
	}
	cur, err := s.DB.Apply(b, s.Now())
	var invalid *serverdb.ValidationError
	switch {
	case errors.Is(err, serverdb.ErrSchemaVersion):
		writeError(w, http.StatusConflict, err.Error())
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case err != nil:
		s.Log("ingest from %s: %v", b.Host.UUID, err)
		writeError(w, http.StatusInternalServerError, "internal error")
	default:
		writeJSON(w, http.StatusOK, wire.IngestResponse{Cursor: cur})
	}
}
