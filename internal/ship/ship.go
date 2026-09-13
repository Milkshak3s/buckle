// Package ship sends a buckle database's changed rows to buckle serve.
package ship

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"buckle/internal/store"
	"buckle/internal/wire"
)

const maxBackoff = 2 * time.Minute

type Options struct {
	Store      *store.Store
	Host       wire.Host
	DBInstance string
	Server     string // base URL, e.g. http://127.0.0.1:8080
	Interval   time.Duration
	Client     *http.Client
	Logf       func(format string, args ...any)
}

// RejectedError is a 4xx from the server: retrying the same data cannot succeed.
type RejectedError struct {
	Status int
	Body   string
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("server rejected the batch (HTTP %d): %s", e.Status, strings.TrimSpace(e.Body))
}

// Run ships until ctx is cancelled (nil) or the server rejects a batch (*RejectedError). Network
// errors and 5xx back off from Interval, doubling up to 2 minutes; the server's cursor means
// nothing is lost.
func Run(ctx context.Context, o Options) error {
	wait := o.Interval
	failing := false
	for {
		sent, err := o.syncOnce(ctx)
		var rejected *RejectedError
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.As(err, &rejected):
			return err
		case err != nil:
			if failing {
				wait = min(wait*2, maxBackoff)
			} else {
				o.Logf("server unavailable, retrying with backoff: %v", err)
				wait = o.Interval
			}
			failing = true
		default:
			if failing {
				o.Logf("server reachable again")
			}
			failing = false
			wait = o.Interval
			if sent > 0 {
				o.Logf("shipped %d rows", sent)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// syncOnce sends every row newer than the server's cursor, in batches of wire.MaxRows. An empty
// batch is still posted so the server records the report.
func (o Options) syncOnce(ctx context.Context) (int, error) {
	var cr wire.CursorResponse
	q := url.Values{"host": {o.Host.UUID}, "db_instance": {o.DBInstance}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.Server+"/api/v1/cursor?"+q.Encode(), nil)
	if err != nil {
		return 0, &RejectedError{Status: 0, Body: err.Error()}
	}
	if err := o.do(req, &cr); err != nil {
		return 0, err
	}
	cursor, total := cr.Rev, 0
	for {
		rows, err := o.Store.ChangesSince(cursor, wire.MaxRows)
		if err != nil {
			return total, fmt.Errorf("read changes: %w", err)
		}
		if rows == nil {
			rows = []wire.Row{}
		}
		body, err := json.Marshal(wire.Batch{Host: o.Host, DBInstance: o.DBInstance, SchemaVersion: wire.SchemaVersion, Rows: rows})
		if err != nil {
			return total, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.Server+"/api/v1/ingest", bytes.NewReader(body))
		if err != nil {
			return total, err
		}
		req.Header.Set("Content-Type", "application/json")
		var ir wire.IngestResponse
		if err := o.do(req, &ir); err != nil {
			return total, err
		}
		total += len(rows)
		if len(rows) > 0 && ir.Cursor < rows[len(rows)-1].Rev {
			return total, &RejectedError{Status: http.StatusOK, Body: fmt.Sprintf("cursor %d did not advance past rev %d", ir.Cursor, rows[len(rows)-1].Rev)}
		}
		cursor = ir.Cursor
		if len(rows) < wire.MaxRows {
			return total, nil
		}
	}
}

func (o Options) do(req *http.Request, out any) error {
	resp, err := o.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return &RejectedError{Status: resp.StatusCode, Body: string(body)}
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, out)
}
