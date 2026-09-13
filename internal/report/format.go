// Package report reads buckle's database and renders sessions, runs, run detail and
// denial aggregates as JSON, JSONL or CSV.
package report

import (
	"bytes"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Field is one named value; Record keeps field order for JSON and CSV output.
type Field struct {
	Key   string
	Value any
}

type Record []Field

func (r Record) Get(key string) any {
	for _, f := range r {
		if f.Key == key {
			return f.Value
		}
	}
	return nil
}

func (r Record) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, f := range r {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, err := json.Marshal(f.Key)
		if err != nil {
			return nil, err
		}
		buf.Write(k)
		buf.WriteByte(':')
		v, err := marshal(f.Value)
		if err != nil {
			return nil, err
		}
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

const (
	FormatJSON  = "json"
	FormatJSONL = "jsonl"
	FormatCSV   = "csv"
)

func ValidFormat(f string) bool {
	return f == FormatJSON || f == FormatJSONL || f == FormatCSV
}

// WriteRecords writes recs; columns fixes the CSV header even when there are no rows.
func WriteRecords(w io.Writer, format string, columns []string, recs []Record) error {
	switch format {
	case FormatJSON:
		if recs == nil {
			recs = []Record{}
		}
		b, err := json.MarshalIndent(recs, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "%s\n", b)
		return err
	case FormatJSONL:
		for _, r := range recs {
			b, err := r.MarshalJSON()
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "%s\n", b); err != nil {
				return err
			}
		}
		return nil
	case FormatCSV:
		cw := csv.NewWriter(w)
		if err := cw.Write(columns); err != nil {
			return err
		}
		for _, r := range recs {
			row := make([]string, len(columns))
			for i, c := range columns {
				row[i] = csvValue(r.Get(c))
			}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
		cw.Flush()
		return cw.Error()
	}
	return fmt.Errorf("unknown format %q", format)
}

// WriteObject writes a single record (run detail) as indented JSON or one JSONL line.
func WriteObject(w io.Writer, format string, rec Record) error {
	b, err := rec.MarshalJSON()
	if err != nil {
		return err
	}
	if format == FormatJSON {
		var out bytes.Buffer
		if err := json.Indent(&out, b, "", "  "); err != nil {
			return err
		}
		b = out.Bytes()
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}

func csvValue(v any) string {
	switch v := v.(type) {
	case nil:
		return ""
	case string:
		return v
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case json.RawMessage:
		return string(v)
	default:
		b, _ := marshal(v)
		return string(b)
	}
}

var timeColumns = map[string]bool{"started_at": true, "ended_at": true, "first_seen": true, "last_seen": true, "time": true}
var boolColumns = map[string]bool{"started_before_watch": true, "is_platform_binary": true}

// FormatTime renders stored unix nanoseconds.
func FormatTime(ns int64) string {
	return time.Unix(0, ns).UTC().Format(time.RFC3339Nano)
}

// scanRecords converts rows generically: *_json columns become raw JSON under the name without
// the suffix, time columns become RFC 3339 strings, flag columns become booleans.
func scanRecords(rows *sql.Rows) ([]Record, []string, error) {
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, nil, err
	}
	keys := make([]string, len(cols))
	for i, c := range cols {
		keys[i] = strings.TrimSuffix(c, "_json")
	}
	var recs []Record
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, nil, err
		}
		rec := make(Record, len(cols))
		for i, c := range cols {
			v := vals[i]
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			switch {
			case strings.HasSuffix(c, "_json"):
				if s, ok := v.(string); ok {
					v = json.RawMessage(s)
				}
			case timeColumns[c]:
				if n, ok := v.(int64); ok {
					v = FormatTime(n)
				}
			case boolColumns[c]:
				if n, ok := v.(int64); ok {
					v = n != 0
				}
			}
			rec[i] = Field{Key: keys[i], Value: v}
		}
		recs = append(recs, rec)
	}
	return recs, keys, rows.Err()
}
