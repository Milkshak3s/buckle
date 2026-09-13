package store

import (
	"sort"
	"strings"

	"buckle/internal/wire"
)

// ChangesSince returns up to limit rows from all shipped tables with rev > cursor, lowest revision
// first, read from one snapshot. Each table contributes at most limit rows, so the merged prefix is
// exactly the limit lowest revisions overall.
func (s *Store) ChangesSince(cursor int64, limit int) ([]wire.Row, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var all []wire.Row
	for _, t := range wire.Tables {
		cols := wire.Columns[t]
		rows, err := tx.Query(`SELECT `+strings.Join(cols, ", ")+` FROM `+t+` WHERE rev > ? ORDER BY rev LIMIT ?`, cursor, limit)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				return nil, err
			}
			data := make(map[string]any, len(cols))
			for i, c := range cols {
				v := vals[i]
				if b, ok := v.([]byte); ok {
					v = string(b)
				}
				data[c] = v
			}
			rev, _ := data["rev"].(int64)
			all = append(all, wire.Row{Table: t, Rev: rev, Data: data})
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Rev < all[j].Rev })
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}
