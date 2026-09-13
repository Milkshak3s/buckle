package store

import "time"

type PruneStats struct {
	Runs, Orphans, Watches, Sessions, Profiles int64
}

// Prune deletes runs and orphans older than maxAge (runs cascade to processes and denials),
// then removes watches, sessions and profiles that nothing references any more.
func (s *Store) Prune(now time.Time, maxAge time.Duration) (PruneStats, error) {
	cutoff := now.Add(-maxAge).UnixNano()
	var st PruneStats
	tx, err := s.DB.Begin()
	if err != nil {
		return st, err
	}
	defer tx.Rollback()
	steps := []struct {
		n    *int64
		stmt string
		args []any
	}{
		{&st.Runs, `DELETE FROM runs WHERE started_at < ?`, []any{cutoff}},
		{&st.Orphans, `DELETE FROM orphans WHERE time < ?`, []any{cutoff}},
		{&st.Watches, `DELETE FROM watches WHERE started_at < ?
			AND NOT EXISTS (SELECT 1 FROM runs WHERE runs.watch_id = watches.id)
			AND NOT EXISTS (SELECT 1 FROM orphans WHERE orphans.watch_id = watches.id)`, []any{cutoff}},
		{&st.Sessions, `DELETE FROM sessions WHERE NOT EXISTS (SELECT 1 FROM runs WHERE runs.session_id = sessions.id)`, nil},
		{&st.Profiles, `DELETE FROM profiles WHERE NOT EXISTS (SELECT 1 FROM runs WHERE runs.profile_hash = profiles.hash)`, nil},
	}
	for _, step := range steps {
		res, err := tx.Exec(step.stmt, step.args...)
		if err != nil {
			return st, err
		}
		if *step.n, err = res.RowsAffected(); err != nil {
			return st, err
		}
	}
	return st, tx.Commit()
}
