package drive

// Exec runs a statement on the tenant metadata DB. Exported for audit
// verification tooling and tests.
func (s *Store) Exec(sql string) error { return s.db.Exec(sql) }
