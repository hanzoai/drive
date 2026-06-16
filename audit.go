package drive

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// AuditEntry is one tamper-evident log record. The hash chain makes the trail
// append-only in evidence: altering or deleting any entry breaks every hash
// after it (SOC2 CC7.2 / CC6.1 — logical access + monitoring).
type AuditEntry struct {
	Seq      int64
	TS       int64
	Actor    string
	Action   string
	Resource string
	Detail   string
	Hash     string
}

func chainHash(seq, ts int64, actor, action, resource, detail, prev string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%d|%s|%s|%s|%s|%s", seq, ts, actor, action, resource, detail, prev)))
	return hex.EncodeToString(h[:])
}

// Audit appends a tamper-evident record. Called at the access boundary with the
// authenticated actor.
func (s *Store) Audit(actor, action, resource, detail string) error {
	var prev string
	var seq int64
	st, _, _ := s.db.Prepare(`SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`)
	if st.Step() {
		seq = st.ColumnInt64(0)
		prev = st.ColumnText(1)
	}
	st.Close()
	seq++
	ts := time.Now().Unix()
	if prev == "" {
		prev = "genesis"
	}
	h := chainHash(seq, ts, actor, action, resource, detail, prev)
	ins, _, err := s.db.Prepare(`INSERT INTO audit(seq,ts,actor,action,resource,detail,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer ins.Close()
	ins.BindInt64(1, seq); ins.BindInt64(2, ts); ins.BindText(3, actor); ins.BindText(4, action)
	ins.BindText(5, resource); ins.BindText(6, detail); ins.BindText(7, prev); ins.BindText(8, h)
	return ins.Exec()
}

// AuditTrail returns the most recent entries (evidence export).
func (s *Store) AuditTrail(limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	st, _, err := s.db.Prepare(`SELECT seq,ts,actor,action,resource,detail,hash FROM audit ORDER BY seq DESC LIMIT ?`)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	st.BindInt(1, limit)
	var out []AuditEntry
	for st.Step() {
		out = append(out, AuditEntry{st.ColumnInt64(0), st.ColumnInt64(1), st.ColumnText(2), st.ColumnText(3), st.ColumnText(4), st.ColumnText(5), st.ColumnText(6)})
	}
	return out, nil
}

// VerifyAudit recomputes the hash chain and returns the first tampered seq, or 0
// if the trail is intact. This is the control an auditor (or a continuous monitor)
// runs to prove the log was not altered.
func (s *Store) VerifyAudit() (tamperedAt int64, err error) {
	st, _, err := s.db.Prepare(`SELECT seq,ts,actor,action,resource,detail,prev_hash,hash FROM audit ORDER BY seq ASC`)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	prev := "genesis"
	for st.Step() {
		seq := st.ColumnInt64(0)
		want := chainHash(seq, st.ColumnInt64(1), st.ColumnText(2), st.ColumnText(3), st.ColumnText(4), st.ColumnText(5), st.ColumnText(6))
		if st.ColumnText(6) != prev || st.ColumnText(7) != want {
			return seq, nil
		}
		prev = st.ColumnText(7)
	}
	return 0, nil
}
