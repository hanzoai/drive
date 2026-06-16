// Package drive is Hanzo Drive: end-to-end post-quantum, Google-Drive-class
// storage. Content is content-addressed, ChaCha20-Poly1305-sealed blobs on a
// hanzoai/vfs backend (⇒ hanzoai/s3); metadata + ACLs are an encrypted SQLite
// per tenant. Sharing re-wraps a node's DEK to a recipient's ML-KEM identity —
// the bytes never re-encrypt and the server never sees plaintext.
package drive

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/hanzoai/sqlite3"
	"github.com/hanzoai/vfs/pkg/backend"
	"github.com/luxfi/age"
	"golang.org/x/crypto/chacha20poly1305"
)

// Store is one tenant's Drive: a metadata DB + a content backend.
type Store struct {
	db      *sqlite3.Conn
	content backend.Backend
}

// Node is a folder or file in the tree.
type Node struct {
	ID, ParentID, Name, Kind, ContentKey string
	Size                                  int64
	ModifiedAt                            int64
}

// Open opens a tenant Store: metaDSN is a hanzoai/sqlite3 DSN (use vfs=hanzo for
// the encrypted per-tenant DB); content is a vfs backend (s3:// in prod).
func Open(metaDSN string, content backend.Backend) (*Store, error) {
	db, err := sqlite3.Open(metaDSN)
	if err != nil {
		return nil, err
	}
	if err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("drive: schema: %w", err)
	}
	return &Store{db: db, content: content}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func id() string { b := make([]byte, 16); rand.Read(b); return hex.EncodeToString(b) }
func now() int64 { return time.Now().Unix() }

// Mkdir creates a folder.
func (s *Store) Mkdir(parent, name string) (*Node, error) {
	n := &Node{ID: id(), ParentID: parent, Name: name, Kind: "folder", ModifiedAt: now()}
	st, _, err := s.db.Prepare(`INSERT INTO nodes(id,parent_id,name,kind,size,created_at,modified_at) VALUES(?,?,?,'folder',0,?,?)`)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	st.BindText(1, n.ID); st.BindText(2, parent); st.BindText(3, name); st.BindInt64(4, n.ModifiedAt); st.BindInt64(5, n.ModifiedAt)
	if err := st.Exec(); err != nil {
		return nil, err
	}
	return n, nil
}

// Upload seals content with a fresh per-node DEK, stores the content-addressed
// blob, records the node + version, and wraps the DEK to the owner. Returns the node.
func (s *Store) Upload(ctx context.Context, parent, name string, r io.Reader, owner age.Recipient) (*Node, error) {
	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	dek := make([]byte, chacha20poly1305.KeySize)
	rand.Read(dek)
	aead, _ := chacha20poly1305.New(dek)
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	sealed := aead.Seal(nonce, nonce, plain, nil)
	key := hex.EncodeToString(sha256.New().Sum(sealed)[:]) // content-addressed
	if err := s.content.Put(ctx, key, sealed); err != nil {
		return nil, fmt.Errorf("drive: content put: %w", err)
	}
	n := &Node{ID: id(), ParentID: parent, Name: name, Kind: "file", ContentKey: key, Size: int64(len(plain)), ModifiedAt: now()}
	if err := s.db.Exec("BEGIN"); err != nil {
		return nil, err
	}
	st, _, _ := s.db.Prepare(`INSERT INTO nodes(id,parent_id,name,kind,size,content_key,created_at,modified_at) VALUES(?,?,?,'file',?,?,?,?)`)
	st.BindText(1, n.ID); st.BindText(2, parent); st.BindText(3, name); st.BindInt64(4, n.Size); st.BindText(5, key); st.BindInt64(6, n.ModifiedAt); st.BindInt64(7, n.ModifiedAt)
	if err := st.Exec(); err != nil { st.Close(); s.db.Exec("ROLLBACK"); return nil, err }
	st.Close()
	vs, _, _ := s.db.Prepare(`INSERT INTO versions(id,node_id,content_key,size,created_at) VALUES(?,?,?,?,?)`)
	vs.BindText(1, id()); vs.BindText(2, n.ID); vs.BindText(3, key); vs.BindInt64(4, n.Size); vs.BindInt64(5, n.ModifiedAt)
	vs.Exec(); vs.Close()
	if err := s.wrapDEK(n.ID, "owner", "owner", dek, owner); err != nil { s.db.Exec("ROLLBACK"); return nil, err }
	return n, s.db.Exec("COMMIT")
}

// wrapDEK seals a node's DEK to a recipient and records the share (ACL row).
func (s *Store) wrapDEK(nodeID, recipient, role string, dek []byte, to age.Recipient) error {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, to)
	if err != nil {
		return err
	}
	w.Write(dek); w.Close()
	st, _, _ := s.db.Prepare(`INSERT OR REPLACE INTO shares(node_id,recipient,role,wrapped_dek,created_at) VALUES(?,?,?,?,?)`)
	defer st.Close()
	st.BindText(1, nodeID); st.BindText(2, recipient); st.BindText(3, role); st.BindBlob(4, buf.Bytes()); st.BindInt64(5, now())
	return st.Exec()
}

// Share re-wraps an existing node's DEK to a new recipient — e2e, no re-encrypt.
// The caller must hold a share they can unwrap (their identity) to recover the DEK.
func (s *Store) Share(nodeID, asRecipient string, as age.Identity, to age.Recipient, toName, role string) error {
	dek, err := s.unwrap(nodeID, asRecipient, as)
	if err != nil {
		return err
	}
	return s.wrapDEK(nodeID, toName, role, dek, to)
}

func (s *Store) unwrap(nodeID, recipient string, as age.Identity) ([]byte, error) {
	st, _, _ := s.db.Prepare(`SELECT wrapped_dek FROM shares WHERE node_id=? AND recipient=?`)
	defer st.Close()
	st.BindText(1, nodeID); st.BindText(2, recipient)
	if !st.Step() {
		return nil, errors.New("drive: no share for recipient")
	}
	wrapped := st.ColumnRawBlob(0)
	r, err := age.Decrypt(bytes.NewReader(wrapped), as)
	if err != nil {
		return nil, fmt.Errorf("drive: unwrap DEK: %w", err)
	}
	return io.ReadAll(r)
}

// Download fetches + decrypts a file for a recipient who holds a share.
func (s *Store) Download(ctx context.Context, nodeID, recipient string, as age.Identity) ([]byte, error) {
	var ckey string
	st, _, _ := s.db.Prepare(`SELECT content_key FROM nodes WHERE id=? AND trashed=0`)
	st.BindText(1, nodeID)
	if !st.Step() { st.Close(); return nil, errors.New("drive: node not found") }
	ckey = st.ColumnText(0); st.Close()
	dek, err := s.unwrap(nodeID, recipient, as)
	if err != nil {
		return nil, err
	}
	sealed, err := s.content.Get(ctx, ckey)
	if err != nil {
		return nil, err
	}
	aead, _ := chacha20poly1305.New(dek)
	ns := aead.NonceSize()
	return aead.Open(nil, sealed[:ns], sealed[ns:], nil)
}

// List returns the children of a folder.
func (s *Store) List(parent string) ([]Node, error) {
	st, _, err := s.db.Prepare(`SELECT id,name,kind,size,coalesce(content_key,''),modified_at FROM nodes WHERE parent_id=? AND trashed=0 ORDER BY kind,name`)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	st.BindText(1, parent)
	var out []Node
	for st.Step() {
		out = append(out, Node{ID: st.ColumnText(0), ParentID: parent, Name: st.ColumnText(1), Kind: st.ColumnText(2), Size: st.ColumnInt64(3), ContentKey: st.ColumnText(4), ModifiedAt: st.ColumnInt64(5)})
	}
	return out, nil
}
