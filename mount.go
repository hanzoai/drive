package drive

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/hanzoai/cloud"
	"github.com/hanzoai/sqlite3/hanzovfs"
	"github.com/hanzoai/vfs/pkg/backend"
	_ "github.com/hanzoai/vfs/pkg/backend/file"
	_ "github.com/hanzoai/vfs/pkg/backend/s3"
	"github.com/hanzoai/zip"
	"github.com/luxfi/age"
)

func init() { cloud.Register("drive", 120, Mount) }

// Mount wires /v1/drive/* onto the cloud app (HIP-0106 subsystem contract).
// Content backend from DRIVE_BACKEND (s3:// in prod); per-tenant metadata DBs
// are encrypted SQLite under {DataDir}/drive-meta via the hanzo PQ VFS.
func Mount(app any, deps cloud.Deps) error {
	a, ok := app.(*zip.App)
	if !ok {
		return fmt.Errorf("drive: app is %T, want *zip.App", app)
	}
	beURL := os.Getenv("DRIVE_BACKEND")
	if beURL == "" {
		beURL = "file://" + filepath.Join(deps.DataDir, "drive-content")
		os.MkdirAll(filepath.Join(deps.DataDir, "drive-content"), 0o700)
	}
	be, err := backend.Open(context.Background(), beURL)
	if err != nil {
		return fmt.Errorf("drive: backend %q: %w", beURL, err)
	}
	id, rcpt, err := resolveIdentity()
	if err != nil {
		return err
	}
	hanzovfs.Register("drive-meta", hanzovfs.Config{
		Dir:        filepath.Join(deps.DataDir, "drive-meta"),
		Recipients: []age.Recipient{rcpt},
		Identities: []age.Identity{id},
	})
	svc := &service{be: be, ownerName: "owner", owner: id, ownerR: rcpt, stores: map[string]*Store{}}

	a.Get("/v1/drive/health", func(c *zip.Ctx) error {
		return c.JSON(200, map[string]string{"service": "drive", "status": "ok"})
	})
	a.Get("/v1/drive/nodes", svc.list)            // ?org=&parent=
	a.Post("/v1/drive/folders", svc.mkdir)        // ?org=&parent=&name=
	a.Post("/v1/drive/files", svc.upload)         // ?org=&parent=&name= ; body=content
	a.Get("/v1/drive/files/:id", svc.download)    // ?org=
	a.Post("/v1/drive/shares", svc.share)         // ?org=&id=&recipient=&name=&role=
	a.Get("/v1/drive/audit", svc.audit)           // ?org= — tamper-evident trail (SOC2)
	a.Get("/v1/drive/admin/access-review", svc.accessReview) // ?org= — CSV evidence (SOC2 CC6.2/6.3)
	deps.Logger.Info("drive mounted", "routes", "/v1/drive/*", "backend", beURL)
	return nil
}

type service struct {
	mu        sync.Mutex
	be        backend.Backend
	ownerName string
	owner     age.Identity
	ownerR    age.Recipient
	stores    map[string]*Store
}

func (s *service) store(org string) (*Store, error) {
	if org == "" {
		org = "default"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.stores[org]; ok {
		return st, nil
	}
	st, err := Open(fmt.Sprintf("file:/orgs/%s/drive.db?vfs=drive-meta", org), s.be)
	if err != nil {
		return nil, err
	}
	s.stores[org] = st
	return st, nil
}

func (s *service) list(c *zip.Ctx) error {
	st, err := s.store(c.Query("org"))
	if err != nil {
		return c.JSON(500, errJSON(err))
	}
	nodes, err := st.List(c.Query("parent"))
	if err != nil {
		return c.JSON(500, errJSON(err))
	}
	return c.JSON(200, map[string]any{"nodes": nodes})
}

func (s *service) mkdir(c *zip.Ctx) error {
	st, err := s.store(c.Query("org"))
	if err != nil {
		return c.JSON(500, errJSON(err))
	}
	n, err := st.Mkdir(c.Query("parent"), c.Query("name"))
	if err != nil {
		return c.JSON(500, errJSON(err))
	}
	st.Audit(actor(c), "mkdir", n.ID, n.Name)
	return c.JSON(201, n)
}

func (s *service) upload(c *zip.Ctx) error {
	st, err := s.store(c.Query("org"))
	if err != nil {
		return c.JSON(500, errJSON(err))
	}
	n, err := st.Upload(context.Background(), c.Query("parent"), c.Query("name"), bytes.NewReader(c.Body()), s.ownerR)
	if err != nil {
		return c.JSON(500, errJSON(err))
	}
	st.Audit(actor(c), "upload", n.ID, n.Name)
	return c.JSON(201, n)
}

func (s *service) download(c *zip.Ctx) error {
	st, err := s.store(c.Query("org"))
	if err != nil {
		return c.JSON(500, errJSON(err))
	}
	data, err := st.Download(context.Background(), c.Param("id"), s.ownerName, s.owner)
	if err != nil {
		st.Audit(actor(c), "download.denied", c.Param("id"), err.Error())
		return c.JSON(404, errJSON(err))
	}
	st.Audit(actor(c), "download", c.Param("id"), "")
	return c.SendStream(bytes.NewReader(data))
}

func (s *service) share(c *zip.Ctx) error {
	st, err := s.store(c.Query("org"))
	if err != nil {
		return c.JSON(500, errJSON(err))
	}
	rcpts, err := age.ParseRecipients(bytes.NewReader([]byte(c.Query("recipient") + "\n")))
	if err != nil || len(rcpts) == 0 {
		return c.JSON(400, errJSON(fmt.Errorf("bad recipient")))
	}
	role := c.Query("role")
	if role == "" {
		role = "viewer"
	}
	if err := st.Share(c.Query("id"), s.ownerName, s.owner, rcpts[0], c.Query("name"), role); err != nil {
		return c.JSON(500, errJSON(err))
	}
	st.Audit(actor(c), "share", c.Query("id"), c.Query("name")+":"+role)
	return c.JSON(200, map[string]string{"status": "shared"})
}

func actor(c *zip.Ctx) string {
	if a := c.Query("actor"); a != "" {
		return a
	}
	return "system"
}

func (s *service) audit(c *zip.Ctx) error {
	st, err := s.store(c.Query("org"))
	if err != nil {
		return c.JSON(500, errJSON(err))
	}
	trail, _ := st.AuditTrail(200)
	tampered, _ := st.VerifyAudit()
	return c.JSON(200, map[string]any{"intact": tampered == 0, "tampered_at": tampered, "entries": trail})
}

// accessReview exports the access-review evidence as CSV (SOC2 CC6.2/CC6.3): one
// row per grant (node id, node name, recipient, role). The export itself is audited.
func (s *service) accessReview(c *zip.Ctx) error {
	st, err := s.store(c.Query("org"))
	if err != nil {
		return c.JSON(500, errJSON(err))
	}
	rows, err := st.AccessReview()
	if err != nil {
		return c.JSON(500, errJSON(err))
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"node_id", "node_name", "recipient", "role"})
	for _, r := range rows {
		w.Write([]string{r.NodeID, r.NodeName, r.Recipient, r.Role})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return c.JSON(500, errJSON(err))
	}
	st.Audit(actor(c), "access-review.export", "", fmt.Sprintf("rows=%d", len(rows)))
	c.SetHeader("Content-Type", "text/csv; charset=utf-8")
	c.SetHeader("Content-Disposition", `attachment; filename="access-review.csv"`)
	return c.String(200, buf.String())
}

func errJSON(err error) map[string]string { return map[string]string{"error": err.Error()} }

func resolveIdentity() (age.Identity, age.Recipient, error) {
	if p := os.Getenv("DRIVE_AGE_KEY"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, nil, err
		}
		ids, err := age.ParseIdentities(bytes.NewReader(b))
		if err != nil || len(ids) == 0 {
			return nil, nil, fmt.Errorf("drive: DRIVE_AGE_KEY: %w", err)
		}
		if hi, ok := ids[0].(interface{ Recipient() age.Recipient }); ok {
			return ids[0], hi.Recipient(), nil
		}
	}
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, nil, err
	}
	return id, id.Recipient(), nil
}
