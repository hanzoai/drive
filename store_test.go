package drive_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hanzoai/drive"
	_ "github.com/hanzoai/sqlite3/embed"
	"github.com/hanzoai/vfs/pkg/backend"
	_ "github.com/hanzoai/vfs/pkg/backend/file"
	"github.com/luxfi/age"
)

func TestDriveRoundTripPQShare(t *testing.T) {
	ctx := context.Background()
	u := "file://" + t.TempDir()
	be, err := backend.Open(ctx, u)
	if err != nil { t.Fatalf("backend: %v", err) }
	st, err := drive.Open("file:"+t.TempDir()+"/meta.db", be)
	if err != nil { t.Fatalf("open: %v", err) }
	defer st.Close()

	owner, _ := age.GenerateHybridIdentity()
	folder, err := st.Mkdir("", "docs")
	if err != nil { t.Fatalf("mkdir: %v", err) }
	node, err := st.Upload(ctx, folder.ID, "secret.txt", strings.NewReader("top secret"), owner.Recipient())
	if err != nil { t.Fatalf("upload: %v", err) }

	kids, _ := st.List(folder.ID)
	if len(kids) != 1 || kids[0].Name != "secret.txt" { t.Fatalf("list: %+v", kids) }

	// owner downloads + decrypts
	got, err := st.Download(ctx, node.ID, "owner", owner)
	if err != nil || string(got) != "top secret" { t.Fatalf("owner download: %q %v", got, err) }

	// share to bob (re-wrap DEK to bob's ML-KEM); bob downloads
	bob, _ := age.GenerateHybridIdentity()
	if err := st.Share(node.ID, "owner", owner, bob.Recipient(), "bob", "viewer"); err != nil { t.Fatalf("share: %v", err) }
	got, err = st.Download(ctx, node.ID, "bob", bob)
	if err != nil || string(got) != "top secret" { t.Fatalf("bob download: %q %v", got, err) }

	// mallory has no share → must be denied
	mallory, _ := age.GenerateHybridIdentity()
	if _, err := st.Download(ctx, node.ID, "mallory", mallory); err == nil {
		t.Fatal("mallory downloaded without a share — e2e ACL broken")
	}
	t.Log("Hanzo Drive e2e-PQ: upload sealed, owner+shared decrypt via ML-KEM unwrap, non-shared denied")
}

// TestDRRestoreDrill proves restore-from-substrate (SOC2 A1.3 — recovery): after
// total node loss (Store closed), a FRESH Store opened against the SAME content
// backend dir and the SAME metadata DB path recovers every file byte-for-byte and
// the tamper-evident audit chain still verifies intact.
func TestDRRestoreDrill(t *testing.T) {
	ctx := context.Background()
	// Fixed paths shared across the "before" and "after" Store instances.
	backendDir := t.TempDir()
	metaDSN := "file:" + t.TempDir() + "/meta.db"
	owner, _ := age.GenerateHybridIdentity()

	files := map[string]string{
		"contract.txt": "binding agreement v1",
		"ledger.csv":   "date,amount\n2026-06-16,42",
		"keys.bin":     "\x00\x01\x02\xfe\xff binary payload",
	}

	// --- before: open Store, upload several files, record node ids, audit, close ---
	nodeIDs := map[string]string{}
	{
		be, err := backend.Open(ctx, "file://"+backendDir)
		if err != nil { t.Fatalf("backend open: %v", err) }
		st, err := drive.Open(metaDSN, be)
		if err != nil { t.Fatalf("open: %v", err) }
		for name, body := range files {
			n, err := st.Upload(ctx, "", name, strings.NewReader(body), owner.Recipient())
			if err != nil { t.Fatalf("upload %s: %v", name, err) }
			nodeIDs[name] = n.ID
			if err := st.Audit("alice", "upload", n.ID, name); err != nil { t.Fatalf("audit: %v", err) }
		}
		if at, _ := st.VerifyAudit(); at != 0 { t.Fatalf("pre-loss audit tampered at %d", at) }
		// simulate node loss: drop the running Store entirely.
		if err := st.Close(); err != nil { t.Fatalf("close: %v", err) }
	}

	// --- after: FRESH Store against the SAME substrate — restore-from-disk ---
	be, err := backend.Open(ctx, "file://"+backendDir)
	if err != nil { t.Fatalf("restore backend open: %v", err) }
	st, err := drive.Open(metaDSN, be)
	if err != nil { t.Fatalf("restore open: %v", err) }
	defer st.Close()

	for name, want := range files {
		got, err := st.Download(ctx, nodeIDs[name], "owner", owner)
		if err != nil { t.Fatalf("restore download %s: %v", name, err) }
		if string(got) != want { t.Fatalf("restore %s: got %q want %q", name, got, want) }
	}
	if at, _ := st.VerifyAudit(); at != 0 {
		t.Fatalf("audit chain broke across restore at seq %d — substrate not durable", at)
	}
	t.Log(fmt.Sprintf("DR drill (SOC2 A1.3): %d files restored byte-identical from substrate + audit chain intact", len(files)))
}
