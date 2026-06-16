package drive_test

import (
	"context"
	
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
