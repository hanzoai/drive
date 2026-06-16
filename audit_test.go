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

func TestAuditTamperEvident(t *testing.T) {
	ctx := context.Background()
	be, _ := backend.Open(ctx, "file://"+t.TempDir())
	st, _ := drive.Open("file:"+t.TempDir()+"/m.db", be)
	defer st.Close()
	owner, _ := age.GenerateHybridIdentity()

	f, _ := st.Mkdir("", "docs")
	st.Audit("zach@hanzo.ai", "mkdir", f.ID, "docs")
	n, _ := st.Upload(ctx, f.ID, "a.txt", strings.NewReader("x"), owner.Recipient())
	st.Audit("zach@hanzo.ai", "upload", n.ID, "a.txt")
	st.Audit("ops@hanzo.ai", "download", n.ID, "")

	trail, _ := st.AuditTrail(10)
	if len(trail) != 3 { t.Fatalf("trail len=%d want 3", len(trail)) }
	if at, _ := st.VerifyAudit(); at != 0 { t.Fatalf("intact chain flagged tamper at %d", at) }

	// tamper: rewrite an actor in place (the classic "cover your tracks") — chain must break
	st.Exec(`UPDATE audit SET actor='nobody' WHERE action='download'`)
	at, _ := st.VerifyAudit()
	if at == 0 { t.Fatal("tamper NOT detected — audit log is not tamper-evident") }
	t.Logf("tamper detected at seq %d — hash chain holds (SOC2 CC7.2)", at)
}
