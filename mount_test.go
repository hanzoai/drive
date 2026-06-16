package drive_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/cloud"
	"github.com/hanzoai/drive"
	_ "github.com/hanzoai/sqlite3/embed"
	"github.com/hanzoai/zip"
	"github.com/luxfi/age"
	luxlog "github.com/luxfi/log"
)

func TestDriveMountAPI(t *testing.T) {
	log := luxlog.New("drive-test")
	app := zip.New(zip.Config{Logger: log})
	if err := drive.Mount(app, cloud.Deps{Logger: log, DataDir: t.TempDir(), Brand: "hanzo"}); err != nil {
		t.Fatalf("mount: %v", err)
	}
	test := func(method, path, body string) (int, []byte) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		resp, err := app.Fiber().Test(req)
		if err != nil { t.Fatalf("%s %s: %v", method, path, err) }
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	if c, _ := test("GET", "/v1/drive/health", ""); c != 200 { t.Fatalf("health=%d", c) }

	c, b := test("POST", "/v1/drive/files?org=acme&parent=&name=a.txt", "hello drive")
	if c != 201 { t.Fatalf("upload=%d %s", c, b) }
	var node struct{ ID string }
	json.Unmarshal(b, &node)
	if node.ID == "" { t.Fatalf("no node id: %s", b) }

	c, b = test("GET", "/v1/drive/nodes?org=acme&parent=", "")
	if c != 200 || !strings.Contains(string(b), "a.txt") { t.Fatalf("list=%d %s", c, b) }

	c, b = test("GET", "/v1/drive/files/"+node.ID+"?org=acme", "")
	if c != 200 || string(b) != "hello drive" { t.Fatalf("download=%d %q", c, b) }
	t.Log("/v1/drive API: health, upload (PQ-sealed), list, download — all green")
}

func TestDriveAccessReviewExportAPI(t *testing.T) {
	log := luxlog.New("drive-test")
	app := zip.New(zip.Config{Logger: log})
	if err := drive.Mount(app, cloud.Deps{Logger: log, DataDir: t.TempDir(), Brand: "hanzo"}); err != nil {
		t.Fatalf("mount: %v", err)
	}
	test := func(method, path, body string) (int, []byte) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		resp, err := app.Fiber().Test(req)
		if err != nil { t.Fatalf("%s %s: %v", method, path, err) }
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}

	// upload a file, then share it to two recipients with distinct roles.
	c, b := test("POST", "/v1/drive/files?org=acme&parent=&name=report.txt", "quarterly numbers")
	if c != 201 { t.Fatalf("upload=%d %s", c, b) }
	var node struct{ ID string }
	json.Unmarshal(b, &node)
	if node.ID == "" { t.Fatalf("no node id: %s", b) }

	bob, _ := age.GenerateHybridIdentity()
	carol, _ := age.GenerateHybridIdentity()
	bobR := fmt.Sprintf("%s", bob.Recipient())
	carolR := fmt.Sprintf("%s", carol.Recipient())
	if c, b := test("POST", "/v1/drive/shares?org=acme&id="+node.ID+"&recipient="+url.QueryEscape(bobR)+"&name=bob&role=viewer", ""); c != 200 {
		t.Fatalf("share bob=%d %s", c, b)
	}
	if c, b := test("POST", "/v1/drive/shares?org=acme&id="+node.ID+"&recipient="+url.QueryEscape(carolR)+"&name=carol&role=editor", ""); c != 200 {
		t.Fatalf("share carol=%d %s", c, b)
	}

	// hit the access-review export and assert the CSV evidence.
	c, b = test("GET", "/v1/drive/admin/access-review?org=acme", "")
	if c != 200 { t.Fatalf("access-review=%d %s", c, b) }
	csv := string(b)
	for _, want := range []string{"node_id,node_name,recipient,role", "report.txt", "bob,viewer", "carol,editor"} {
		if !strings.Contains(csv, want) { t.Fatalf("access-review CSV missing %q:\n%s", want, csv) }
	}

	// the export itself must be audited (SOC2 evidence of evidence access).
	c, b = test("GET", "/v1/drive/audit?org=acme", "")
	if c != 200 || !strings.Contains(string(b), "access-review.export") {
		t.Fatalf("export not audited: %d %s", c, b)
	}
	t.Log("/v1/drive/admin/access-review: CSV with recipients+roles, export audited — SOC2 CC6.2/6.3 green")
}
