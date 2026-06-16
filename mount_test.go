package drive_test

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/cloud"
	"github.com/hanzoai/drive"
	_ "github.com/hanzoai/sqlite3/embed"
	"github.com/hanzoai/zip"
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
