package drive_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanzoai/drive"
	"github.com/luxfi/age"
)

func idStr(t *testing.T, id age.Identity) string {
	hi, ok := id.(*age.HybridIdentity)
	if !ok { t.Fatalf("identity is %T, want *age.HybridIdentity", id) }
	return hi.String()
}

func TestHSMRootedIdentityCustody(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.sealed")
	os.Setenv("DRIVE_TEST_MASTER", "super-secret-hsm-master-0xfeed")
	cfg := map[string]string{"env_var": "DRIVE_TEST_MASTER"}

	c1, err := drive.NewCustodian("env", "drive-master", cfg)
	if err != nil { t.Fatalf("custodian: %v", err) }
	id1, r1, err := c1.LoadOrCreate(ctx, path)
	if err != nil { t.Fatalf("load/create: %v", err) }
	if id1 == nil || r1 == nil { t.Fatal("nil identity/recipient") }

	// sealed blob exists and is NOT the raw key
	sealed, err := os.ReadFile(path)
	if err != nil { t.Fatalf("no sealed blob: %v", err) }
	if string(sealed) == idStr(t, id1) || len(sealed) < 32 {
		t.Fatal("identity not sealed (plaintext at rest)")
	}

	// same HSM master → recovers the SAME identity (durable restore via HSM)
	c2, _ := drive.NewCustodian("env", "drive-master", cfg)
	id2, _, err := c2.LoadOrCreate(ctx, path)
	if err != nil { t.Fatalf("reopen: %v", err) }
	if idStr(t, id1) != idStr(t, id2) { t.Fatal("HSM master did not recover the same identity") }

	// WRONG master → cannot unseal (custody enforced by the HSM root)
	os.Setenv("DRIVE_TEST_MASTER", "attacker-guess")
	c3, _ := drive.NewCustodian("env", "drive-master", cfg)
	if _, _, err := c3.LoadOrCreate(ctx, path); err == nil {
		t.Fatal("wrong HSM master opened the identity — custody NOT enforced")
	}
	t.Log("HSM-rooted custody: identity sealed under HSM master, recovered with right master, rejected with wrong (CC6.1)")
}
