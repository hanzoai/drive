package drive

// Custodian roots Drive's per-deployment post-quantum identity in an HSM via
// luxfi/hsm. The wrapping key is derived (HKDF) from a master that the HSM holds
// and never releases in cleartext beyond transient use — AWS/GCP/Azure KMS,
// Zymbit, YubiHSM, PKCS#11, etc. in prod; env/file for dev. The tenant's age
// ML-KEM-768+X25519 identity is sealed under that key, so the PQ secret is never
// stored or shipped in the clear, and a node restore needs the HSM, not a file.
//
// This is the CC6.1 key-custody control: replaces the deployment-identity
// stand-in. It should graduate to a shared hanzoai/kms package once a second
// service needs it (one way).

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/luxfi/age"
	"github.com/luxfi/hsm"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// Custodian wraps/unwraps the Drive identity using an HSM-held master.
type Custodian struct {
	provider hsm.PasswordProvider
	keyID    string
	attest   hsm.Signer // ML-DSA attestation of custody events (optional)
}

// NewCustodian builds a Custodian. provider ∈ {aws,gcp,azure,zymbit,env,file,...};
// keyID identifies the master in that provider; cfg carries provider params.
func NewCustodian(provider, keyID string, cfg map[string]string) (*Custodian, error) {
	p, err := hsm.NewPasswordProvider(provider, cfg)
	if err != nil {
		return nil, fmt.Errorf("drive/custody: provider %q: %w", provider, err)
	}
	return &Custodian{provider: p, keyID: keyID, attest: hsm.NewMLDSASigner(0)}, nil
}

// wrapKey derives a 32-byte AEAD key from the HSM master (never persisted).
func (c *Custodian) wrapKey(ctx context.Context) ([]byte, error) {
	master, err := c.provider.GetPassword(ctx, c.keyID)
	if err != nil {
		return nil, fmt.Errorf("drive/custody: fetch master: %w", err)
	}
	if master == "" {
		return nil, errors.New("drive/custody: empty master from HSM")
	}
	r := hkdf.New(sha3.New256, []byte(master), []byte("hanzo-drive-custody-v1"), []byte("dek-identity-wrap"))
	wk := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, wk); err != nil {
		return nil, err
	}
	return wk, nil
}

func sealUnder(wk, plain []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(wk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, plain, nil), nil
}

func openUnder(wk, sealed []byte) ([]byte, error) {
	a, err := chacha20poly1305.New(wk)
	if err != nil {
		return nil, err
	}
	if len(sealed) < a.NonceSize() {
		return nil, errors.New("drive/custody: truncated sealed blob")
	}
	return a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], nil)
}

func recipientOf(id age.Identity) (age.Recipient, error) {
	if hi, ok := id.(*age.HybridIdentity); ok {
		return hi.Recipient(), nil
	}
	if xi, ok := id.(*age.X25519Identity); ok {
		return xi.Recipient(), nil
	}
	return nil, errors.New("drive/custody: identity has no recipient")
}

// LoadOrCreate returns the deployment identity: it opens the HSM-sealed blob at
// path, or (first run) generates a PQ identity, seals it under the HSM master,
// and persists the sealed blob. The blob is safe at rest — only the HSM master
// (never on disk) can open it.
func (c *Custodian) LoadOrCreate(ctx context.Context, path string) (age.Identity, age.Recipient, error) {
	wk, err := c.wrapKey(ctx)
	if err != nil {
		return nil, nil, err
	}
	if sealed, err := os.ReadFile(path); err == nil {
		plain, err := openUnder(wk, sealed)
		if err != nil {
			return nil, nil, fmt.Errorf("drive/custody: unseal identity (wrong HSM master?): %w", err)
		}
		ids, err := age.ParseIdentities(bytes.NewReader(plain))
		if err != nil || len(ids) == 0 {
			return nil, nil, fmt.Errorf("drive/custody: parse sealed identity: %w", err)
		}
		rcpt, err := recipientOf(ids[0])
		return ids[0], rcpt, err
	}
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, nil, err
	}
	sealed, err := sealUnder(wk, []byte(id.String()))
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(path, sealed, 0o600); err != nil {
		return nil, nil, err
	}
	// non-repudiable attestation that this identity was provisioned under the HSM
	_, _ = c.attest.Sign(ctx, "drive-custody", append([]byte("provisioned:"), sealed...))
	return id, id.Recipient(), nil
}
