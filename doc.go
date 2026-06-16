// Package drive — Hanzo Drive. See README.md.
//
// Threat model: the server (and S3 provider) are honest-but-curious. All content
// and metadata are encrypted client/edge-side; the server stores only ciphertext
// and ML-KEM-wrapped DEKs. A quantum adversary recording all objects learns
// nothing without a tenant's ML-KEM identity (custodied by luxfi/hsm in prod).
package drive
