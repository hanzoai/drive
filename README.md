# Hanzo Drive

End-to-end **post-quantum**, Google-Drive-class storage on the Hanzo object substrate.
Content never reaches the server in plaintext; sharing is a key re-wrap, not a re-encrypt.

## How it's built (one substrate, no new services)

```
        storage-console (web)        FUSE mount (desktop sync)
                    \                /
                  hanzoai/drive  (this repo)
        per-tenant metadata + ACLs  |  content blobs
                    |               |
        hanzoai/sqlite3 + hanzovfs  |  hanzoai/vfs ⇒ hanzoai/s3
        (encrypted SQLite, PQ)      |  (content-addressed, PQ blocks)
                    \_______________/
                    lux.id (auth/share) · luxfi/hsm+kms (key custody)
```

- **Content** — each file is sealed with a fresh per-node DEK (ChaCha20-Poly1305),
  stored as a content-addressed blob on a `hanzoai/vfs` backend (`s3://` in prod).
- **Metadata + ACLs** — folder tree, versions, and shares live in a per-tenant
  **encrypted SQLite** (`hanzoai/sqlite3` + `hanzovfs`), so metadata is PQ at rest too.
- **Sharing** — the node DEK is sealed to each recipient's **ML-KEM-768 + X25519**
  identity (`luxfi/age`). Sharing re-wraps the DEK; the content bytes never re-encrypt
  and the server never sees plaintext. Revocation rotates the DEK forward.
- **Versioning / dedup** — blobs are content-addressed, so an edit stores only new
  blobs and file history is an immutable blob set.

## Surfaces
- **Web**: `hanzoai/storage-console` over the `/v1/drive/*` API (mounts into `hanzoai/cloud`).
- **Desktop sync**: the `hanzoai/vfs` FUSE mount — a normal folder, encrypted-at-rest.

## Status
Core library + **`/v1/drive` HTTP surface** (cloud subsystem `Mount`, registers into
`cloud.Registry` order 120) both green — health, upload (PQ-sealed), list, download,
share. storage-console can hit `/v1/drive/*` once the cloud binary enables `drive`.
Tamper-evident **audit trail** (hash-chained, `VerifyAudit`) + `/v1/drive/audit` — SOC 2 CC7.2.
See [`SOC2-READINESS.md`](SOC2-READINESS.md). Next: HSM-rooted DEK custody (`luxfi/hsm`),
SIEM log export, chunked large files, storage-console wiring.

See [`HIP`]: realizes HIP-0302 (encrypted SQLite) + HIP-0107 (VFS replication).
MIT (depends on AGPL `hanzoai/s3` at the storage floor).
