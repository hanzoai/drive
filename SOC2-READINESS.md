# SOC 2 Readiness — Hanzo Drive

**Readiness is not certification.** SOC 2 (Type II) is an *audit*: an independent
CPA firm observes controls operating over a 3–12 month window and issues the
report. No code makes an org "SOC 2 compliant." This document maps the **technical
controls** Hanzo Drive implements to the Trust Services Criteria, and is honest
about what is code versus organizational process an auditor must still see.

## Control matrix (Common Criteria + C/A)

| TSC | Control | Where | Status |
|-----|---------|-------|--------|
| CC6.1 | Encryption at rest | per-node DEK (ChaCha20-Poly1305), DEK sealed ML-KEM-768+X25519 (luxfi/age); metadata in encrypted SQLite | **code ✓** |
| CC6.1 | Key management | `luxfi/hsm` + `hanzoai/kms` root-of-trust | **gap** — wire HSM custody (today: deployment identity stand-in) |
| CC6.6 | Logical access / authN | `lux.id` OIDC at the gateway; per-request tenant scope | **code ✓** (infra) |
| CC6.3 | Least privilege / authZ | per-share roles (viewer/editor/owner); DEK only re-wrapped to authorized ML-KEM recipients | **code ✓** |
| CC6.1 | Tenant isolation | one encrypted SQLite + key per org (`{DataDir}/orgs/{org}/drive.db`); no shared DB | **code ✓** |
| CC6.7 | Encryption in transit | TLS via cert-manager DNS-01 (Cloudflare/KMS); ML-KEM hybrid TLS roadmap | **infra ✓** |
| CC7.2 | Audit logging / monitoring | hash-chained, append-only audit trail; `VerifyAudit` detects any alteration | **code ✓** (this release) |
| CC7.3 | Anomaly detection | ship audit + `o11y` metrics to SIEM | **gap** — wire log export |
| CC8.1 | Change management | Git + required PR review + CI on every repo | **process ✓** |
| A1.2 | Availability / DR | content + metadata replicate to S3 (HIP-0107); restore-on-boot | **code ✓** |
| C1.1/C1.2 | Confidentiality | e2e encryption; provider sees only ciphertext + wrapped DEKs | **code ✓** |
| CC1–CC5 | Governance, risk, policy, HR | security policy, risk assessment, background checks, vendor mgmt, IR runbook, access reviews | **org process** — not code; evidence required |

## Gaps to close for "audit-ready"
1. ~~HSM-root the DEK custody~~ ✅ done (`custody.go`, `luxfi/hsm`); set `DRIVE_HSM_PROVIDER`+`DRIVE_HSM_KEY_ID` to a real KMS/HSM in prod. Threshold (`luxfi/mpc`) is the next custody layer.
2. **Ship the audit trail + o11y to a SIEM** with retention + alerting (CC7.2/7.3).
3. **Automated access reviews** — periodic export of `shares` per tenant for owner attestation.
4. **Retention/legal-hold** policy enforced on `versions`/`audit` (immutable S3 object-lock recommended).
5. Organizational: policies, risk register, vendor list, IR plan, change-management evidence — owned by the security program, not this repo.

## What an auditor can already test here
- Pull `GET /v1/drive/audit?org=<t>` → tamper-evident trail; run `VerifyAudit` → proves the log was not altered.
- Inspect at-rest objects in S3 → only ciphertext + ML-KEM-wrapped DEKs, no plaintext.
- Attempt cross-tenant access → denied by per-tenant key + DB isolation (see tests).
