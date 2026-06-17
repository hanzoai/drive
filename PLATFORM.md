# CI/CD on hanzoai/platform — no GitHub Actions

This repo is built, run, and scanned by **hanzoai/platform** (the Hanzo PaaS),
not GitHub Actions. `.github/workflows` is intentionally absent.

- **Build / run** — the platform builds via Dockerfile / Nixpacks / Railpack and
  runs the result; auto-deploy on push.
- **Actions (CI)** — a platform **Scheduled Task** (and/or build step) runs
  `make ci` = `build → test → scan` (govulncheck + gitleaks + CycloneDX SBOM),
  on push and on a cron. SOC 2 CC7.x/CC8.x evidence (artifacts to hanzoai/audit).
- The platform build env carries Git credentials for `github.com/hanzoai` +
  `github.com/luxfi`, so cross-org private modules resolve natively — no per-repo
  token dance (the thing that made GitHub Actions painful).

Run anywhere: `make ci`.
