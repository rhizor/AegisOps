# AegisOps

AegisOps is a **local-first** cybersecurity operations toolkit focused on **case management**, **evidence integrity**, **reproducible reports**, and **forensic snapshots** ("freeze bundles") with optional **Ed25519 signing**.

> Status: MVP / functional prototype. Designed to be extended (plugins, AI governance, SaaS migration later).

## What you get

- Case + evidence vault layout (`vault/`)
- Evidence integrity model:
  - SHA-256 per evidence file
  - Per-case `manifest.json`
  - Aggregate hash (deterministic)
  - Enterprise mode blocks actions on integrity failure
- Safe filesystem behavior:
  - POSIX umask hardening (best-effort)
  - Atomic writes for manifests and outputs
  - Case locks
  - Path traversal protection
- Reports:
  - `md` (primary) + `html` (escaped) + `pdf` (text-only)
- Freeze bundles:
  - Snapshot `manifest + report (+ AI output if present)`
  - `--full` option to include evidence files
  - Internal per-file hashes (`hashes.json`)
  - Optional Ed25519 signing + verification
- Retention policy for freeze bundles
- SOC-friendly status commands (`freeze status`, `status-all`, table output)

## Install

Requirements:
- Python **3.10+**

Install locally:

```bash
pip install -e .
```

## Quick start

Create a case:

```bash
aegisops --vault-root ./vault case create --name "Demo" --enterprise
```

Add evidence:

```bash
aegisops --vault-root ./vault evidence add <CASE_ID> ./sample.txt --source manual --notes "initial capture"
```

Validate/open (enterprise mode blocks on tampering):

```bash
aegisops --vault-root ./vault case open <CASE_ID>
```

Generate a report:

```bash
aegisops --vault-root ./vault report generate <CASE_ID> --format md
```

Freeze (snapshot):

```bash
aegisops --vault-root ./vault freeze <CASE_ID> --report-format md
```

Freeze FULL (includes evidence, with size cap):

```bash
aegisops --vault-root ./vault freeze <CASE_ID> --report-format md --full --max-evidence-size-mb 100
```

Verify latest bundle for a case:

```bash
aegisops --vault-root ./vault freeze verify-case <CASE_ID>
```

Status overview for all cases (JSON):

```bash
aegisops --vault-root ./vault freeze status-all
```

Status overview for all cases (table):

```bash
aegisops --vault-root ./vault freeze status-all --format table
```

## Security notes

- **Local-first** by default.
- Do not store secrets in the vault.
- The PDF generator is **text-only** (no remote assets, no script execution).
- Integrity checks are deterministic and block report/freeze when running in enterprise mode.

## Roadmap (high level)

- Encryption-at-rest (optional)
- Expanded AI governance + provider integrations
- Stronger Windows ACL management (best-effort today)
- RBAC / multi-user mode
- SaaS migration path

## License

Apache-2.0. See [LICENSE](LICENSE).
