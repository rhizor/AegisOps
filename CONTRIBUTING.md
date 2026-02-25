# Contributing to AegisOps

Thanks for helping improve AegisOps.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
pytest -q
```

## Guidelines

- Keep changes minimal and well-tested.
- Prefer deterministic outputs (especially for hashing, manifests, reports).
- Security-sensitive code must include negative tests.

## Reporting security issues

Please follow [SECURITY.md](SECURITY.md).
