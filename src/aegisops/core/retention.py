from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class RetentionResult:
    deleted: List[Path]
    skipped: List[str]


def apply_retention(vault_root: Path, days: int, force_signed: bool = False) -> RetentionResult:
    """Delete freeze bundles older than N days for closed cases.

    Rules:
    - Never delete bundles for open cases.
    - Never delete signed bundles unless force_signed=True.
    """
    cutoff = time.time() - (days * 86400)
    deleted: List[Path] = []
    skipped: List[str] = []

    cases_dir = vault_root / "cases"
    if not cases_dir.exists():
        return RetentionResult([], ["No cases directory"])

    for case_root in cases_dir.iterdir():
        if not case_root.is_dir():
            continue
        meta_path = case_root / "case.json"
        if not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            skipped.append(f"Bad case.json: {case_root.name}")
            continue
        if meta.get("status") != "closed":
            skipped.append(f"Case open: {case_root.name}")
            continue

        freeze_dir = case_root / "freeze"
        if not freeze_dir.exists():
            continue

        for meta_file in freeze_dir.glob("bundle-*.zip.meta.json"):
            try:
                obj = json.loads(meta_file.read_text(encoding="utf-8"))
                created_at = int(obj.get("created_at", 0))
                zip_path = Path(obj.get("bundle_path", ""))
                if not zip_path.is_absolute():
                    zip_path = freeze_dir / zip_path
            except Exception:
                skipped.append(f"Bad bundle meta: {meta_file}")
                continue

            if created_at and created_at > cutoff:
                continue

            # meta is: bundle-<id>.zip.meta.json ; signature is: bundle-<id>.zip.sig.json
            sig_file = meta_file.with_name(meta_file.name.replace(".zip.meta.json", ".zip.sig.json"))
            if sig_file.exists() and not force_signed:
                skipped.append(f"Signed bundle skipped: {zip_path.name}")
                continue

            # Delete zip, meta, sig if any
            for p in [zip_path, meta_file, sig_file]:
                try:
                    if p.exists():
                        p.unlink()
                        deleted.append(p)
                except Exception as e:
                    skipped.append(f"Failed to delete {p}: {e}")

    return RetentionResult(deleted, skipped)
