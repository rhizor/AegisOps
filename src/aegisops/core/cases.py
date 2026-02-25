from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from aegisops.core.vault_fs import acquire_case_lock, ensure_dir, atomic_write_text, dump_canonical_json
from aegisops.security.integrity import validate_case, write_manifest


class IntegrityFailure(RuntimeError):
    pass


@dataclass
class CaseContext:
    case_id: str
    case_root: Path
    enterprise: bool

    @property
    def manifest_path(self) -> Path:
        return self.case_root / "manifest.json"

    @property
    def meta_path(self) -> Path:
        return self.case_root / "case.json"


class CaseManager:
    def __init__(self, vault_root: Path):
        self.vault_root = vault_root
        self.cases_dir = vault_root / "cases"
        ensure_dir(self.cases_dir)

    def case_root(self, case_id: str) -> Path:
        return self.cases_dir / case_id

    def create_case(self, name: str, enterprise: bool = False) -> CaseContext:
        case_id = str(uuid.uuid4())
        root = self.case_root(case_id)
        ensure_dir(root)
        ensure_dir(root / "evidence")
        ensure_dir(root / "reports")
        ensure_dir(root / "freeze")

        meta = {
            "case_id": case_id,
            "name": name,
            "enterprise": bool(enterprise),
            "status": "open",
        }
        atomic_write_text(root / "case.json", dump_canonical_json(meta))

        manifest = {
            "schema_version": 1,
            "case_id": case_id,
            "evidence": [],
            "aggregate": {"hash": ""},
        }
        write_manifest(root / "manifest.json", manifest)
        return CaseContext(case_id, root, enterprise)

    def load_case(self, case_id: str) -> CaseContext:
        root = self.case_root(case_id)
        meta_path = root / "case.json"
        if not meta_path.exists():
            raise FileNotFoundError(f"Case not found: {case_id}")
        import json

        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        return CaseContext(case_id=case_id, case_root=root, enterprise=bool(meta.get("enterprise", False)))

    def open_case(self, case_id: str) -> CaseContext:
        ctx = self.load_case(case_id)
        with acquire_case_lock(ctx.case_root):
            rep = validate_case(ctx.case_root)
            if ctx.enterprise and not rep.ok:
                raise IntegrityFailure("Integrity check failed (enterprise mode)")
        return ctx

    def close_case(self, case_id: str) -> None:
        ctx = self.load_case(case_id)
        with acquire_case_lock(ctx.case_root):
            rep = validate_case(ctx.case_root)
            if ctx.enterprise and not rep.ok:
                raise IntegrityFailure("Cannot close case: integrity failed (enterprise mode)")
            import json
            meta = json.loads((ctx.meta_path).read_text(encoding="utf-8"))
            meta["status"] = "closed"
            atomic_write_text(ctx.meta_path, dump_canonical_json(meta))
