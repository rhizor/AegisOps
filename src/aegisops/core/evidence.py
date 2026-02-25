from __future__ import annotations

import mimetypes
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from aegisops.core.vault_fs import acquire_case_lock, ensure_dir, ensure_file_mode
from aegisops.security.integrity import hash_file, load_manifest, write_manifest


def _safe_filename(name: str) -> str:
    # Very conservative filename sanitizer
    name = name.replace("\\", "_").replace("/", "_").strip()
    if not name:
        return "file"
    return name[:200]


@dataclass
class EvidenceRecord:
    evidence_id: str
    storage_path: str
    sha256: str
    size_bytes: int
    mime_type: str
    source: str
    notes: str
    filename_original: str


class EvidenceManager:
    def __init__(self, case_root: Path):
        self.case_root = case_root
        self.evidence_dir = case_root / "evidence"
        ensure_dir(self.evidence_dir)

    def add_file(self, src: Path, source: str = "manual", notes: str = "", evidence_id: Optional[str] = None) -> EvidenceRecord:
        if not src.exists() or not src.is_file():
            raise FileNotFoundError(str(src))
        eid = evidence_id or str(uuid.uuid4())
        orig_name = src.name
        safe_name = _safe_filename(orig_name)
        dest_dir = self.evidence_dir / eid
        ensure_dir(dest_dir)
        dest = dest_dir / safe_name

        # Copy then fsync best-effort
        with open(src, "rb") as fsrc, open(dest, "wb") as fdst:
            shutil.copyfileobj(fsrc, fdst)
            fdst.flush()
            os.fsync(fdst.fileno())

        ensure_file_mode(dest)

        sha = hash_file(dest)
        size = dest.stat().st_size
        mime, _ = mimetypes.guess_type(dest.name)
        mime = mime or "application/octet-stream"
        rel_storage = f"evidence/{eid}/{safe_name}"

        rec = EvidenceRecord(
            evidence_id=eid,
            storage_path=rel_storage,
            sha256=sha,
            size_bytes=size,
            mime_type=mime,
            source=source,
            notes=notes,
            filename_original=orig_name,
        )

        # Update manifest atomically
        manifest_path = self.case_root / "manifest.json"
        manifest = load_manifest(manifest_path)
        evidence_list = manifest.setdefault("evidence", [])
        evidence_list.append(
            {
                "evidence_id": rec.evidence_id,
                "storage_path": rec.storage_path,
                "sha256": rec.sha256,
                "size_bytes": rec.size_bytes,
                "mime_type": rec.mime_type,
                "source": rec.source,
                "notes": rec.notes,
                "filename_original": rec.filename_original,
            }
        )
        write_manifest(manifest_path, manifest)
        return rec
