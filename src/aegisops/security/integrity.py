from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegisops.core.vault_fs import dump_canonical_json, safe_case_path, atomic_write_text


@dataclass
class IntegrityIssue:
    code: str
    message: str


@dataclass
class IntegrityReport:
    ok: bool
    aggregate_hash: str
    issues: List[IntegrityIssue]


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical_manifest(manifest: Dict[str, Any]) -> str:
    # Deterministic ordering of evidence list
    ev = manifest.get("evidence", [])
    if isinstance(ev, list):
        ev_sorted = sorted(ev, key=lambda x: str(x.get("evidence_id", "")))
        manifest = dict(manifest)
        manifest["evidence"] = ev_sorted
    return dump_canonical_json(manifest)


def compute_aggregate_hash(manifest: Dict[str, Any]) -> str:
    # fixed-point: set aggregate.hash empty before hashing
    m = json.loads(json.dumps(manifest))
    agg = m.setdefault("aggregate", {})
    agg["hash"] = ""
    canon = _canonical_manifest(m).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def write_manifest(path: Path, manifest: Dict[str, Any]) -> None:
    # Fill aggregate hash
    manifest = dict(manifest)
    manifest.setdefault("aggregate", {})
    manifest["aggregate"]["hash"] = compute_aggregate_hash(manifest)
    atomic_write_text(path, _canonical_manifest(manifest))


def load_manifest(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_case(case_root: Path, manifest_rel: str = "manifest.json") -> IntegrityReport:
    issues: List[IntegrityIssue] = []
    try:
        manifest_path = safe_case_path(case_root, manifest_rel)
    except Exception as e:
        return IntegrityReport(False, "", [IntegrityIssue("MANIFEST_INVALID", str(e))])

    if not manifest_path.exists():
        return IntegrityReport(False, "", [IntegrityIssue("MANIFEST_MISSING", "manifest.json not found")])

    try:
        manifest = load_manifest(manifest_path)
    except Exception as e:
        return IntegrityReport(False, "", [IntegrityIssue("MANIFEST_INVALID", f"Failed to parse manifest: {e}")])

    evidence = manifest.get("evidence", [])
    if not isinstance(evidence, list):
        issues.append(IntegrityIssue("MANIFEST_INVALID", "evidence must be a list"))
        return IntegrityReport(False, "", issues)

    for item in evidence:
        try:
            rel_path = item["storage_path"]
            sha_expected = item["sha256"]
        except Exception:
            issues.append(IntegrityIssue("MANIFEST_INVALID", "evidence entry missing required fields"))
            continue

        try:
            fpath = safe_case_path(case_root, rel_path)
        except Exception as e:
            issues.append(IntegrityIssue("MANIFEST_INVALID", f"Bad storage_path: {e}"))
            continue

        if not fpath.exists():
            issues.append(IntegrityIssue("MISSING_FILE", f"Missing evidence file: {rel_path}"))
            continue

        sha_actual = hash_file(fpath)
        if sha_actual != sha_expected:
            issues.append(IntegrityIssue("HASH_MISMATCH", f"Hash mismatch for {rel_path}"))

        size_expected = item.get("size_bytes")
        if isinstance(size_expected, int):
            try:
                if fpath.stat().st_size != size_expected:
                    issues.append(IntegrityIssue("SIZE_MISMATCH", f"Size mismatch for {rel_path}"))
            except OSError:
                pass

    agg_expected = str(manifest.get("aggregate", {}).get("hash", ""))
    agg_actual = compute_aggregate_hash(manifest)
    if agg_expected and agg_expected != agg_actual:
        issues.append(IntegrityIssue("AGGREGATE_MISMATCH", "Aggregate hash mismatch"))

    ok = len(issues) == 0
    return IntegrityReport(ok, agg_actual, issues)
