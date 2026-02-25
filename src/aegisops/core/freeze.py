from __future__ import annotations

import hashlib
import json
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from aegisops.core.vault_fs import acquire_case_lock, atomic_write_bytes, dump_canonical_json, ensure_dir, safe_case_path
from aegisops.security.integrity import validate_case
from aegisops.security.signing import sign_message, public_key_fingerprint


@dataclass
class FreezeResult:
    bundle_zip: Path
    meta_path: Path
    sig_path: Optional[Path]
    bundle_hash: str


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def freeze_case(
    case_root: Path,
    report_format: str = "md",
    full: bool = False,
    max_evidence_size_mb: int = 100,
    sign_key: Optional[Path] = None,
    public_key_path: Optional[Path] = None,
) -> FreezeResult:
    """Create an auditable snapshot zip. If full=True, include evidence files (size-limited)."""

    with acquire_case_lock(case_root):
        rep = validate_case(case_root)
        case_meta = json.loads((case_root / "case.json").read_text(encoding="utf-8"))
        if case_meta.get("enterprise") and not rep.ok:
            raise RuntimeError("Cannot freeze: integrity failed (enterprise mode)")

        ensure_dir(case_root / "freeze")
        bundle_id = str(uuid.uuid4())
        zip_path = case_root / "freeze" / f"bundle-{bundle_id}.zip"
        meta_path = case_root / "freeze" / f"bundle-{bundle_id}.zip.meta.json"
        sig_path = case_root / "freeze" / f"bundle-{bundle_id}.zip.sig.json" if sign_key else None

        # Gather files
        manifest_path = case_root / "manifest.json"
        report_path = case_root / "reports" / f"report.{report_format}"
        if not report_path.exists():
            raise FileNotFoundError(f"Report not found: {report_path}")

        ai_out_path = case_root / "ai" / "output.json"

        hashes: Dict[str, str] = {}

        # Build zip in memory for atomic write
        from io import BytesIO

        buf = BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.write(manifest_path, arcname="manifest.json")
            hashes["manifest.json"] = _hash_file(manifest_path)

            z.write(report_path, arcname=f"report.{report_format}")
            hashes[f"report.{report_format}"] = _hash_file(report_path)

            if ai_out_path.exists():
                z.write(ai_out_path, arcname="ai/output.json")
                hashes["ai/output.json"] = _hash_file(ai_out_path)

            if full:
                # include evidence files listed in manifest
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                evidence = manifest.get("evidence", [])
                if not isinstance(evidence, list):
                    raise RuntimeError("Manifest evidence invalid")
                max_bytes = int(max_evidence_size_mb) * 1024 * 1024
                for e in evidence:
                    rel = str(e.get("storage_path", ""))
                    if not rel:
                        continue
                    fpath = safe_case_path(case_root, rel)
                    if not fpath.exists():
                        raise RuntimeError(f"Evidence missing for freeze: {rel}")
                    sz = fpath.stat().st_size
                    if sz > max_bytes:
                        raise RuntimeError(f"Evidence exceeds max size ({max_evidence_size_mb}MB): {rel}")
                    arcname = f"evidence/{e.get('evidence_id','unknown')}/{fpath.name}"
                    z.write(fpath, arcname=arcname)
                    hashes[arcname] = _hash_file(fpath)

            bundle_meta = {
                "bundle_id": bundle_id,
                "created_at": int(time.time()),
                "case_id": case_meta.get("case_id"),
                "integrity_ok": rep.ok,
                "aggregate_hash": rep.aggregate_hash,
                "report_format": report_format,
                "full": bool(full),
                "max_evidence_size_mb": int(max_evidence_size_mb),
            }
            z.writestr("hashes.json", dump_canonical_json({"files": hashes}))
            z.writestr("bundle_meta.json", dump_canonical_json(bundle_meta))

        zip_bytes = buf.getvalue()
        atomic_write_bytes(zip_path, zip_bytes)
        bundle_hash = _hash_bytes(zip_bytes)

        meta_obj = {
            "bundle_id": bundle_id,
            "bundle_path": str(zip_path),
            "bundle_hash": bundle_hash,
            "created_at": int(time.time()),
            "case_id": case_meta.get("case_id"),
            "full": bool(full),
        }
        atomic_write_bytes(meta_path, dump_canonical_json(meta_obj).encode("utf-8"))

        if sign_key:
            pub_pem = public_key_path.read_bytes() if public_key_path and public_key_path.exists() else b""
            sig_obj = {
                "bundle_id": bundle_id,
                "bundle_hash": bundle_hash,
                "signature": sign_message(sign_key, bundle_hash.encode("utf-8")),
                "public_key_fingerprint": public_key_fingerprint(pub_pem) if pub_pem else "",
            }
            atomic_write_bytes(sig_path, dump_canonical_json(sig_obj).encode("utf-8"))

        return FreezeResult(zip_path, meta_path, sig_path, bundle_hash)


@dataclass
class VerifyResult:
    ok: bool
    bundle_hash_ok: bool
    internal_hashes_ok: bool
    signature_ok: Optional[bool]
    failures: list[str]


def verify_bundle(bundle_meta_path: Path, public_key: Optional[Path] = None, signature_path: Optional[Path] = None) -> VerifyResult:
    """Verify a frozen bundle.

    Checks:
      1) The zip's SHA-256 matches bundle_hash in the meta file.
      2) The hashes.json inside the zip matches the content of the archived files.
      3) If signature_path+public_key provided (or signature_path exists next to meta), verify Ed25519 signature over bundle_hash.
    """

    failures: list[str] = []
    meta = json.loads(bundle_meta_path.read_text(encoding="utf-8"))
    bundle_path = Path(str(meta.get("bundle_path", "")))
    expected_hash = str(meta.get("bundle_hash", ""))
    if not bundle_path.exists():
        return VerifyResult(False, False, False, None, [f"Bundle not found: {bundle_path}"])

    actual_hash = _hash_file(bundle_path)
    bundle_hash_ok = (expected_hash == actual_hash)
    if not bundle_hash_ok:
        failures.append("BUNDLE_HASH_MISMATCH")

    internal_ok = True
    try:
        with zipfile.ZipFile(bundle_path, "r") as z:
            try:
                hashes_obj = json.loads(z.read("hashes.json").decode("utf-8"))
            except KeyError:
                failures.append("HASHES_JSON_MISSING")
                internal_ok = False
                hashes_obj = {"files": {}}

            files = hashes_obj.get("files", {})
            if not isinstance(files, dict):
                failures.append("HASHES_JSON_INVALID")
                internal_ok = False
                files = {}

            for arcname, expected in files.items():
                if arcname == "hashes.json":
                    continue
                try:
                    data = z.read(arcname)
                except KeyError:
                    failures.append(f"MISSING_ENTRY:{arcname}")
                    internal_ok = False
                    continue
                got = _hash_bytes(data)
                if got != expected:
                    failures.append(f"INTERNAL_HASH_MISMATCH:{arcname}")
                    internal_ok = False
    except zipfile.BadZipFile:
        failures.append("BAD_ZIP")
        internal_ok = False

    # Signature (optional)
    sig_ok: Optional[bool] = None
    if signature_path is None:
        candidate = bundle_meta_path.with_suffix(".zip.sig.json")
        if candidate.exists():
            signature_path = candidate

    if signature_path is not None:
        if public_key is None:
            failures.append("SIGNATURE_PRESENT_BUT_NO_PUBLIC_KEY")
            sig_ok = False
        else:
            from aegisops.security.signing import verify_message

            sig = json.loads(signature_path.read_text(encoding="utf-8"))
            sig_ok = verify_message(public_key, expected_hash.encode("utf-8"), str(sig.get("signature", "")))
            if not sig_ok:
                failures.append("SIGNATURE_INVALID")

    ok = bundle_hash_ok and internal_ok and (sig_ok is None or sig_ok)
    return VerifyResult(ok, bundle_hash_ok, internal_ok, sig_ok, failures)


def find_latest_bundle_meta(case_root: Path) -> Optional[Path]:
    """Find the most recent bundle meta file for a case.

    Preference order:
      1) Highest created_at inside the meta JSON (if parseable)
      2) Newest mtime
    """

    freeze_dir = case_root / "freeze"
    if not freeze_dir.exists():
        return None
    metas = sorted(freeze_dir.glob("bundle-*.zip.meta.json"))
    if not metas:
        return None

    best: Optional[Path] = None
    best_created: int = -1
    best_mtime: float = -1.0

    for p in metas:
        created = -1
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
            created = int(obj.get("created_at", -1))
        except Exception:
            created = -1
        try:
            mtime = p.stat().st_mtime
        except OSError:
            mtime = -1.0

        if created > best_created or (created == best_created and mtime > best_mtime):
            best = p
            best_created = created
            best_mtime = mtime

    if best is None:
        metas.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        return metas[0]
    return best


def verify_latest_bundle_for_case(
    case_root: Path,
    public_key: Optional[Path] = None,
    signature_path: Optional[Path] = None,
) -> VerifyResult:
    """Verify the latest frozen bundle for a case (if any)."""

    meta = find_latest_bundle_meta(case_root)
    if meta is None:
        return VerifyResult(False, False, False, None, ["NO_BUNDLES_FOUND"])
    return verify_bundle(meta, public_key=public_key, signature_path=signature_path)
def list_bundles_for_case(case_root: Path) -> list[dict]:
    """List available freeze bundle meta files for a case.

    Returns a list of dicts (newest first). Each entry contains parsed meta fields plus
    a `meta_path` and `sig_present` boolean.
    """
    freeze_dir = case_root / "freeze"
    if not freeze_dir.exists():
        return []
    metas = list(freeze_dir.glob("bundle-*.zip.meta.json"))
    items: list[dict] = []
    for p in metas:
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            obj = {}
        created_at = int(obj.get("created_at", 0) or 0)
        bundle_path = str(obj.get("bundle_path", ""))
        bundle_hash = str(obj.get("bundle_hash", ""))
        full = bool(obj.get("full", False))
        sig_path = p.with_suffix(".zip.sig.json")
        items.append({
            "bundle_id": str(obj.get("bundle_id", "")),
            "created_at": created_at,
            "bundle_path": bundle_path,
            "bundle_hash": bundle_hash,
            "full": full,
            "meta_path": str(p),
            "sig_present": sig_path.exists(),
            "sig_path": str(sig_path) if sig_path.exists() else None,
        })
    # sort newest first by created_at then mtime
    def _key(it):
        try:
            mtime = Path(it["meta_path"]).stat().st_mtime
        except OSError:
            mtime = 0.0
        return (it.get("created_at", 0), mtime)
    items.sort(key=_key, reverse=True)
    return items


def verify_all_bundles_for_case(
    case_root: Path,
    public_key: Optional[Path] = None,
    fail_fast: bool = False,
) -> dict:
    """Verify all bundles for a case and return a summary dict."""
    bundles = list_bundles_for_case(case_root)
    results: list[dict] = []
    ok_count = 0
    for b in bundles:
        meta_path = Path(b["meta_path"])
        res = verify_bundle(meta_path, public_key=public_key, signature_path=None)
        r = {
            "meta_path": b["meta_path"],
            "bundle_path": b["bundle_path"],
            "bundle_id": b.get("bundle_id", ""),
            "created_at": b.get("created_at", 0),
            "ok": res.ok,
            "bundle_hash_ok": res.bundle_hash_ok,
            "internal_hashes_ok": res.internal_hashes_ok,
            "signature_ok": res.signature_ok,
            "failures": res.failures,
        }
        results.append(r)
        if res.ok:
            ok_count += 1
        elif fail_fast:
            break
    return {
        "case_root": str(case_root),
        "total": len(bundles),
        "verified": len(results),
        "ok": ok_count,
        "failed": len(results) - ok_count,
        "results": results,
    }


def status_for_case(case_root: Path, public_key: Optional[Path] = None) -> dict:
    """Return a small, script-friendly status summary for the latest freeze bundle of a case.

    Output is intended for dashboards/automation.
    """
    meta_path = find_latest_bundle_meta(case_root)
    if meta_path is None:
        return {
            "ok": False,
            "status": "NO_BUNDLES_FOUND",
            "case_root": str(case_root),
        }
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        meta = {}
    sig_path = meta_path.with_suffix(".zip.sig.json")
    sig_present = sig_path.exists()
    res = verify_bundle(meta_path, public_key=public_key, signature_path=(sig_path if sig_present else None))
    return {
        "ok": res.ok,
        "status": "OK" if res.ok else "FAIL",
        "case_root": str(case_root),
        "bundle_id": str(meta.get("bundle_id", "")),
        "created_at": int(meta.get("created_at", 0) or 0),
        "full": bool(meta.get("full", False)),
        "signed": bool(sig_present),
        "meta_path": str(meta_path),
        "bundle_path": str(meta.get("bundle_path", "")),
        "bundle_hash_ok": res.bundle_hash_ok,
        "internal_hashes_ok": res.internal_hashes_ok,
        "signature_ok": res.signature_ok,
        "failures": res.failures,
    }


def status_all_cases(vault_root: Path, public_key: Optional[Path] = None) -> dict:
    """Return status of latest freeze bundle for all cases under vault_root/cases.

    Intended for monitoring / dashboards.

    Returns:
      {
        "vault_root": "...",
        "total_cases": N,
        "ok": n_ok,
        "fail": n_fail,
        "no_bundles": n_no_bundles,
        "results": [ {case_id,name,status,...}, ... ]
      }
    """
    cases_dir = (vault_root / "cases")
    if not cases_dir.exists():
        return {
            "vault_root": str(vault_root),
            "total_cases": 0,
            "ok": 0,
            "fail": 0,
            "no_bundles": 0,
            "results": [],
        }

    results: list[dict] = []
    ok = fail = no_bundles = 0
    for case_root in sorted([p for p in cases_dir.iterdir() if p.is_dir()], key=lambda p: p.name):
        meta_path = case_root / "case.json"
        try:
            case_meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
        except Exception:
            case_meta = {}
        st = status_for_case(case_root, public_key=public_key)
        # Enrich
        st["case_id"] = str(case_meta.get("case_id") or case_root.name)
        st["case_name"] = str(case_meta.get("name") or "")
        st["case_status"] = str(case_meta.get("status") or "")
        st["enterprise"] = bool(case_meta.get("enterprise", False))
        results.append(st)

        if st.get("status") == "OK":
            ok += 1
        elif st.get("status") == "NO_BUNDLES_FOUND":
            no_bundles += 1
        else:
            fail += 1

    return {
        "vault_root": str(vault_root),
        "total_cases": len(results),
        "ok": ok,
        "fail": fail,
        "no_bundles": no_bundles,
        "results": results,
    }
