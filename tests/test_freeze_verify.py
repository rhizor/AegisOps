from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

from aegisops.core.cases import CaseManager
from aegisops.core.evidence import EvidenceManager
from aegisops.plugins.report.report_manager import generate_report
from aegisops.security.signing import keygen
from aegisops.core.freeze import freeze_case, verify_bundle


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_freeze_verify_detects_tampering(tmp_path: Path):
    vault = tmp_path / "vault"
    cm = CaseManager(vault)
    ctx = cm.create_case("demo", enterprise=True)

    sample = tmp_path / "sample.txt"
    sample.write_text("hello\n", encoding="utf-8")
    EvidenceManager(ctx.case_root).add_file(sample)

    generate_report(ctx.case_root, fmt="md")

    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    keygen(priv, pub)

    res = freeze_case(ctx.case_root, report_format="md", full=True, max_evidence_size_mb=1, sign_key=priv, public_key_path=pub)

    ok = verify_bundle(res.meta_path, public_key=pub, signature_path=res.sig_path)
    assert ok.ok

    # 1) Tamper zip bytes -> bundle hash mismatch
    zbytes = res.bundle_zip.read_bytes()
    tampered = bytearray(zbytes)
    tampered[len(tampered) // 2] ^= 0x01
    res.bundle_zip.write_bytes(bytes(tampered))

    bad = verify_bundle(res.meta_path, public_key=pub, signature_path=res.sig_path)
    assert not bad.ok
    assert not bad.bundle_hash_ok
    assert "BUNDLE_HASH_MISMATCH" in bad.failures


def test_freeze_verify_internal_hash_mismatch(tmp_path: Path):
    vault = tmp_path / "vault"
    cm = CaseManager(vault)
    ctx = cm.create_case("demo", enterprise=False)

    sample = tmp_path / "sample.txt"
    sample.write_text("hello\n", encoding="utf-8")
    EvidenceManager(ctx.case_root).add_file(sample)

    report_path, _ = generate_report(ctx.case_root, fmt="md")
    assert report_path.exists()

    res = freeze_case(ctx.case_root, report_format="md", full=False)

    # Rebuild zip with modified report content but keep hashes.json the same
    original_zip = res.bundle_zip.read_bytes()
    with zipfile.ZipFile(io.BytesIO(original_zip), "r") as zin:
        members = {n: zin.read(n) for n in zin.namelist()}

    # Modify report.md content
    members["report.md"] = members["report.md"] + b"\nTAMPER\n"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for name, data in members.items():
            zout.writestr(name, data)
    new_zip_bytes = buf.getvalue()
    res.bundle_zip.write_bytes(new_zip_bytes)

    # Update meta to match new zip hash so outer hash passes
    meta = json.loads(res.meta_path.read_text(encoding="utf-8"))
    meta["bundle_hash"] = _sha256_bytes(new_zip_bytes)
    res.meta_path.write_text(json.dumps(meta), encoding="utf-8")

    vr = verify_bundle(res.meta_path)
    assert not vr.ok
    assert vr.bundle_hash_ok
    assert not vr.internal_hashes_ok
    assert any(s.startswith("INTERNAL_HASH_MISMATCH:report.md") for s in vr.failures)
