from __future__ import annotations

import json
import time
import zipfile
from pathlib import Path

from aegisops.core.cases import CaseManager
from aegisops.core.evidence import EvidenceManager
from aegisops.plugins.report.report_manager import generate_report
from aegisops.security.signing import keygen
from aegisops.core.freeze import freeze_case
from aegisops.core.retention import apply_retention


def test_freeze_full_and_retention(tmp_path: Path):
    vault = tmp_path / "vault"
    cm = CaseManager(vault)
    ctx = cm.create_case("demo", enterprise=True)

    # add evidence
    sample = tmp_path / "sample.txt"
    sample.write_text("hello secret AKIA1234567890ABCDEF\ncontact: a@b.com\n", encoding="utf-8")
    em = EvidenceManager(ctx.case_root)
    rec = em.add_file(sample, source="manual", notes="n")

    # generate report
    report_path, _ = generate_report(ctx.case_root, fmt="md")
    assert report_path.exists()

    # keygen
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    keygen(priv, pub)

    # freeze full signed
    res = freeze_case(ctx.case_root, report_format="md", full=True, max_evidence_size_mb=1, sign_key=priv, public_key_path=pub)
    assert res.bundle_zip.exists()
    assert res.meta_path.exists()
    assert res.sig_path and res.sig_path.exists()

    # check zip contains evidence
    with zipfile.ZipFile(res.bundle_zip, "r") as z:
        names = set(z.namelist())
        assert "manifest.json" in names
        assert "report.md" in names
        ev_prefix = f"evidence/{rec.evidence_id}/"
        assert any(n.startswith(ev_prefix) for n in names)
        assert "hashes.json" in names
        assert "bundle_meta.json" in names

    # close case to allow retention
    cm.close_case(ctx.case_id)

    # make bundle look old
    meta_obj = json.loads(res.meta_path.read_text(encoding="utf-8"))
    meta_obj["created_at"] = int(time.time()) - 40 * 86400
    res.meta_path.write_text(json.dumps(meta_obj), encoding="utf-8")

    # retention should skip signed bundle unless forced
    out = apply_retention(vault, days=30, force_signed=False)
    assert res.bundle_zip.exists()
    assert any("Signed bundle skipped" in s for s in out.skipped)

    out2 = apply_retention(vault, days=30, force_signed=True)
    assert not res.bundle_zip.exists()
