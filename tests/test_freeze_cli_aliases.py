from __future__ import annotations

import json
from pathlib import Path

from aegisops import cli


def test_freeze_verify_aliases_and_verify_case(tmp_path: Path, capsys):
    vault = tmp_path / "vault"
    sample = tmp_path / "sample.txt"
    sample.write_text("hello\n", encoding="utf-8")

    rc = cli.main(["--vault-root", str(vault), "case", "create", "--name", "demo", "--enterprise"])
    assert rc == 0
    case_id = capsys.readouterr().out.strip()
    assert case_id

    rc = cli.main(["--vault-root", str(vault), "evidence", "add", case_id, str(sample), "--source", "manual"])
    assert rc == 0
    capsys.readouterr()

    rc = cli.main(["--vault-root", str(vault), "report", "generate", case_id, "--format", "md"])
    assert rc == 0
    capsys.readouterr()

    rc = cli.main(["--vault-root", str(vault), "freeze", case_id, "--report-format", "md"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    meta_path = Path(json.loads(out)["meta"]).resolve()
    assert meta_path.exists()

    # New: `freeze verify`
    rc = cli.main(["freeze", "verify", "--bundle-meta", str(meta_path)])
    assert rc == 0
    verify_out = json.loads(capsys.readouterr().out)
    assert verify_out["ok"] is True

    # New: `freeze verify-case <case_id>` (find latest bundle)
    rc = cli.main(["--vault-root", str(vault), "freeze", "verify-case", case_id])
    assert rc == 0
    verify_case_out = json.loads(capsys.readouterr().out)
    assert verify_case_out["ok"] is True
