from __future__ import annotations

import json
from pathlib import Path

from aegisops import cli


def test_freeze_status_latest_ok(tmp_path: Path, capsys):
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
    capsys.readouterr()

    rc = cli.main(["--vault-root", str(vault), "freeze", "status", case_id])
    assert rc == 0
    st = json.loads(capsys.readouterr().out)
    assert st["ok"] is True
    assert st["status"] == "OK"
    assert st["bundle_id"]
    assert st["meta_path"].endswith(".zip.meta.json")
