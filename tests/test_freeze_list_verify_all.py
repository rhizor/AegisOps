from __future__ import annotations

import json
from pathlib import Path

from aegisops import cli


def test_freeze_list_and_verify_all(tmp_path: Path, capsys):
    vault = tmp_path / "vault"
    sample = tmp_path / "sample.txt"
    sample.write_text("hello\n", encoding="utf-8")

    # create case, evidence, report, freeze twice
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

    # second freeze
    rc = cli.main(["--vault-root", str(vault), "freeze", case_id, "--report-format", "md"])
    assert rc == 0
    capsys.readouterr()

    # list
    rc = cli.main(["--vault-root", str(vault), "freeze", "list", case_id])
    assert rc == 0
    items = json.loads(capsys.readouterr().out)
    assert isinstance(items, list)
    assert len(items) >= 2
    assert "meta_path" in items[0]

    # list --verify
    rc = cli.main(["--vault-root", str(vault), "freeze", "list", case_id, "--verify"])
    assert rc == 0
    items_v = json.loads(capsys.readouterr().out)
    assert items_v[0]["verify_ok"] is True

    # verify-all
    rc = cli.main(["--vault-root", str(vault), "freeze", "verify-all", case_id])
    out = json.loads(capsys.readouterr().out)
    assert out["total"] >= 2
    assert out["failed"] == 0
    assert rc == 0
