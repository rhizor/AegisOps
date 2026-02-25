from __future__ import annotations

import json
from pathlib import Path

from aegisops import cli


def test_freeze_status_all_counts_and_exit_codes(tmp_path: Path, capsys):
    vault = tmp_path / "vault"
    sample = tmp_path / "sample.txt"
    sample.write_text("hello\n", encoding="utf-8")

    # Case A with a valid bundle
    rc = cli.main(["--vault-root", str(vault), "case", "create", "--name", "a", "--enterprise"])
    assert rc == 0
    case_a = capsys.readouterr().out.strip()
    assert case_a

    rc = cli.main(["--vault-root", str(vault), "evidence", "add", case_a, str(sample), "--source", "manual"])
    assert rc == 0
    capsys.readouterr()

    rc = cli.main(["--vault-root", str(vault), "report", "generate", case_a, "--format", "md"])
    assert rc == 0
    capsys.readouterr()

    rc = cli.main(["--vault-root", str(vault), "freeze", case_a, "--report-format", "md"])
    assert rc == 0
    capsys.readouterr()

    # Case B with no bundles
    rc = cli.main(["--vault-root", str(vault), "case", "create", "--name", "b"])
    assert rc == 0
    case_b = capsys.readouterr().out.strip()
    assert case_b

    # status-all should be OK (NO_BUNDLES is not counted as FAIL)
    rc = cli.main(["--vault-root", str(vault), "freeze", "status-all"])
    assert rc == 0
    st = json.loads(capsys.readouterr().out)
    assert st["total_cases"] == 2
    assert st["ok"] == 1
    assert st["no_bundles"] == 1
    assert st["fail"] == 0

    # Tamper with case A bundle zip to cause FAIL
    freeze_dir = vault / "cases" / case_a / "freeze"
    meta = next(freeze_dir.glob("bundle-*.zip.meta.json"))
    meta_obj = json.loads(meta.read_text(encoding="utf-8"))
    bundle_path = Path(meta_obj["bundle_path"])
    with open(bundle_path, "ab") as f:
        f.write(b"X")  # modifies zip hash -> BUNDLE_HASH_MISMATCH

    rc = cli.main(["--vault-root", str(vault), "freeze", "status-all"])
    assert rc == 2
    st2 = json.loads(capsys.readouterr().out)
    assert st2["fail"] == 1
