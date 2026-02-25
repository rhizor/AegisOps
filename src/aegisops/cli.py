from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegisops.core.vault_fs import set_secure_umask
from aegisops.core.cases import CaseManager, IntegrityFailure
from aegisops.core.evidence import EvidenceManager
from aegisops.plugins.report.report_manager import generate_report
from aegisops.core.freeze import freeze_case
from aegisops.core.freeze import verify_bundle, verify_latest_bundle_for_case, list_bundles_for_case, verify_all_bundles_for_case, status_for_case, status_all_cases
from aegisops.security.signing import keygen, verify_message
from aegisops.core.retention import apply_retention


def _vault_root(args) -> Path:
    return Path(getattr(args, "vault_root", "./vault")).resolve()


def cmd_case_create(args) -> int:
    vr = _vault_root(args)
    cm = CaseManager(vr)
    ctx = cm.create_case(args.name, enterprise=args.enterprise)
    print(ctx.case_id)
    return 0


def cmd_case_list(args) -> int:
    vr = _vault_root(args)
    cases_dir = vr / "cases"
    if not cases_dir.exists():
        return 0
    for d in sorted([p for p in cases_dir.iterdir() if p.is_dir()], key=lambda p: p.name):
        meta = d / "case.json"
        if not meta.exists():
            continue
        try:
            obj = json.loads(meta.read_text(encoding="utf-8"))
        except Exception:
            continue
        print(f"{obj.get('case_id')}\t{obj.get('status')}\t{'enterprise' if obj.get('enterprise') else 'standard'}\t{obj.get('name','')}")
    return 0


def cmd_case_open(args) -> int:
    vr = _vault_root(args)
    cm = CaseManager(vr)
    try:
        cm.open_case(args.case_id)
        print("OK")
        return 0
    except IntegrityFailure as e:
        print(str(e), file=sys.stderr)
        return 3


def cmd_case_close(args) -> int:
    vr = _vault_root(args)
    cm = CaseManager(vr)
    try:
        cm.close_case(args.case_id)
        print("OK")
        return 0
    except IntegrityFailure as e:
        print(str(e), file=sys.stderr)
        return 3


def cmd_evidence_add(args) -> int:
    vr = _vault_root(args)
    cm = CaseManager(vr)
    ctx = cm.open_case(args.case_id)
    em = EvidenceManager(ctx.case_root)
    rec = em.add_file(Path(args.path), source=args.source, notes=args.notes)
    print(json.dumps({"evidence_id": rec.evidence_id, "sha256": rec.sha256, "storage_path": rec.storage_path}, sort_keys=True))
    return 0


def cmd_evidence_list(args) -> int:
    vr = _vault_root(args)
    case_root = (vr / "cases" / args.case_id)
    manifest_path = case_root / "manifest.json"
    if not manifest_path.exists():
        print("[]")
        return 0
    obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    ev = obj.get("evidence", [])
    print(json.dumps(ev, sort_keys=True))
    return 0


def cmd_report_generate(args) -> int:
    vr = _vault_root(args)
    cm = CaseManager(vr)
    ctx = cm.open_case(args.case_id)
    out = Path(args.output).resolve() if args.output else None
    path, out_hash = generate_report(ctx.case_root, fmt=args.format, output_path=out)
    print(json.dumps({"path": str(path), "sha256": out_hash}, sort_keys=True))
    return 0


def cmd_freeze(args) -> int:
    """Dispatch freeze actions.

    Backwards compatible:
      aegisops freeze <case_id> [--full ...]   -> create freeze bundle
    New:
      aegisops freeze verify --bundle-meta ...
      aegisops freeze verify-case <case_id>
      aegisops freeze list <case_id> [--verify]
      aegisops freeze verify-all <case_id> [--fail-fast]
      aegisops freeze status <case_id>
    """

    action = str(args.action)

    if action == "verify":
        if not args.bundle_meta:
            print("--bundle-meta is required for 'freeze verify'", file=sys.stderr)
            return 2
        meta_path = Path(args.bundle_meta).resolve()
        pub = Path(args.public_key).resolve() if args.public_key else None
        sig = Path(args.signature).resolve() if args.signature else None
        res = verify_bundle(meta_path, public_key=pub, signature_path=sig)
        print(json.dumps({
            "ok": res.ok,
            "bundle_hash_ok": res.bundle_hash_ok,
            "internal_hashes_ok": res.internal_hashes_ok,
            "signature_ok": res.signature_ok,
            "failures": res.failures,
        }, sort_keys=True))
        return 0 if res.ok else 2

    if action == "verify-case":
        vr = _vault_root(args)
        if not args.case_id:
            print("case_id is required for 'freeze verify-case'", file=sys.stderr)
            return 2
        case_root = (vr / "cases" / args.case_id).resolve()
        pub = Path(args.public_key).resolve() if args.public_key else None
        sig = Path(args.signature).resolve() if args.signature else None
        res = verify_latest_bundle_for_case(case_root, public_key=pub, signature_path=sig)
        print(json.dumps({
            "ok": res.ok,
            "bundle_hash_ok": res.bundle_hash_ok,
            "internal_hashes_ok": res.internal_hashes_ok,
            "signature_ok": res.signature_ok,
            "failures": res.failures,
        }, sort_keys=True))
        return 0 if res.ok else 2

    if action == "list":
        vr = _vault_root(args)
        if not args.case_id:
            print("case_id is required for 'freeze list'", file=sys.stderr)
            return 2
        case_root = (vr / "cases" / args.case_id).resolve()
        items = list_bundles_for_case(case_root)

        if getattr(args, "verify", False):
            pub = Path(args.public_key).resolve() if args.public_key else None
            verified = []
            for it in items:
                res = verify_bundle(Path(it["meta_path"]), public_key=pub, signature_path=None)
                it2 = dict(it)
                it2.update({
                    "verify_ok": res.ok,
                    "bundle_hash_ok": res.bundle_hash_ok,
                    "internal_hashes_ok": res.internal_hashes_ok,
                    "signature_ok": res.signature_ok,
                    "failures": res.failures,
                })
                verified.append(it2)
            items = verified

        print(json.dumps(items, sort_keys=True))
        return 0

    if action == "verify-all":
        vr = _vault_root(args)
        if not args.case_id:
            print("case_id is required for 'freeze verify-all'", file=sys.stderr)
            return 2
        case_root = (vr / "cases" / args.case_id).resolve()
        pub = Path(args.public_key).resolve() if args.public_key else None
        summary = verify_all_bundles_for_case(case_root, public_key=pub, fail_fast=getattr(args, "fail_fast", False))
        print(json.dumps(summary, sort_keys=True))
        return 0 if summary["failed"] == 0 and summary["verified"] == summary["total"] else 2


    if action == "status":
        vr = _vault_root(args)
        if not args.case_id:
            print("case_id is required for 'freeze status'", file=sys.stderr)
            return 2
        case_root = (vr / "cases" / args.case_id).resolve()
        pub = Path(args.public_key).resolve() if args.public_key else None
        st = status_for_case(case_root, public_key=pub)
        print(json.dumps(st, sort_keys=True))
        return 0 if st.get("ok") else 2


    if action == "status-all":
        vr = _vault_root(args)
        pub = Path(args.public_key).resolve() if args.public_key else None
        st = status_all_cases(vr, public_key=pub)
        print(json.dumps(st, sort_keys=True))
        # exit nonzero if any FAIL (but ignore NO_BUNDLES)
        any_fail = any(r.get("status") == "FAIL" for r in st.get("results", []))
        return 2 if any_fail else 0

    # Default: action is the case_id (backcompat)
    vr = _vault_root(args)
    cm = CaseManager(vr)
    ctx = cm.open_case(action)
    sign_key = Path(args.sign_key).resolve() if args.sign_key else None
    pub_key = Path(args.public_key).resolve() if args.public_key else None
    res = freeze_case(
        ctx.case_root,
        report_format=args.report_format,
        full=args.full,
        max_evidence_size_mb=args.max_evidence_size_mb,
        sign_key=sign_key,
        public_key_path=pub_key,
    )
    print(json.dumps({
        "bundle": str(res.bundle_zip),
        "bundle_hash": res.bundle_hash,
        "meta": str(res.meta_path),
        "sig": str(res.sig_path) if res.sig_path else None
    }, sort_keys=True))
    return 0


def cmd_freeze_verify(args) -> int:
    meta_path = Path(args.bundle_meta).resolve()
    pub = Path(args.public_key).resolve() if args.public_key else None
    sig = Path(args.signature).resolve() if args.signature else None
    res = verify_bundle(meta_path, public_key=pub, signature_path=sig)
    print(json.dumps({
        "ok": res.ok,
        "bundle_hash_ok": res.bundle_hash_ok,
        "internal_hashes_ok": res.internal_hashes_ok,
        "signature_ok": res.signature_ok,
        "failures": res.failures,
    }, sort_keys=True))
    return 0 if res.ok else 2


def cmd_sign_keygen(args) -> int:
    keygen(Path(args.private_key).resolve(), Path(args.public_key).resolve())
    print("OK")
    return 0


def cmd_sign_verify(args) -> int:
    meta = json.loads(Path(args.bundle_meta).read_text(encoding="utf-8"))
    sig = json.loads(Path(args.signature).read_text(encoding="utf-8"))
    bundle_hash = str(meta.get("bundle_hash", ""))
    ok = verify_message(Path(args.public_key).resolve(), bundle_hash.encode("utf-8"), str(sig.get("signature", "")))
    print("OK" if ok else "FAIL")
    return 0 if ok else 2


def cmd_retention_apply(args) -> int:
    vr = _vault_root(args)
    res = apply_retention(vr, days=args.days, force_signed=args.force_signed)
    print(json.dumps({"deleted": [str(p) for p in res.deleted], "skipped": res.skipped}, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegisops")
    p.add_argument("--vault-root", default="./vault")

    sp = p.add_subparsers(dest="cmd", required=True)

    case = sp.add_parser("case")
    csp = case.add_subparsers(dest="case_cmd", required=True)
    c = csp.add_parser("create")
    c.add_argument("--name", required=True)
    c.add_argument("--enterprise", action="store_true")
    c.set_defaults(func=cmd_case_create)

    l = csp.add_parser("list")
    l.set_defaults(func=cmd_case_list)

    o = csp.add_parser("open")
    o.add_argument("case_id")
    o.set_defaults(func=cmd_case_open)

    cl = csp.add_parser("close")
    cl.add_argument("case_id")
    cl.set_defaults(func=cmd_case_close)

    ev = sp.add_parser("evidence")
    esp = ev.add_subparsers(dest="ev_cmd", required=True)
    ea = esp.add_parser("add")
    ea.add_argument("case_id")
    ea.add_argument("path")
    ea.add_argument("--source", default="manual")
    ea.add_argument("--notes", default="")
    ea.set_defaults(func=cmd_evidence_add)

    el = esp.add_parser("list")
    el.add_argument("case_id")
    el.set_defaults(func=cmd_evidence_list)

    rp = sp.add_parser("report")
    rsp = rp.add_subparsers(dest="report_cmd", required=True)
    rg = rsp.add_parser("generate")
    rg.add_argument("case_id")
    rg.add_argument("--format", choices=["md", "html", "pdf"], required=True)
    rg.add_argument("--output")
    rg.set_defaults(func=cmd_report_generate)

    fr = sp.add_parser("freeze")
    fr.add_argument("action", help="case_id (create), or 'verify'/'verify-case'/'list'/'verify-all'/'status'/'status-all'")
    fr.add_argument("case_id", nargs="?", help="case_id for verify-case")
    fr.add_argument("--report-format", choices=["md", "html", "pdf"], default="md")
    fr.add_argument("--full", action="store_true")
    fr.add_argument("--max-evidence-size-mb", type=int, default=100)
    fr.add_argument("--sign-key")
    fr.add_argument("--public-key")
    fr.add_argument("--bundle-meta")
    fr.add_argument("--signature")
    fr.add_argument("--verify", action="store_true", help="For 'freeze list': verify each bundle")
    fr.add_argument("--fail-fast", action="store_true", help="For 'freeze verify-all': stop at first failure")
    fr.set_defaults(func=cmd_freeze)

    fv = sp.add_parser("freeze-verify")
    fv.add_argument("--bundle-meta", required=True)
    fv.add_argument("--public-key")
    fv.add_argument("--signature")
    fv.set_defaults(func=cmd_freeze_verify)

    sg = sp.add_parser("sign")
    ssp = sg.add_subparsers(dest="sign_cmd", required=True)
    kg = ssp.add_parser("keygen")
    kg.add_argument("--private-key", required=True)
    kg.add_argument("--public-key", required=True)
    kg.set_defaults(func=cmd_sign_keygen)

    sv = ssp.add_parser("verify")
    sv.add_argument("--public-key", required=True)
    sv.add_argument("--bundle-meta", required=True)
    sv.add_argument("--signature", required=True)
    sv.set_defaults(func=cmd_sign_verify)

    rt = sp.add_parser("retention")
    rtp = rt.add_subparsers(dest="ret_cmd", required=True)
    ra = rtp.add_parser("apply")
    ra.add_argument("--days", type=int, required=True)
    ra.add_argument("--force-signed", action="store_true")
    ra.set_defaults(func=cmd_retention_apply)

    return p


def main(argv: list[str] | None = None) -> int:
    set_secure_umask()
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
