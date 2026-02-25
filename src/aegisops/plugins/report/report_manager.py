from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from typing import Literal, Optional

from reportlab.pdfgen import canvas

from aegisops.core.vault_fs import atomic_write_text, atomic_write_bytes, ensure_dir, dump_canonical_json
from aegisops.security.integrity import load_manifest, validate_case


ReportFormat = Literal["md", "html", "pdf"]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_ai_output(case_root: Path) -> Optional[dict]:
    p = case_root / "ai" / "output.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def build_markdown(case_root: Path) -> str:
    rep = validate_case(case_root)
    manifest = load_manifest(case_root / "manifest.json")
    case_meta = json.loads((case_root / "case.json").read_text(encoding="utf-8"))
    ai_out = _read_ai_output(case_root)

    evidence = sorted(manifest.get("evidence", []), key=lambda x: str(x.get("evidence_id", "")))

    lines = []
    lines.append(f"# AegisOps Report\n")
    lines.append("## Case Metadata\n")
    lines.append(f"- Case ID: `{case_meta.get('case_id')}`")
    lines.append(f"- Name: {case_meta.get('name','')}")
    lines.append(f"- Status: {case_meta.get('status','')}")
    lines.append(f"- Enterprise mode: {'Yes' if case_meta.get('enterprise') else 'No'}")
    lines.append(f"- Integrity status: **{'OK' if rep.ok else 'FAIL'}**")
    lines.append(f"- Aggregate hash: `{rep.aggregate_hash}`")
    lines.append(f"- AI Used: **{'Yes' if ai_out else 'No'}**\n")

    lines.append("## Compliance Mapping (High Level)\n")
    lines.append("- NIST CSF: Protect / Detect / Respond / Recover")
    lines.append("- ISO/IEC 27001: Audit logging, asset control, operational integrity\n")

    lines.append("## Executive Summary\n")
    if ai_out and isinstance(ai_out.get("summary"), str):
        lines.append(ai_out["summary"].strip() or "(empty)")
    else:
        lines.append("No AI summary available.")
    lines.append("")

    lines.append("## Evidence Table\n")
    lines.append("| evidence_id | sha256 | mime | size_bytes | storage_path | source | notes |")
    lines.append("|---|---|---:|---:|---|---|---|")
    for e in evidence:
        lines.append(
            "| {evidence_id} | {sha256} | {mime_type} | {size_bytes} | {storage_path} | {source} | {notes} |".format(
                evidence_id=str(e.get("evidence_id", "")),
                sha256=str(e.get("sha256", "")),
                mime_type=str(e.get("mime_type", "")),
                size_bytes=str(e.get("size_bytes", "")),
                storage_path=str(e.get("storage_path", "")),
                source=str(e.get("source", "")),
                notes=str(e.get("notes", "")).replace("\n", " "),
            )
        )
    lines.append("")

    lines.append("## Technical Findings\n")
    findings = []
    if ai_out and isinstance(ai_out.get("findings"), list):
        findings = ai_out["findings"]
    if findings:
        for f in findings:
            title = str(f.get("title", ""))
            sev = str(f.get("severity", ""))
            refs = f.get("evidence_refs", [])
            refs_s = ", ".join(map(str, refs)) if isinstance(refs, list) else ""
            lines.append(f"- **{title}** (severity: {sev}) — evidence: {refs_s}")
    else:
        lines.append("No AI findings included.")
    lines.append("")

    lines.append("## Integrity Details\n")
    if rep.ok:
        lines.append("No integrity issues detected.")
    else:
        for iss in rep.issues:
            lines.append(f"- {iss.code}: {iss.message}")

    return "\n".join(lines).rstrip() + "\n"


def render_html_from_markdown(md: str) -> str:
    # Safe renderer: escape everything, keep in <pre>
    return "<html><body><pre>" + html.escape(md) + "</pre></body></html>\n"


def render_pdf_from_markdown(md: str) -> bytes:
    # Safe: render text only (no HTML)
    from io import BytesIO

    buf = BytesIO()
    c = canvas.Canvas(buf)
    text = c.beginText(40, 800)
    text.setLeading(14)
    for line in md.splitlines():
        # simple wrap
        if len(line) <= 100:
            text.textLine(line)
        else:
            while line:
                text.textLine(line[:100])
                line = line[100:]
        if text.getY() < 40:
            c.drawText(text)
            c.showPage()
            text = c.beginText(40, 800)
            text.setLeading(14)
    c.drawText(text)
    c.save()
    return buf.getvalue()


def generate_report(case_root: Path, fmt: ReportFormat = "md", output_path: Optional[Path] = None) -> tuple[Path, str]:
    ensure_dir(case_root / "reports")
    md = build_markdown(case_root)
    if fmt == "md":
        data = md.encode("utf-8")
        dest = output_path or (case_root / "reports" / "report.md")
        atomic_write_bytes(dest, data)
        return dest, _sha256_bytes(data)

    if fmt == "html":
        html_text = render_html_from_markdown(md)
        data = html_text.encode("utf-8")
        dest = output_path or (case_root / "reports" / "report.html")
        atomic_write_bytes(dest, data)
        return dest, _sha256_bytes(data)

    if fmt == "pdf":
        data = render_pdf_from_markdown(md)
        dest = output_path or (case_root / "reports" / "report.pdf")
        atomic_write_bytes(dest, data)
        return dest, _sha256_bytes(data)

    raise ValueError("Unsupported format")
