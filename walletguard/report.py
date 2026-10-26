"""Write scan findings to a readable text report and a JSON report."""

import datetime
import json
import os

from .alerts import DATA_DIR


def format_text(findings, verbose=False):
    lines = []
    for f in findings:
        if f.severity == "info" and not verbose:
            continue
        lines.append(f"[{f.severity.upper():8}] {f.title}")
        if f.detail:
            lines.append(f"           {f.detail}")
        if f.fix:
            lines.append(f"           -> {f.fix}")
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    order = ("critical", "high", "medium", "low", "info")
    lines.append("")
    lines.append("Summary: " + (", ".join(f"{counts[s]} {s}" for s in order if counts.get(s)) or "nothing found"))
    return "\n".join(lines)


def write_reports(findings):
    """Return (text_path, json_path)."""
    os.makedirs(DATA_DIR, exist_ok=True)
    stamp = f"{datetime.datetime.now():%Y%m%d-%H%M%S}"
    txt = os.path.join(DATA_DIR, f"scan-{stamp}.txt")
    js = os.path.join(DATA_DIR, f"scan-{stamp}.json")
    with open(txt, "w", encoding="utf-8") as fh:
        fh.write(f"WalletGuard scan {stamp}\n\n" + format_text(findings, verbose=True) + "\n")
    with open(js, "w", encoding="utf-8") as fh:
        json.dump([f.to_dict() for f in findings], fh, indent=1)
    return txt, js
