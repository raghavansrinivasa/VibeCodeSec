from __future__ import annotations
import json
from pathlib import Path
from typing import Iterable, List, Dict

from .scanner import Finding


def _md_escape(text: str) -> str:
    return text.replace("|", "\|")


def generate_reports(findings: List[Finding], scores: Dict[str, int], stats: Dict[str, int], *, md_path: Path, json_path: Path | None) -> None:
    md_lines: List[str] = []
    md_lines.append(f"# VibeCodeSec Report\n")
    md_lines.append(f"SecurityScore: {scores['security']}/100 | VibeScore: {scores['vibe']}/100 | Files: {stats['files']} | Findings: {stats['findings']}\n")
    md_lines.append("\n## Findings\n")
    if not findings:
        md_lines.append("No issues found. ✅\n")
    else:
        md_lines.append("| Level | Type | Rule | File:Line | Message |\n|---|---|---|---|---|\n")
        for f in findings:
            level = f.severity.upper()
            ftype = "SEC" if f.category == "SEC" else "VIBE"
            md_lines.append(
                f"| {level} | {ftype} | `{_md_escape(f.rule_id)}` | `{_md_escape(f.file)}:{f.line}` | {_md_escape(f.message)} |\n"
            )
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text("".join(md_lines), encoding="utf-8")

    if json_path is not None:
        json_safe = [f.__dict__ for f in findings]
        json_out = {
            "scores": scores,
            "stats": stats,
            "findings": json_safe,
        }
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(json_out, ensure_ascii=False, indent=2), encoding="utf-8")