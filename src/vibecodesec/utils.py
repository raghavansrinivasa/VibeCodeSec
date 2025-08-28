from __future__ import annotations
import argparse
from pathlib import Path

def cli_entry() -> None:
    """Console entrypoint for `vibecode`.

    Safe: no eval/exec; arguments validated; paths resolved.
    """
    parser = argparse.ArgumentParser(prog="vibecode", description="Scan Python code for vibe+security issues")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Scan a directory or file")
    scan.add_argument("target", type=str, help="File or directory to scan")
    scan.add_argument("--rules-sec", default="rules/secure_coding.yml", help="Path to secure coding rules")
    scan.add_argument("--rules-vibe", default="rules/vibe_patterns.yml", help="Path to vibe rules")
    scan.add_argument("--exclude", action="append", default=[], help="Glob/path to exclude (repeatable)")
    scan.add_argument("--out", default="report.md", help="Markdown report output path")
    scan.add_argument("--json", dest="json_out", default=None, help="Optional JSON report output path")

    args = parser.parse_args()

    if args.cmd == "scan":
        from .scanner import load_rules, scan_path
        from .reporters import generate_reports
        target = Path(args.target).resolve()
        rules_sec, rules_vibe = load_rules(Path(r"E:\VibeCodeSec\src\rules\secure_coding.yml"),Path(r"E:\VibeCodeSec\src\rules\vibe_patterns.yml"))
        findings, scores, stats = scan_path(target, rules_sec, rules_vibe, excludes=args.exclude)
        generate_reports(findings, scores, stats, md_path=Path(args.out), json_path=(Path(args.json_out) if args.json_out else None))