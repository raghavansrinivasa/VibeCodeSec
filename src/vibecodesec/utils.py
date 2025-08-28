from __future__ import annotations
import argparse
from pathlib import Path
from typing import List, Dict

def merge_scores(scores_list: List[Dict[str, int]]) -> Dict[str, int]:
    """Average scores across multiple targets."""
    if not scores_list:
        return {"security": 100, "vibe": 100}
    return {
        "security": sum(s['security'] for s in scores_list) // len(scores_list),
        "vibe": sum(s['vibe'] for s in scores_list) // len(scores_list)
    }

def merge_stats(stats_list: List[Dict[str, int]]) -> Dict[str, int]:
    """Sum stats across multiple targets."""
    merged = {"files": 0, "findings": 0}
    for s in stats_list:
        merged['files'] += s.get('files', 0)
        merged['findings'] += s.get('findings', 0)
    return merged

def cli_entry() -> None:
    """Console entrypoint for `vibecode`.

    Safe: no eval/exec; arguments validated; paths resolved.
    """
    parser = argparse.ArgumentParser(prog="vibecode", description="Scan Python code for vibe+security issues")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Scan a directory or file")
    scan.add_argument("targets", nargs="+", help="File or directory to scan")
    scan.add_argument("--rules-sec", default="rules/secure_coding.yml", help="Path to secure coding rules")
    scan.add_argument("--rules-vibe", default="rules/vibe_patterns.yml", help="Path to vibe rules")
    scan.add_argument("--exclude", action="append", default=[], help="Glob/path to exclude (repeatable)")
    scan.add_argument("--out", default="report.md", help="Markdown report output path")
    scan.add_argument("--json", dest="json_out", default=None, help="Optional JSON report output path")

    args = parser.parse_args()

    if args.cmd == "scan":
        from .scanner import load_rules, scan_path
        from .reporters import generate_reports

        # Load rules once
        rules_sec, rules_vibe = load_rules(
            Path(r"E:\VibeCodeSec\src\rules\secure_coding.yml"),
            Path(r"E:\VibeCodeSec\src\rules\vibe_patterns.yml")
        )

        all_findings: list = []
        all_scores: list = []
        all_stats: list = []

        # Iterate over all targets
        for target in args.targets:
            target_path = Path(target).resolve()
            findings, scores, stats = scan_path(target_path, rules_sec, rules_vibe, excludes=args.exclude)
            all_findings.extend(findings)
            all_scores.append(scores)
            all_stats.append(stats)

        # Merge scores and stats before generating report
        merged_scores = merge_scores(all_scores)
        merged_stats = merge_stats(all_stats)

        # Generate report
        generate_reports(
            all_findings,
            merged_scores,
            merged_stats,
            md_path=Path(args.out),
            json_path=(Path(args.json_out) if args.json_out else None)
        )
