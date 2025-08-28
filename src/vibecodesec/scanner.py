from __future__ import annotations
import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple
import yaml  # PyYAML

SAFE_DEFAULT_EXCLUDES = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}


# ---------- Data models ----------

@dataclass
class Rule:
    id: str
    description: str
    pattern: Optional[str]
    severity: str  # LOW | MEDIUM | HIGH
    category: str  # SEC | VIBE
    example: Optional[str] = None
    check_tool: Optional[str] = None  # regex | ast | mixed


@dataclass
class Finding:
    rule_id: str
    file: str
    line: int
    severity: str
    category: str
    message: str


# ---------- File reading ----------

def _read_text_safely(path: Path) -> str:
    """Read text from a file with safe UTF-8 decoding and BOM tolerance."""
    with path.open("rb") as f:
        data = f.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


# ---------- Rule loading ----------

def load_rules(secure_path: Path, vibe_path: Path) -> Tuple[List[Rule], List[Rule]]:
    """Load security and vibe rules from YAML files."""

    def load_one(p: Path, category: str) -> List[Rule]:
        text = _read_text_safely(p)
        raw = yaml.safe_load(text) or []
        rules: List[Rule] = []
        for item in raw:
            rules.append(Rule(
                id=item.get("id"),
                description=item.get("description", ""),
                pattern=item.get("pattern"),
                severity=item.get("severity", "MEDIUM").upper(),
                category=category,
                example=item.get("example"),
                check_tool=item.get("check_tool", "regex"),
            ))
        return rules

    return load_one(secure_path, "SEC"), load_one(vibe_path, "VIBE")


# ---------- Regex checks ----------

def _regex_findings(py_text: str, file_path: Path, rules: Iterable[Rule]) -> List[Finding]:
    findings: List[Finding] = []
    for rule in rules:
        if rule.check_tool != "regex" or not rule.pattern:
            continue
        try:
            pattern = re.compile(rule.pattern, flags=re.MULTILINE)
        except re.error:
            continue  # skip invalid regex
        for m in pattern.finditer(py_text):
            line_no = py_text.count("\n", 0, m.start()) + 1
            findings.append(Finding(
                rule_id=rule.id,
                file=str(file_path),
                line=line_no,
                severity=rule.severity,
                category=rule.category,
                message=rule.description,
            ))
    return findings


# ---------- AST checks ----------

class AstVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, rules: Iterable[Rule]):
        self.file_path = file_path
        self.rules = list(rules)
        self.findings: List[Finding] = []

    def _emit(self, rule_id: str, node: ast.AST, severity: str, category: str, message: str) -> None:
        line = getattr(node, "lineno", 1) or 1
        self.findings.append(Finding(rule_id, str(self.file_path), line, severity, category, message))

    def visit_Call(self, node: ast.Call) -> None:
        # SEC: eval/exec/__import__
        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "__import__"}:
            for r in self.rules:
                if r.check_tool == "ast" and r.id in {"insecure-eval", "insecure-exec", "dynamic-import"}:
                    self._emit(r.id, node, r.severity, r.category, r.description)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # VIBE: single-letter parameter names
        short_args = [arg.arg for arg in node.args.args if len(arg.arg) == 1]
        if short_args:
            for r in self.rules:
                if r.check_tool == "ast" and r.id == "single-letter-args":
                    self._emit(r.id, node, r.severity, r.category, f"Single-letter parameters: {', '.join(short_args)}")
        self.generic_visit(node)


def _ast_findings(py_text: str, file_path: Path, rules: Iterable[Rule]) -> List[Finding]:
    try:
        tree = ast.parse(py_text)
    except SyntaxError:
        return []
    visitor = AstVisitor(file_path, rules)
    visitor.visit(tree)
    return visitor.findings


# ---------- Scanning orchestration ----------

def _iter_py_files(root: Path, excludes: Iterable[str]) -> Iterable[Path]:
    root = root if root.is_dir() else root.parent
    exclude_set = set(excludes) | SAFE_DEFAULT_EXCLUDES
    for path in root.rglob("*.py"):
        if any(part in exclude_set for part in path.parts):
            continue
        yield path


def scan_path(target: Path, rules_sec: List[Rule], rules_vibe: List[Rule], excludes: Iterable[str] = ()):
    """Scan a file or directory and return findings, scores, and stats."""
    files: List[Path] = []
    if target.is_dir():
        files = list(_iter_py_files(target, excludes))
    elif target.is_file() and target.suffix == ".py":
        files = [target]
    else:
        return [], {"security": 100, "vibe": 100}, {"files": 0, "findings": 0}

    all_findings: List[Finding] = []
    for f in files:
        text = _read_text_safely(f)
        all_findings.extend(_regex_findings(text, f, rules_sec))
        all_findings.extend(_regex_findings(text, f, rules_vibe))
        all_findings.extend(_ast_findings(text, f, rules_sec))
        all_findings.extend(_ast_findings(text, f, rules_vibe))

    # scoring
    weights = {"LOW": 1, "MEDIUM": 3, "HIGH": 7}
    sec_score = 100
    vibe_score = 100
    for fd in all_findings:
        w = weights.get(fd.severity.upper(), 3)
        if fd.category == "SEC":
            sec_score -= w
        else:
            vibe_score -= w
    sec_score = max(sec_score, 0)
    vibe_score = max(vibe_score, 0)

    stats = {"files": len(files), "findings": len(all_findings)}
    scores = {"security": sec_score, "vibe": vibe_score}
    return all_findings, scores, stats
