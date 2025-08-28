# VibeCodeSec — Security Scanner for Vibe‑Coded Python Codebases 🚀🛡️


**VibeCodeSec** detects risky “vibe‑coded” patterns (aesthetic, one‑liner, or AI‑generated) and classic secure‑coding issues in Python. It produces a combined **SecurityScore** and **VibeScore** with actionable suggestions.


## Why
Vibe coding can trade clarity for cleverness. That can hide:
- Unvalidated input paths
- Dangerous dynamic execution (`eval`, `exec`)
- Obscure one‑liners and chained calls
- Hardcoded secrets


## What it does
- Scans Python files using **regex + AST**
- Applies two rule sets: `rules/secure_coding.yml` and `rules/vibe_patterns.yml`
- Emits **Markdown** and **JSON** reports with line‑precise findings


## Quickstart
```bash
# 1) Create venv
python -m venv .venv && . .venv/bin/activate # Windows: .venv\Scripts\activate


# 2) Install (editable)
pip install -e .


# 3) Run scan
vibecode scan . --out report.md --json report.json


# Or without packaging
python vibecode.py scan . --out report.md --json report.json