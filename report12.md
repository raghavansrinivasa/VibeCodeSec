# VibeCodeSec Report
SecurityScore: 58/100 | VibeScore: 91/100 | Files: 2 | Findings: 9

## Findings
| Level | Type | Rule | File:Line | Message |
|---|---|---|---|---|
| LOW | VIBE | `ambiguous-variable-names` | `E:\code\bad_code.py:11` | Single ambiguous variables (l, O, I) hinder code review; choose descriptive names. |
| HIGH | VIBE | `unicode-homoglyph` | `E:\code\bad_code.py:15` | Potential Unicode homoglyph usage (obfuscation risk). |
| HIGH | SEC | `insecure-eval` | `E:\code\bad_code.py:7` | Use of eval() is unsafe and can lead to RCE. Prefer ast.literal_eval for data or explicit parsing. |
| HIGH | SEC | `insecure-exec` | `E:\code\bad_code.py:7` | Use of exec() can execute arbitrary code. Avoid or strictly confine. |
| HIGH | SEC | `dynamic-import` | `E:\code\bad_code.py:7` | Dynamic imports via __import__ can mask malicious modules. Prefer static imports. |
| HIGH | SEC | `insecure-eval` | `E:\code\bad_code.py:8` | Use of eval() is unsafe and can lead to RCE. Prefer ast.literal_eval for data or explicit parsing. |
| HIGH | SEC | `insecure-exec` | `E:\code\bad_code.py:8` | Use of exec() can execute arbitrary code. Avoid or strictly confine. |
| HIGH | SEC | `dynamic-import` | `E:\code\bad_code.py:8` | Dynamic imports via __import__ can mask malicious modules. Prefer static imports. |
| LOW | VIBE | `single-letter-args` | `E:\code\bad_code.py:5` | Single-letter parameters: a, b, c |
