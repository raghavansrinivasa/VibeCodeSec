# VibeCodeSec Report
SecurityScore: 51/100 | VibeScore: 78/100 | Files: 7 | Findings: 15

## Findings
| Level | Type | Rule | File:Line | Message |
|---|---|---|---|---|
| LOW | VIBE | `ambiguous-variable-names` | `E:\VibeCodeSec\bad_code.py:11` | Single ambiguous variables (l, O, I) hinder code review; choose descriptive names. |
| HIGH | VIBE | `unicode-homoglyph` | `E:\VibeCodeSec\bad_code.py:15` | Potential Unicode homoglyph usage (obfuscation risk). |
| HIGH | SEC | `insecure-eval` | `E:\VibeCodeSec\bad_code.py:7` | Use of eval() is unsafe and can lead to RCE. Prefer ast.literal_eval for data or explicit parsing. |
| HIGH | SEC | `insecure-exec` | `E:\VibeCodeSec\bad_code.py:7` | Use of exec() can execute arbitrary code. Avoid or strictly confine. |
| HIGH | SEC | `dynamic-import` | `E:\VibeCodeSec\bad_code.py:7` | Dynamic imports via __import__ can mask malicious modules. Prefer static imports. |
| HIGH | SEC | `insecure-eval` | `E:\VibeCodeSec\bad_code.py:8` | Use of eval() is unsafe and can lead to RCE. Prefer ast.literal_eval for data or explicit parsing. |
| HIGH | SEC | `insecure-exec` | `E:\VibeCodeSec\bad_code.py:8` | Use of exec() can execute arbitrary code. Avoid or strictly confine. |
| HIGH | SEC | `dynamic-import` | `E:\VibeCodeSec\bad_code.py:8` | Dynamic imports via __import__ can mask malicious modules. Prefer static imports. |
| LOW | VIBE | `single-letter-args` | `E:\VibeCodeSec\bad_code.py:5` | Single-letter parameters: a, b, c |
| HIGH | SEC | `magic-attr-access` | `E:\VibeCodeSec\src\vibecodesec\reporters.py:32` | Access to __dict__ or __class__ may leak internals or enable tampering. |
| MEDIUM | VIBE | `one-liner-complex` | `E:\VibeCodeSec\src\vibecodesec\reporters.py:13` | Overly long single lines reduce readability and auditability; split statements. |
| MEDIUM | VIBE | `one-liner-complex` | `E:\VibeCodeSec\src\vibecodesec\reporters.py:16` | Overly long single lines reduce readability and auditability; split statements. |
| MEDIUM | VIBE | `one-liner-complex` | `E:\VibeCodeSec\src\vibecodesec\reporters.py:26` | Overly long single lines reduce readability and auditability; split statements. |
| MEDIUM | VIBE | `one-liner-complex` | `E:\VibeCodeSec\src\vibecodesec\scanner.py:121` | Overly long single lines reduce readability and auditability; split statements. |
| LOW | VIBE | `single-letter-args` | `E:\VibeCodeSec\src\vibecodesec\scanner.py:52` | Single-letter parameters: p |
