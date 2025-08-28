# Mapping: Vibe Patterns → Security & Maintainability (Python)

This document aligns Python‑specific vibe patterns with potential security or maintainability risks.

| Category | Rule ID | Description | Example | Mitigation |
|---|---|---|---|---|
| SEC | insecure-eval | Dynamic execution via `eval()` can enable RCE | `result = eval(user_data)` | Use `ast.literal_eval` or safe parsers |
| SEC | insecure-exec | `exec()` executes arbitrary code | `exec(code)` | Avoid; replace with explicit logic |
| SEC | dynamic-import | `__import__()` hides dependencies | `m = __import__(name)` | Use static imports |
| SEC | hardcoded-secrets | Secrets embedded in code | `API_KEY = "sk_live..."` | Use env vars / secret manager |
| SEC | regex-validation-only | Regex only validation is brittle | `re.match(...)` | Add type/len/allowlist checks |
| SEC | magic-attr-access | `__dict__`, `__class__` expose internals | `obj.__dict__['admin']=1` | Encapsulation; dataclasses; accessors |
| VIBE | one-liner-complex | Long single lines harm readability | very long conditional chains | Split into steps, add comments |
| VIBE | chained-methods | Deep chains hide errors | `a().b().c()` | Intermediates + try/except |
| VIBE | ambiguous-variable-names | `l`, `O`, `I` confuse auditors | `for l in xs:` | Use descriptive names |
| VIBE | unicode-homoglyph | Visual deception in identifiers | `а = 1` (Cyrillic) | Normalize; lint; review |
| VIBE | single-letter-args | Poorly named parameters | `def f(a,b):` | Rename; refactor |