# Contributing to VibeCodeSec

## Add or edit a rule
1. Open `docs/mapping.md` and add/update the mapping row.
2. Reflect the rule in YAML:
   - Security → `rules/secure_coding.yml`
   - Vibe → `rules/vibe_patterns.yml`
3. Choose `check_tool`:
   - `regex` for simple token/line patterns (fastest)
   - `ast` for semantic checks (e.g., function calls, parameters)
4. Provide an **example** showing the issue.
5. Run local scan and verify the rule triggers only where expected.