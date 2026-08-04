# Contributing

Contributions are welcome — new scenario variants, additional attack paths
within existing scenarios, UI improvements, and fixes are all fair game.

## Ground rules

- **Every scenario stays local-only and clearly labeled as intentionally
  vulnerable.** Don't add anything that could cause real-world harm if
  copy-pasted out of context — no real exploit payloads with genuine
  transferable weaponization value (see the README's note on why A08 uses
  a simulated integrity-check gap rather than a real deserialization RCE).
- All fake data (users, orders, secrets) must be obviously synthetic.
- Each scenario should map to exactly one OWASP Top 10:2025 category —
  check `docs/OWASP_MAPPING.md` before adding a new one to avoid duplicates.
- Prefer genuinely exploitable code (real SQL queries, real JWT
  verification, real unescaped rendering) over simulated checks wherever it
  can be done safely — that's what makes this project meaningfully
  different from a purely narrative walkthrough.

## Adding a scenario

1. `app/scenarios/<your_id>/scenario.py` — export `SCENARIO = Scenario(...)`
   with a real `APIRouter` containing the vulnerable route(s). See
   `app/scenarios/base.py` for required fields and any existing scenario
   (e.g. `a05_injection`) as a template.
2. Write `objective_md`, `hints_md`, and `fix_md` in the same voice as
   existing scenarios.
3. Call `capture_flag(session, FLAG)` at the exact point the vulnerable
   condition is genuinely triggered — not just "the user visited a page."
4. Add a real end-to-end exploit test in `tests/test_exploits.py` using
   `TestClient` — this is the actual proof the vulnerability works, not
   just a description of it.

## Pull requests

- Keep PRs scoped to one scenario or one fix at a time where possible.
- Run `PYTHONPATH=. python3 tests/test_exploits.py` locally and confirm
  all exploits (including any new one) pass before submitting.

## Reporting issues

Open a GitHub issue with steps to reproduce. If you find a way a scenario's
"vulnerability" doesn't actually work as described, or a way to affect
another scenario's isolated state, that's a bug in the training app itself
— please flag it clearly.
