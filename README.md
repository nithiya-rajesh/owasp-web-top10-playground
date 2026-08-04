# OWASP Web Top 10 Playground

[![CI](https://github.com/nithiya-rajesh/owasp-web-top10-playground/actions/workflows/ci.yml/badge.svg)](https://github.com/nithiya-rajesh/owasp-web-top10-playground/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

**Free, open-source, hands-on practice for classic web application
security — no paid subscription, no API key, no external service of any
kind required.** Everything here runs entirely on your own machine.

A deliberately vulnerable web application for hands-on practice against the
**[OWASP Top 10:2025](https://owasp.org/Top10/)** — classic web application
security risks (SQL injection, broken access control, XSS, and so on), as
opposed to the separate **OWASP LLM Top 10 Playground** (a companion
project covering AI/LLM-specific risks — link it here once both repos are
published, e.g. `https://github.com/YOUR-USERNAME/owasp-llm-playground`).

Twenty-five real, genuinely exploitable endpoints across all 10 OWASP
categories — including a dedicated exploit-chaining round — with
in-app Objective/Hints/Fix guidance and automatic flag capture on successful
exploitation. Think Juice Shop / WebGoat / DVWA, scoped specifically to the
current (2025) OWASP list.

**Run this only locally, against your own machine. Never deploy it publicly
— every endpoint here is intentionally broken.**


## Scenarios

**25 scenarios**, grouped by OWASP category — most categories include a
second, distinct mechanism beyond the classic textbook example, plus a
dedicated **exploit-chaining round**: five scenarios that require
combining two vulnerabilities in sequence to succeed, closer to how real
penetration testing actually works than any single-bug challenge.

| OWASP ID | Category | Scenarios in this category |
|----------|----------|------------------------------|
| A01:2025 | Broken Access Control | IDOR on order details + SSRF via avatar import · Mass assignment privilege escalation · **Chained:** SQL injection leaks a user ID, then IDOR uses it |
| A02:2025 | Security Misconfiguration | Exposed debug endpoint · Default admin credentials · **Chained:** debug leak reveals a credential, then used to log into a separate panel |
| A03:2025 | Supply Chain Failures | Typosquatted marketplace extension · Vulnerable frontend library with no integrity check |
| A04:2025 | Cryptographic Failures | Crackable MD5 export + forgeable JWT · Predictable (sequential) session tokens |
| A05:2025 | Injection | Real SQL injection login bypass + stored XSS · OS command injection · **Chained:** stored XSS auto-triggers a CSRF-vulnerable account change |
| A06:2025 | Insecure Design | Client-trusted checkout pricing · Coupon redemption abuse (no idempotency/rate limit) |
| A07:2025 | Authentication Failures | No-lockout brute force + username enumeration · Session fixation · **Chained:** enumeration result informs a targeted brute force |
| A08:2025 | Software or Data Integrity Failures | Unsigned settings restore · Unverified plugin/package install source |
| A09:2025 | Security Logging and Alerting Failures | CRLF log injection · Missing audit trail for a privileged action · **Chained:** SQL injection combined with forged log entries to evade detection |
| A10:2025 | Mishandling of Exceptional Conditions | Auth check fails open on malformed input · Verbose stack trace disclosure |

See `docs/OWASP_MAPPING.md` for the full breakdown and fixes.

## Quick start (Docker — recommended)

```bash
git clone <your-fork-url>
cd owasp-web-top10-playground
docker compose up --build
```

Open **http://localhost:8000**.

See `TESTING_GUIDE.md` for exact step-by-step instructions to verify every
one of the 25 scenarios yourself.

## Quick start (without Docker)

```bash
git clone <your-fork-url>
cd owasp-web-top10-playground
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open **http://localhost:8000**.

## How it works

- The dashboard lists all 25 scenarios. Click one to go straight to its
  real, vulnerable page — a login form, a search box, a checkout flow,
  whatever's appropriate for that category.
- Each scenario has **Play / Objective / Hints / Fix** tabs. Play is the
  actual vulnerable app; the others are training material.
- Exploiting the vulnerability captures a flag automatically (server-side,
  based on real request/response state — not something you can fake from
  the frontend) and unlocks that scenario's **Fix** tab.
- **Reset session** (via `POST /play/{id}/reset`) clears your session's
  captured flags and any per-scenario state for that scenario.

This is architecturally the same pattern as the sibling LLM playground —
self-discovering scenarios (drop a new folder in `app/scenarios/`, it's
picked up automatically), deterministic server-side flag verification, one
OWASP category per scenario module.

## A note on what's real vs. simulated

Everything here is a **genuine** vulnerability against **real** running
code — the SQL injection hits an actual sqlite3 database with a real
unparameterized query; the JWT forgery is checked with real PyJWT
verification against the app's actual (weak) signing secret; the XSS is
genuinely unescaped HTML rendering; the OS command injection scenario
genuinely executes a shell command via `subprocess` with `shell=True` —
contained entirely within this app's own Docker container (same
established pattern as real-world labs like DVWA), never expose this
publicly.

Two things are deliberately simulated rather than fully real, for safety:
- **SSRF (A01):** the avatar importer detects internal-looking hostnames
  and returns a *fake* "fetched" result — it never makes a real outbound
  network request, so it can't actually be used to reach real internal
  infrastructure even accidentally.
- **A08 (Integrity Failures):** this uses a JSON settings restore with no
  signature check, rather than a real insecure-deserialization (e.g.
  Python `pickle`) remote-code-execution demo. A working RCE-via-pickle
  payload is a generic, directly transferable exploit primitive usable
  against *any* Python app that unpickles untrusted data — that's a
  meaningfully different (and broader) risk than a contained training lab
  should hand out, so this scenario teaches the same missing-integrity-check
  root cause without shipping a reusable RCE payload generator.

## Architecture

```
app/
  core/
    db.py          # real sqlite3 DB (for A05) + plain dict stores for the rest
    session.py      # cookie-based session store
    layout.py        # shared HTML page shell (Play/Objective/Hints/Fix tabs)
  scenarios/
    base.py          # Scenario dataclass every module implements
    a01_broken_access_control/
      scenario.py     # real FastAPI router with the vulnerable routes
    a02_security_misconfiguration/
    ...
  main.py            # dashboard, mounts each scenario's router, generic tab routes
```

No real user accounts, no real payment processing, no persistence beyond
process memory. This is a training tool, not a template for production
architecture — do not reuse these patterns in anything real.

## Requirements

- Python 3.11+ (if running without Docker)
- Docker + Docker Compose (optional, recommended)

## License

MIT — see `LICENSE`. Contributions welcome; see `CONTRIBUTING.md` and our
`CODE_OF_CONDUCT.md`.
