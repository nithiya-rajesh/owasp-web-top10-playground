# Manual Testing Guide

Use this to walk through every scenario yourself before publishing, and to
re-verify things still work if you modify or extend a scenario later.

**Scope note:** 25 scenarios total — most categories have a classic
scenario plus a second, distinct mechanism, and there's a dedicated
5-scenario exploit-chaining round. See `docs/OWASP_MAPPING.md` for exactly
which mechanism each scenario demonstrates.

## Setup

```bash
cd owasp-web-top10-playground
docker compose up --build
```
Open **http://localhost:8000**. No API key or `.env` needed — there's no
model in the loop here.

For each scenario below: click it from the dashboard, follow the steps,
and check for the 🚩 flag banner. A session cookie tracks your progress
across scenarios; use **Reset session** (via `POST /play/{id}/reset`) to
clear a scenario's state and retry from scratch.

---

## A01 — Broken Access Control

**1. IDOR + SSRF** — Log in as either demo user, then edit the order URL
to view someone else's order (e.g. `/orders/102` while logged in as
user 1). Separately, try importing an avatar from
`http://169.254.169.254/latest/meta-data/`.

**2. Mass Assignment Privilege Escalation** — The profile form only shows
name/email. Submit a raw request including an extra `role=admin` field:
```bash
curl -X POST http://localhost:8000/play/a01_mass_assignment_privesc/update-profile \
  -d "name=Alice&email=alice@example.com&role=admin"
```

**3. Chained: SQLi → IDOR** — Search products with:
```
nonexistent' UNION SELECT id, username, role FROM users -- 
```
This leaks user IDs (including `bob`, id=2). Then look up private notes
for user ID `2`.

---

## A02 — Security Misconfiguration

**1. Exposed debug endpoint** — Visit `/debug/info` under this scenario.

**2. Default Admin Credentials** — Log in with `admin` / `admin123`.

**3. Chained: Debug leak → credential theft** — Visit `/debug/config`
first (leaks a backup admin password), then use that exact password to
log in at the "internal admin login" form with username `admin`.

---

## A03 — Supply Chain Failures

**1. Typosquatted extension** — Compare the two "PriceTracker Pro"
listings character-by-character before installing the wrong one.

**2. Vulnerable Frontend Library** — View the page's raw source
(Ctrl+U / View Page Source), find the vendored library comment, and
report `jquery` version `1.6.1`.

---

## A04 — Cryptographic Failures

**1. Crackable MD5 + forgeable JWT** — Crack a seeded weak password from
the leaked export; separately, forge a JWT with `role: admin` using the
guessable signing secret.

**2. Predictable Session Tokens** — Log in once to see your token's
pattern (e.g. `sess_1001`), then look up account info using `sess_1000`
directly — that session already existed before you logged in.

---

## A05 — Injection

**1. SQL injection + stored XSS** — `admin' -- ` (trailing space) as
username bypasses login; `<script>alert(1)</script>` in a comment
persists unescaped.

**2. OS Command Injection** — Submit `127.0.0.1; whoami` (or `&& id`) as
the ping host.

**3. Chained: Stored XSS → CSRF** — Post a comment containing:
```html
<script>fetch('/change-email?email=attacker@evil.example')</script>
```
Then click "Simulate victim opening this page" and confirm the victim's
email actually changed.

---

## A06 — Insecure Design

**1. Client-trusted checkout pricing** — Submit a negative price or
quantity at checkout.

**2. Coupon Redemption Abuse** — Redeem the same `WELCOME10` coupon 5+
times in a row; watch your credit balance exceed the intended single-use
cap.

---

## A07 — Authentication Failures

**1. No lockout + username enumeration** — Brute-force `bob`'s password
(no lockout ever kicks in); compare forgot-password responses for a real
vs. fake username.

**2. Session Fixation** — Click "set a custom session ID," then complete
the login form, and confirm the session ID shown afterward is still the
same attacker-chosen value.

**3. Chained: Enumeration → targeted brute force** — Confirm `bob` is a
real username via the forgot-password check, then brute-force exactly
that username's password.

---

## A08 — Software or Data Integrity Failures

**1. Unsigned settings restore** — Edit the exported settings JSON's
`role` field to `admin` before restoring.

**2. Unverified Package Source** — Install a plugin from
`http://my-plugin-host.example/manifest?grant=admin`.

---

## A09 — Security Logging and Alerting Failures

**1. CRLF log injection** — Search with an embedded newline + fake
`[ADMIN]` log line.

**2. Missing Audit Trail** — Promote a user to admin, then check the
audit log and confirm nothing was recorded.

**3. Chained: Injection + forensics evasion** — First bypass login with
`admin' -- ` (trailing space, any password). Then submit a second login
attempt (it's fine if it fails) with a username containing a real newline
followed by `[INFO] Routine login check completed`. Check the log — both
the real bypass and the forged decoy line should be present.

---

## A10 — Mishandling of Exceptional Conditions

**1. Fail-open exception handling** — Submit a non-numeric `user_id` on
the private notes form.

**2. Verbose Stack Trace Disclosure** — Divide by `0` on the calculator,
or submit a non-numeric value in either field.

---

## After a full pass

- **Flag counter should read 25/25** on the dashboard.
- Spot-check a couple of **Fix** tabs to confirm remediation content
  renders correctly and only unlocks after that scenario's flag.
- Try the reset endpoint on one scenario and confirm its state (and only
  its state) clears.
