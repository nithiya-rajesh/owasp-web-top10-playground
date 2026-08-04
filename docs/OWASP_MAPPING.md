# OWASP Top 10:2025 — Scenario Mapping

Reference: https://owasp.org/Top10/

| OWASP ID | Category | Scenario | Core mechanism demonstrated |
|---|---|---|---|
| A01:2025 | Broken Access Control | `a01_broken_access_control` | No ownership check on order-detail lookup (IDOR); an avatar-import feature fetches arbitrary server-side URLs with no host restriction (SSRF, now folded into this category) |
| A01:2025 | Broken Access Control | `a01_mass_assignment_privesc` | A profile-update endpoint applies every submitted field directly, including an unexposed `role` field |
| A01:2025 | Broken Access Control | `a01_chain_sqli_to_idor` | **Chained:** SQL injection leaks a user ID the UI never shows, which then unlocks an IDOR-vulnerable endpoint |
| A02:2025 | Security Misconfiguration | `a02_security_misconfiguration` | A debug/diagnostic endpoint left reachable, leaking config, secrets, and stack traces |
| A02:2025 | Security Misconfiguration | `a02_default_admin_credentials` | Factory-default admin credentials were never changed after deployment |
| A02:2025 | Security Misconfiguration | `a02_chain_debug_to_credential_theft` | **Chained:** a debug endpoint leaks a real backup credential, which is then used to log into a separate internal panel |
| A03:2025 | Supply Chain Failures | `a03_supply_chain_failures` | A typosquatted, unverified-publisher "extension" sits alongside a legitimate one in a mock marketplace |
| A03:2025 | Supply Chain Failures | `a03_vulnerable_frontend_library` | An outdated JS library with known CVEs is vendored in with no Subresource Integrity hash |
| A04:2025 | Cryptographic Failures | `a04_cryptographic_failures` | Unsalted, fast-hash (MD5) passwords in a leaked export; a JWT signed with a short, guessable secret |
| A04:2025 | Cryptographic Failures | `a04_predictable_session_tokens` | Sequential, predictable session tokens allow guessing/incrementing into another active session |
| A05:2025 | Injection | `a05_injection` | A genuine unparameterized SQL query (real sqlite3 DB) allowing a login bypass; unescaped HTML rendering of user-submitted comments (stored XSS) |
| A05:2025 | Injection | `a05_command_injection` | Real OS command injection via `subprocess(shell=True)` and unsanitized string concatenation |
| A05:2025 | Injection | `a05_chain_xss_to_csrf` | **Chained:** a stored XSS payload auto-triggers a CSRF-vulnerable account-change action the moment a victim views it |
| A06:2025 | Insecure Design | `a06_insecure_design` | Checkout accepts client-submitted price/quantity with no server-side re-validation against the real catalog |
| A06:2025 | Insecure Design | `a06_coupon_abuse_no_ratelimit` | A "single-use" coupon has no idempotency check or rate limit, allowing unlimited repeat redemption |
| A07:2025 | Authentication Failures | `a07_authentication_failures` | No lockout/rate-limit on repeated failed logins; a forgot-password flow whose response differs based on username existence |
| A07:2025 | Authentication Failures | `a07_session_fixation` | A client-supplied session ID is accepted before login and never rotated afterward |
| A07:2025 | Authentication Failures | `a07_chain_enum_to_bruteforce` | **Chained:** username enumeration confirms a real account, which then narrows a subsequent no-lockout brute force |
| A08:2025 | Software or Data Integrity Failures | `a08_software_data_integrity` | A settings export/restore round-trip with no signature/HMAC verification, allowing role-field tampering |
| A08:2025 | Software or Data Integrity Failures | `a08_unverified_update_source` | A plugin-install feature trusts an arbitrary manifest URL with no publisher/signature verification |
| A09:2025 | Security Logging and Alerting Failures | `a09_logging_alerting_failures` | Unsanitized newline characters in logged input allow forging fake log entries (CRLF/log injection) |
| A09:2025 | Security Logging and Alerting Failures | `a09_no_audit_trail` | A highly sensitive privileged action (admin promotion) produces zero audit log entry at all |
| A09:2025 | Security Logging and Alerting Failures | `a09_chain_injection_log_forensics_evasion` | **Chained:** a SQL injection login bypass is paired with a forged, benign-looking log entry to muddy the forensic trail |
| A10:2025 | Mishandling of Exceptional Conditions | `a10_exceptional_conditions` | An authorization check's exception handler defaults to "allow" instead of "deny" on malformed input |
| A10:2025 | Mishandling of Exceptional Conditions | `a10_stacktrace_disclosure` | A misconfigured debug-mode error handler dumps the full raw traceback, including file paths, into the response |

## Notes on fidelity

Most of these are genuinely exploitable against real running code (a real
sqlite3 database for A05, real PyJWT verification for A04, real unescaped
HTML rendering, and a real OS command injection executed via
`subprocess`). Two are deliberately simulated for safety — see the
README's "A note on what's real vs. simulated" section for why (SSRF in
A01 doesn't make real outbound network calls; A08's original scenario uses
a JSON integrity-check gap rather than a real Python `pickle`
insecure-deserialization RCE, since a working RCE payload generator would
be a directly reusable exploit primitive against real systems, not just
this lab).

## Suggested learning order

1. **A05, A06, A07** (original scenarios) — the most intuitive, classic
   vulnerabilities; best starting point.
2. **A01, A02** (original scenarios) — access-control and configuration
   issues, still fairly direct to exploit.
3. **A04, A09** (original scenarios) — require a bit more understanding of
   the surrounding mechanism (hashing, JWTs, log formats).
4. **A03, A08, A10** (original scenarios) — more nuanced/systemic issues;
   best tackled once the fundamentals feel familiar.
5. **The second scenario in each category** — once the classic version of
   a category clicks, its sibling scenario reinforces the same root cause
   through a genuinely different mechanism.
6. **The five chained scenarios last** — these require confidently
   combining two techniques in sequence, so they're the best capstone
   once each individual vulnerability class feels comfortable on its own.
