from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.core.db import get_connection
from app.scenarios.base import Scenario

FLAG = "FLAG{CHAIN_injection_with_log_forensics_evasion}"

router = APIRouter()

_LOG_TEXT = ""


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = """
    <div class="panel">
      <p>This login form is vulnerable to SQL injection <i>and</i> logs the raw
      username with no sanitization of newline characters — can you do both
      at once?</p>
      <form method="post" action="/play/a09_chain_injection_log_forensics_evasion/login">
        <label>Username</label>
        <input name="username" placeholder="admin">
        <label>Password</label>
        <input name="password">
        <button type="submit">Log in</button>
      </form>
      <p style="margin-top:10px;"><a href="/play/a09_chain_injection_log_forensics_evasion/view-log">View security log &rarr;</a></p>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/login", response_class=HTMLResponse)
def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    global _LOG_TEXT
    session = get_or_create_session(request)
    conn, lock = get_connection()

    # Log the raw username BEFORE the query — no sanitization of embedded
    # newlines, so a crafted username can inject an extra, fake-looking
    # log line right alongside the real one. Note: a single request can't
    # both use a newline AND a working SQL "--" comment (comments don't
    # survive an embedded newline) — so a real attacker chains this across
    # two requests: one to bypass login, one to plant the decoy log line.
    _LOG_TEXT += f"[LOGIN_ATTEMPT] username={username}\n"

    # VULNERABLE: same unparameterized-query SQLi as the standalone
    # Injection scenario.
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        with lock:
            row = conn.execute(query).fetchone()
    except Exception as e:  # noqa: BLE001
        body = f'<div class="panel"><p>Query error: {e}</p></div>'
        return page(SCENARIO, session, body)

    if row and password != row["password"]:
        session["chain_injection_succeeded"] = True
        body = f"<div class='panel'><p>✅ Logged in as <b>{row['username']}</b> — without the real password.</p></div>"
    elif row:
        body = f"<div class='panel'><p>Logged in normally as {row['username']}.</p></div>"
    else:
        body = "<div class='panel'><p>Login failed.</p></div>"

    body += '<p><a href="/play/a09_chain_injection_log_forensics_evasion/">&larr; Back</a></p>'
    return page(SCENARIO, session, body)


@router.get("/view-log", response_class=HTMLResponse)
def view_log(request: Request, response: Response):
    session = get_or_create_session(request)
    flag_captured = None

    lines = _LOG_TEXT.split("\n")
    has_forged_benign_line = any(line.strip().startswith("[INFO]") for line in lines)

    if session.get("chain_injection_succeeded") and has_forged_benign_line:
        capture_flag(session, FLAG)
        flag_captured = FLAG
        note = (
            "<p class='muted'>A successful SQL injection login bypass just "
            "occurred, but the log below has been salted with a fake, "
            "benign-looking [INFO] line — exactly the kind of noise that "
            "makes the real attack harder to spot during a forensic review.</p>"
        )
    else:
        note = ""

    log_html = "<br>".join(l for l in lines if l) if _LOG_TEXT else '<span class="muted">Log is empty.</span>'
    body = f'<div class="panel"><pre class="mono" style="white-space:pre-wrap;">{log_html}</pre>{note}</div>'
    body += '<p><a href="/play/a09_chain_injection_log_forensics_evasion/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a09_chain_injection_log_forensics_evasion",
    owasp_id="A09:2025",
    title="Chained Exploit: Injection with Forensics Evasion",
    difficulty="Advanced",
    tagline="Combine a SQL injection login bypass with a forged log entry, in the same payload, to muddy the forensic trail.",
    objective_md="""
This login form has two independent bugs: it's vulnerable to SQL
injection, and it logs your raw username with no sanitization of newline
characters.

**Your goal:** chain both together across two submissions. First, bypass
login via SQL injection. Then, submit a second attempt whose username
plants a fake, innocuous-looking log line (starting with `[INFO]`) that a
forensic reviewer might mistake for a legitimate event — muddying the
evidence trail around your earlier breach.
""",
    hints_md="""
- Step 1 — bypass login: username = `admin' -- ` (with a trailing space),
  any password.
- Step 2 — plant a decoy log line: submit another login attempt (it can
  fail, that's fine) with a username containing a real newline followed by
  something like `[INFO] Routine login check completed`.
- Why two separate submissions? A SQL line-comment (`-- `) only comments
  out the rest of *that line* — an embedded newline in the same field
  would break the comment technique. Splitting the two techniques across
  two requests is exactly what a real attacker chaining these bugs would
  do anyway.
- Then check the log — both the evidence of your real bypass (tracked
  server-side) and the decoy line should be present.
""",
    fix_md="""
**Root cause:** two independent bugs — unparameterized SQL query
construction, and unsanitized newline characters in logged input — combine
so that a single attacker-controlled field both breaks authentication
*and* corrupts the audit trail meant to detect that exact kind of breach.

**Fixes:**
- Fix each bug on its own merits: parameterized queries for the SQL
  injection, and either strip/escape control characters from logged input
  or use structured (e.g. JSON) logging that can't be broken out of via
  embedded newlines.
- Recognize that log integrity is itself a security control — if an
  attacker can also corrupt your logging in the same step as their attack,
  your ability to detect and respond to that attack is compromised too.
- Use tamper-evident, append-only logging infrastructure so injected or
  altered entries are themselves detectable.
""",
    flag_id=FLAG,
    router=router,
)
