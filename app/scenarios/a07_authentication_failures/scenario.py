from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.core.db import get_connection
from app.scenarios.base import Scenario

BRUTEFORCE_FLAG = "FLAG{A07_auth_failures_no_lockout_bruteforce}"
ENUM_FLAG = "FLAG{A07_auth_failures_username_enumeration}"

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    attempts = session.setdefault("a07_attempts", 0)
    body = f"""
    <div class="panel">
      <h3>Goal 1: brute force (no lockout)</h3>
      <p class="muted">Failed attempts so far this session: {attempts}. Notice there's no
      lockout, no CAPTCHA, no delay, no matter how many times you try.</p>
      <form method="post" action="/play/a07_authentication_failures/login">
        <label>Username</label>
        <input name="username" value="bob">
        <label>Password</label>
        <input name="password" placeholder="guess bob's password">
        <button type="submit">Log in</button>
      </form>
    </div>
    <div class="panel">
      <h3>Goal 2: username enumeration</h3>
      <form method="get" action="/play/a07_authentication_failures/forgot-password">
        <label>Username</label>
        <input name="username" placeholder="try a real username, then a fake one">
        <button type="submit">Send reset link</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/login", response_class=HTMLResponse)
def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    session = get_or_create_session(request)
    conn, lock = get_connection()

    with lock:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?", (username, password)
        ).fetchone()

    flag_captured = None
    if row:
        attempts = session.get("a07_attempts", 0)
        if attempts >= 5:
            capture_flag(session, BRUTEFORCE_FLAG)
            flag_captured = BRUTEFORCE_FLAG
        session["a07_attempts"] = 0
        body = f"""
        <div class="panel">
          <p>✅ Logged in as <b>{row['username']}</b> after {attempts} failed attempts with
          no lockout, delay, or CAPTCHA ever kicking in.</p>
        </div>"""
    else:
        session["a07_attempts"] = session.get("a07_attempts", 0) + 1
        body = f'<div class="panel"><p>Login failed. (Attempt #{session["a07_attempts"]}, still no lockout.)</p></div>'

    body += '<p><a href="/play/a07_authentication_failures/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password(request: Request, response: Response, username: str = ""):
    session = get_or_create_session(request)
    conn, lock = get_connection()
    with lock:
        row = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()

    tried = session.setdefault("a07_enum_tried", {"real": False, "fake": False})
    flag_captured = None

    if row:
        tried["real"] = True
        msg = f"A password reset email has been sent to the address on file for <b>{username}</b>."
    else:
        tried["fake"] = True
        msg = f"No account found with username <b>{username}</b>."

    if tried["real"] and tried["fake"]:
        capture_flag(session, ENUM_FLAG)
        flag_captured = ENUM_FLAG
        msg += ("<br><br><span class='muted'>Notice the message differs depending on whether "
                "the username exists — that difference is the vulnerability. An attacker can "
                "enumerate every valid username on the system this way.</span>")

    body = f'<div class="panel"><p>{msg}</p><p><a href="/play/a07_authentication_failures/">&larr; Back</a></p></div>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a07_authentication_failures",
    owasp_id="A07:2025",
    title="Authentication Failures",
    difficulty="Beginner",
    tagline="No lockout on repeated failed logins, plus a forgot-password flow that reveals valid usernames.",
    objective_md="""
**Goal 1:** the login form has no lockout, rate limit, delay, or CAPTCHA —
brute-force a login for user `bob` (try common/weak passwords) after at
least 5 failed attempts to prove there's no protection kicking in.

**Goal 2:** the "forgot password" flow responds differently depending on
whether a username exists or not. Try one real username (`alice`, `bob`,
or `admin`) and one made-up one to spot the difference.
""",
    hints_md="""
- For brute force: try common weak passwords repeatedly against username
  `bob` — nothing will stop you, that's the point. A real weak password is
  seeded for this account.
- For enumeration: try `admin` (exists) and something like `notarealuser123`
  (doesn't) via the forgot-password form and compare the exact wording of
  each response.
""",
    fix_md="""
**Root cause (brute force):** no account lockout, exponential backoff,
rate limiting, or CAPTCHA after repeated failed attempts.

**Root cause (enumeration):** the forgot-password response text directly
reveals whether a username exists in the system.

**Fixes:**
- Add account lockout/rate limiting after N failed attempts (with care to
  avoid enabling a denial-of-service lockout attack against victims), plus
  CAPTCHA and monitoring/alerting on repeated failures.
- Return an identical response regardless of whether the account exists —
  "If an account exists for that address, a reset link has been sent" —
  every time, with the same timing.
- Consider multi-factor authentication so a leaked/guessed password alone
  isn't sufficient.
""",
    flag_id=BRUTEFORCE_FLAG,
    router=router,
)
