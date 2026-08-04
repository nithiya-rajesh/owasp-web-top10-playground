from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.core.db import get_connection
from app.scenarios.base import Scenario

FLAG = "FLAG{CHAIN_enumeration_to_targeted_bruteforce}"

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = """
    <div class="panel">
      <h3>Step 1: check if a username exists</h3>
      <form method="get" action="/play/a07_chain_enum_to_bruteforce/forgot-password">
        <label>Username</label>
        <input name="username" placeholder="try a few">
        <button type="submit">Check</button>
      </form>
    </div>
    <div class="panel">
      <h3>Step 2: log in (no lockout)</h3>
      <form method="post" action="/play/a07_chain_enum_to_bruteforce/login">
        <label>Username</label>
        <input name="username">
        <label>Password</label>
        <input name="password">
        <button type="submit">Log in</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password(request: Request, response: Response, username: str = ""):
    session = get_or_create_session(request)
    conn, lock = get_connection()
    with lock:
        row = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()

    if row:
        session["chain_enum_confirmed_username"] = username
        msg = f"A reset email has been sent for <b>{username}</b>."
    else:
        msg = f"No account found for <b>{username}</b>."

    body = f'<div class="panel"><p>{msg}</p></div>'
    body += '<p><a href="/play/a07_chain_enum_to_bruteforce/">&larr; Back</a></p>'
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
        # Flag requires the username to have been confirmed via the
        # enumeration step first — proving this was a targeted brute
        # force informed by Step 1, not just a lucky guess.
        if session.get("chain_enum_confirmed_username") == username:
            capture_flag(session, FLAG)
            flag_captured = FLAG
        body = f'<div class="panel"><p>✅ Logged in as <b>{row["username"]}</b>.</p></div>'
    else:
        body = '<div class="panel"><p>Login failed. No lockout — keep trying.</p></div>'

    body += '<p><a href="/play/a07_chain_enum_to_bruteforce/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a07_chain_enum_to_bruteforce",
    owasp_id="A07:2025",
    title="Chained Exploit: Enumeration to Targeted Brute Force",
    difficulty="Advanced",
    tagline="Use username enumeration to confirm a real account exists, then brute-force just that target.",
    objective_md="""
Two steps, using both authentication weaknesses together.

**Step 1:** use the forgot-password check to confirm which usernames
actually exist — the response differs for real vs fake accounts.

**Step 2:** take a *confirmed* username and brute-force its password (no
lockout protects this login form) — the flag requires that you actually
used Step 1's result to inform Step 2, not just gotten lucky.
""",
    hints_md="""
- Try usernames like `alice`, `bob`, `admin`, and a made-up one — compare
  the exact response wording each time.
- Once you've confirmed a real username, try common/weak passwords
  against exactly that username in the login form.
""",
    fix_md="""
**Root cause:** enumeration (a distinct-response forgot-password flow)
narrows an attacker's search space, and no-lockout brute force then lets
them exhaust that narrowed space with unlimited attempts — each bug is
bad alone, but chained they turn "guess a valid credential pair" into
"confirm a target, then just grind it."

**Fixes:**
- Fix both independently: identical forgot-password responses regardless
  of account existence, and real lockout/rate-limiting/CAPTCHA on login.
- Recognize that fixing only one of the two still leaves meaningful risk —
  enumeration without brute-force protection, or brute-force protection
  against a known-valid username, are each still exploitable on their own.
- Monitor for the *pattern* of enumeration-then-login-attempts from the
  same source as a detectable attack signature.
""",
    flag_id=FLAG,
    router=router,
)
