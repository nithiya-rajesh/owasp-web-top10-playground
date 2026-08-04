from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A04_predictable_session_tokens}"

router = APIRouter()

# VULNERABLE: sequential, predictable "session tokens" instead of
# cryptographically random ones. Shared module-level state simulates a
# real backend's session store across "logins."
_ACTIVE_SESSIONS = {"sess_1000": {"username": "bob", "balance": 4200.00}}
_counter = 1000


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = """
    <div class="panel">
      <p>Log in below. Notice the pattern in the session token you get back.</p>
      <form method="post" action="/play/a04_predictable_session_tokens/login">
        <label>Username</label>
        <input name="username" value="alice">
        <button type="submit">Log in</button>
      </form>
    </div>
    <div class="panel">
      <h3>Access account by session token</h3>
      <form method="get" action="/play/a04_predictable_session_tokens/account">
        <label>Session token</label>
        <input name="token" placeholder="sess_1000">
        <button type="submit">View account</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/login", response_class=HTMLResponse)
def login(request: Request, response: Response, username: str = Form(...)):
    global _counter
    session = get_or_create_session(request)
    _counter += 1
    token = f"sess_{_counter}"
    _ACTIVE_SESSIONS[token] = {"username": username, "balance": 1000.00}
    session["a04_own_token"] = token

    body = f"""
    <div class="panel">
      <p>Logged in as <b>{username}</b>. Your session token: <code>{token}</code></p>
      <p class="muted">Notice this is just an incrementing counter, not a
      cryptographically random value — what does that let you try?</p>
    </div>"""
    return page(SCENARIO, session, body)


@router.get("/account", response_class=HTMLResponse)
def account(request: Request, response: Response, token: str = ""):
    session = get_or_create_session(request)
    flag_captured = None

    record = _ACTIVE_SESSIONS.get(token)
    if not record:
        body = '<div class="panel"><p>No active session with that token.</p></div>'
        return page(SCENARIO, session, body)

    # VULNERABLE: no check that the token belongs to the current caller —
    # combined with predictable tokens, guessing/incrementing a nearby
    # token number grants access to someone else's account.
    own_token = session.get("a04_own_token")
    if token != own_token:
        capture_flag(session, FLAG)
        flag_captured = FLAG

    body = f"""
    <div class="panel">
      <p>Account for <b>{record['username']}</b>: balance ${record['balance']:.2f}</p>
    </div>"""
    body += '<p><a href="/play/a04_predictable_session_tokens/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a04_predictable_session_tokens",
    owasp_id="A04:2025",
    title="Predictable Session Tokens",
    difficulty="Intermediate",
    tagline="Session tokens are just an incrementing counter — log in once, then guess someone else's token.",
    objective_md="""
There's already one active session on this server: `sess_1000` (a user
named "bob"). When you log in, notice your own token is just the next
number in sequence — not a random value.

**Your goal:** log in once to see the pattern, then access the
pre-existing `sess_1000` session (or any token that isn't your own)
without ever having logged in as that user.
""",
    hints_md="""
- Log in and note your token, e.g. `sess_1001`.
- Try accessing account info with `sess_1000` directly — that session
  already existed before you logged in.
- Try a few nearby numbers too, in case others have logged in around the
  same time.
""",
    fix_md="""
**Root cause:** session tokens are generated from a predictable,
sequential counter instead of a cryptographically secure random value —
knowing (or guessing) any one token trivially reveals nearby valid tokens.

**Fixes:**
- Generate session tokens using a cryptographically secure random number
  generator with sufficient entropy (128+ bits) — never sequential IDs,
  timestamps, or anything else guessable.
- Bind sessions to additional context (IP address consistency, user-agent)
  as defense-in-depth, though this should never be the only protection.
- Rotate/expire tokens aggressively and monitor for anomalous sequential
  access patterns as a detection signal.
""",
    flag_id=FLAG,
    router=router,
)
