from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A07_session_fixation_no_rotation}"

router = APIRouter()

# Deliberately a SEPARATE cookie from the app's main "session_id" (which is
# used app-wide for flag tracking and has its own, stricter handling).
# This scenario needs to demonstrate a server that accepts an arbitrary
# client-chosen ID and just starts using it — that's the vulnerability
# itself, so it can't share the main session store's validation logic.
DEMO_COOKIE = "demo_sid"
_FIXATION_STORE: dict[str, dict] = {}


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = """
    <div class="panel">
      <p>An attacker can plant their own session ID in a victim's browser
      (e.g. via a crafted link) <i>before</i> the victim logs in. If the app
      doesn't issue a fresh session ID after login, the attacker's
      pre-chosen ID becomes valid too.</p>
      <p><a href="/play/a07_session_fixation/set-session?sid=attacker-chosen-123">
        Simulate: set a custom session ID (like a victim clicking an attacker's link) &rarr;
      </a></p>
    </div>"""
    return page(SCENARIO, session, body)


@router.get("/set-session", response_class=HTMLResponse)
def set_session(request: Request, sid: str = "attacker-chosen-123"):
    # VULNERABLE step 1: the app accepts and sets whatever session ID value
    # is supplied via the URL, with no validation that it originated from
    # this server, and registers it immediately.
    _FIXATION_STORE.setdefault(sid, {"logged_in_user": None})
    resp = RedirectResponse("/play/a07_session_fixation/login", status_code=302)
    resp.set_cookie(DEMO_COOKIE, sid, httponly=True, samesite="lax")
    return resp


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, response: Response):
    session = get_or_create_session(request)
    sid = request.cookies.get(DEMO_COOKIE, "(none)")
    body = f"""
    <div class="panel">
      <p>Your current demo session ID (cookie): <code>{sid}</code></p>
      <form method="post" action="/play/a07_session_fixation/do-login">
        <label>Username</label>
        <input name="username" value="victim">
        <button type="submit">Log in</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/do-login", response_class=HTMLResponse)
def do_login(request: Request, response: Response, username: str = Form(...)):
    session = get_or_create_session(request)
    sid_before = request.cookies.get(DEMO_COOKIE, "")

    # VULNERABLE step 2: login succeeds, but the SAME demo session ID
    # continues to be used afterward — it's never rotated/regenerated
    # post-auth. If that ID was attacker-chosen (fixated), the attacker's
    # copy of it is now also a valid, logged-in session.
    _FIXATION_STORE.setdefault(sid_before, {})["logged_in_user"] = username

    flag_captured = None
    if sid_before == "attacker-chosen-123":
        capture_flag(session, FLAG)
        flag_captured = FLAG

    body = f"""
    <div class="panel">
      <p>✅ Logged in as <b>{username}</b>. Demo session ID after login: <code>{sid_before}</code></p>
      <p class="muted">Notice the session ID is exactly the same as before login —
      it was never rotated. If this ID had been planted by an attacker
      beforehand, their copy of it is now authenticated too.</p>
    </div>"""
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a07_session_fixation",
    owasp_id="A07:2025",
    title="Session Fixation",
    difficulty="Intermediate",
    tagline="The app accepts an attacker-supplied session ID before login and never rotates it afterward.",
    objective_md="""
This app will happily set your session cookie to whatever value a URL
tells it to — simulating an attacker planting a session ID in a victim's
browser via a crafted link, before the victim ever logs in.

**Your goal:** use the "set a custom session ID" link to plant a
known/fixed session ID, then log in, and confirm the app keeps using that
exact same ID afterward instead of issuing a fresh one.
""",
    hints_md="""
- Click the "simulate" link on the objective page — this plants
  `attacker-chosen-123` as your session ID before you've logged in.
- Then complete the login form. Check whether the session ID shown after
  login is still `attacker-chosen-123`.
""",
    fix_md="""
**Root cause:** the app trusts a client-supplied session identifier before
authentication, and never regenerates the session ID at the moment of
successful login — so a pre-planted (fixated) ID remains valid
post-authentication.

**Fixes:**
- Always issue a brand-new, server-generated session ID immediately after
  successful authentication, invalidating whatever ID (if any) existed
  beforehand.
- Never accept a client-supplied value as a session identifier before
  authentication has occurred.
- Set session cookies with `HttpOnly`, `Secure`, and `SameSite` attributes
  as defense-in-depth, though session ID rotation is the actual fix here.
""",
    flag_id=FLAG,
    router=router,
)
