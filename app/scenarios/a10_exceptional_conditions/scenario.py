from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A10_exceptional_conditions_fail_open}"

router = APIRouter()

PRIVATE_NOTES = {
    1: "Alice's private notes: reminder — renew passport in March.",
    2: "Bob's private notes: gate code is 4471, don't share.",
}

CURRENT_USER_ID = 1  # pretend "you" are always logged in as user 1 (alice) in this lab


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = f"""
    <div class="panel">
      <p>You're logged in as user_id={CURRENT_USER_ID} (alice). Private notes are
      supposed to be viewable only by their owner.</p>
      <form method="get" action="/play/a10_exceptional_conditions/notes">
        <label>View private notes for user_id</label>
        <input name="user_id" value="{CURRENT_USER_ID}">
        <button type="submit">View</button>
      </form>
      <p class="muted" style="margin-top:10px;">Try a non-numeric value in that field.</p>
    </div>"""
    return page(SCENARIO, session, body)


@router.get("/notes", response_class=HTMLResponse)
def notes(request: Request, response: Response, user_id: str = ""):
    session = get_or_create_session(request)
    flag_captured = None

    try:
        target_id = int(user_id)
        allowed = target_id == CURRENT_USER_ID
    except ValueError:
        # VULNERABLE: the exception handler "fails open" instead of denying
        # access — a malformed (non-numeric) input bypasses the ownership
        # check entirely instead of being safely rejected.
        allowed = True
        target_id = None

    if not allowed:
        body = '<div class="panel">🚫 Access denied — these notes belong to someone else.</div>'
        return page(SCENARIO, session, body)

    if target_id is None:
        capture_flag(session, FLAG)
        flag_captured = FLAG
        shown = "<br>".join(f"user {uid}: {note}" for uid, note in PRIVATE_NOTES.items())
        body = f"""
        <div class="panel">
          <p>⚠️ Malformed input triggered the exception handler, which granted
          access instead of denying it. All private notes leaked:</p>
          <pre class="mono" style="background:var(--panel-2);padding:12px;border-radius:8px;">{shown}</pre>
        </div>"""
    else:
        body = f'<div class="panel">{PRIVATE_NOTES.get(target_id, "No notes for that user.")}</div>'

    body += '<p><a href="/play/a10_exceptional_conditions/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a10_exceptional_conditions",
    owasp_id="A10:2025",
    title="Mishandling of Exceptional Conditions",
    difficulty="Advanced",
    tagline="An authorization check 'fails open' when malformed input triggers an unhandled exception path.",
    objective_md="""
The "view private notes" feature checks that the requested `user_id`
matches your own before showing anything. But look at what happens if you
give it something that isn't a plain number.

**Your goal:** submit a non-numeric value for `user_id` and see what the
exception-handling path actually does.
""",
    hints_md="""
- Try letters instead of a number, e.g. `abc`, in the "View private notes
  for user_id" field.
- Think about what a `try/except` block *does* when the code inside it
  throws — does every possible except branch actually deny access, or
  could one accidentally allow it instead?
""",
    fix_md="""
**Root cause:** the authorization check is wrapped in a `try/except` where
the exception path defaults to `allowed = True` instead of `False` — any
input that causes an exception (rather than a clean true/false comparison)
accidentally bypasses the entire check.

**Fixes:**
- Default to deny on any exception in an authorization path — fail closed,
  never fail open. If parsing/validation fails, that's an automatic denial,
  not a shortcut to "allowed."
- Validate and type-check input BEFORE it reaches authorization logic
  (e.g. reject non-numeric IDs outright with a 400, rather than letting a
  parse failure fall through into business logic).
- Add tests specifically for the exception/edge-case paths of every
  authorization check, not just the "happy path" where input is well-formed.
""",
    flag_id=FLAG,
    router=router,
)
