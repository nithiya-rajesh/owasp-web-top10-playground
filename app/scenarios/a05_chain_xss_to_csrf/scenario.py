import re
from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{CHAIN_xss_triggers_csrf_account_takeover}"

router = APIRouter()

_COMMENTS: list[str] = []
_VICTIM_ACCOUNT = {"email": "victim-original@example.com"}


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = f"""
    <div class="panel">
      <h3>Step 1: post a comment (rendered completely unescaped)</h3>
      <form method="post" action="/play/a05_chain_xss_to_csrf/comment">
        <textarea name="comment" rows="3" placeholder="Great product!"></textarea>
        <button type="submit">Post</button>
      </form>
    </div>
    <div class="panel">
      <h3>Step 2: simulate a victim viewing the comments page</h3>
      <p>Victim's current email: <b>{_VICTIM_ACCOUNT['email']}</b></p>
      <p><a href="/play/a05_chain_xss_to_csrf/victim-view">Simulate victim opening this page &rarr;</a></p>
      <p class="muted">There's no CSRF token protecting the email-change endpoint this
      account uses — if your comment could make the victim's browser call it
      automatically, it would just work.</p>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/comment", response_class=HTMLResponse)
def post_comment(request: Request, response: Response, comment: str = Form(...)):
    session = get_or_create_session(request)
    _COMMENTS.append(comment)
    body = '<div class="panel"><p>Comment posted.</p></div>'
    body += '<p><a href="/play/a05_chain_xss_to_csrf/">&larr; Back</a></p>'
    return page(SCENARIO, session, body)


@router.get("/victim-view", response_class=HTMLResponse)
def victim_view(request: Request, response: Response):
    session = get_or_create_session(request)
    flag_captured = None

    rendered = "".join(f'<div class="panel" style="padding:10px;">{c}</div>' for c in _COMMENTS)

    # Simulates a victim's browser rendering these comments unescaped. If a
    # comment embeds a script that would call the (CSRF-token-less)
    # change-email endpoint, we treat that as "the victim's browser just
    # executed it" — the same effect a real un-sandboxed render would have.
    for c in _COMMENTS:
        match = re.search(r"change-email[^\"'<>]*email=([^\"'&<> ]+)", c, re.IGNORECASE)
        if match:
            new_email = match.group(1)
            _VICTIM_ACCOUNT["email"] = new_email
            capture_flag(session, FLAG)
            flag_captured = FLAG

    body = f"""
    <div class="panel">
      <p>Victim's email is now: <b>{_VICTIM_ACCOUNT['email']}</b></p>
    </div>
    <h3>Comments (as the victim would see them)</h3>
    {rendered if rendered else '<p class="muted">No comments yet.</p>'}
    """
    body += '<p><a href="/play/a05_chain_xss_to_csrf/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a05_chain_xss_to_csrf",
    owasp_id="A05:2025",
    title="Chained Exploit: Stored XSS to CSRF Account Takeover",
    difficulty="Advanced",
    tagline="A stored XSS payload can silently trigger a CSRF-vulnerable account action the moment a victim views the page.",
    objective_md="""
This comments feature is vulnerable to stored XSS (same root cause as the
standalone Injection scenario). Separately, the victim account's
email-change action has no CSRF protection.

**Your goal:** post a comment that, when the "victim" views the page,
automatically changes the victim's email address to one you control —
without the victim ever intending to do that.
""",
    hints_md="""
- Your comment needs to reference something like `change-email` and
  `email=your-address` — think of it as embedding a request the victim's
  browser would make automatically upon loading the page, e.g.:
  `<script>fetch('/change-email?email=attacker@evil.example')</script>`
- After posting, click "Simulate victim opening this page" to see whether
  it actually took effect.
""",
    fix_md="""
**Root cause:** two separate bugs combine — stored XSS lets an attacker
run arbitrary script in another user's browser session, and a missing
CSRF token on the email-change action means any request that reaches it
(including one fired automatically by an XSS payload) succeeds with no
proof the real user intended it.

**Fixes:**
- Fix the XSS at the source: escape all user-generated content before
  rendering, exactly as in the standalone Injection scenario.
- Add CSRF tokens (or require re-authentication) for any sensitive
  account-changing action, so even a successfully-injected script can't
  silently trigger it.
- Recognize that XSS effectively defeats most CSRF protections that rely
  purely on cookies anyway (since injected script runs with the victim's
  full session) — this is exactly why defense-in-depth across both
  vulnerability classes matters, not just fixing one.
""",
    flag_id=FLAG,
    router=router,
)
