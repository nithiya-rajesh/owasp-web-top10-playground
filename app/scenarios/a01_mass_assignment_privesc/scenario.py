from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A01_mass_assignment_privilege_escalation}"

router = APIRouter()

PROFILE = {"name": "Alice", "email": "alice@example.com", "role": "customer"}


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = f"""
    <div class="panel">
      <p>Current profile: <b>{PROFILE['name']}</b> ({PROFILE['email']}), role: <b>{PROFILE['role']}</b></p>
      <form method="post" action="/play/a01_mass_assignment_privesc/update-profile">
        <label>Name</label>
        <input name="name" value="{PROFILE['name']}">
        <label>Email</label>
        <input name="email" value="{PROFILE['email']}">
        <button type="submit">Update profile</button>
      </form>
      <p class="muted" style="margin-top:10px;">This form only shows name/email — but what does the server actually accept?</p>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/update-profile", response_class=HTMLResponse)
def update_profile(request: Request, response: Response, name: str = Form(...), email: str = Form(...), role: str = Form(None)):
    session = get_or_create_session(request)
    flag_captured = None

    # VULNERABLE: mass assignment — the server blindly applies every field
    # it receives, including "role", which the form never exposes but the
    # backend never explicitly excludes either.
    PROFILE["name"] = name
    PROFILE["email"] = email
    if role is not None:
        PROFILE["role"] = role

    if PROFILE["role"] == "admin":
        capture_flag(session, FLAG)
        flag_captured = FLAG

    body = f'<div class="panel"><p>Profile updated. Role is now: <b>{PROFILE["role"]}</b></p></div>'
    body += '<p><a href="/play/a01_mass_assignment_privesc/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a01_mass_assignment_privesc",
    owasp_id="A01:2025",
    title="Mass Assignment Privilege Escalation",
    difficulty="Beginner",
    tagline="The profile form only shows name/email — but the server accepts any field you send it, including role.",
    objective_md="""
This profile-update endpoint only exposes `name` and `email` in its form.

**Your goal:** send a request that also includes a `role` field set to
`admin`, and get the server to apply it — even though the form never
offered that option.
""",
    hints_md="""
- The visible form only has two fields, but that doesn't mean the server
  only accepts two fields.
- Try crafting a raw request (e.g. with `curl`) that includes an extra
  `role=admin` field alongside `name` and `email`.
""",
    fix_md="""
**Root cause:** the backend applies every field in the incoming request
directly to the underlying record ("mass assignment") instead of
explicitly allowlisting which fields a given endpoint is permitted to
update.

**Fixes:**
- Use an explicit allowlist (or a schema that only defines the fields a
  given operation should accept) for every write operation — never apply
  a raw request body directly to a data model.
- Treat privilege-affecting fields (role, permissions, account flags) as
  requiring a completely separate, authorized code path, never bundled
  into a general-purpose "update profile" endpoint.
""",
    flag_id=FLAG,
    router=router,
)
