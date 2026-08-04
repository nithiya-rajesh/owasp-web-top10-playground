import json
from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A08_integrity_failure_unsigned_settings_restore}"

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    role = session.get("a08_role", "customer")
    settings = {"username": "alice", "role": role, "theme": "dark"}
    settings_json = json.dumps(settings, indent=2)

    body = f"""
    <div class="panel">
      <p>Current role: <b>{role}</b></p>
      <h3>Export settings</h3>
      <pre class="mono" style="background:var(--panel-2);padding:12px;border-radius:8px;">{settings_json}</pre>
      <p class="muted">Notice: no signature, checksum, or HMAC accompanies this export — nothing
      proves it hasn't been tampered with when it comes back in.</p>
    </div>
    <div class="panel">
      <h3>Restore settings</h3>
      <form method="post" action="/play/a08_software_data_integrity/restore">
        <label>Paste settings JSON to restore</label>
        <textarea name="settings_json" rows="6">{settings_json}</textarea>
        <button type="submit">Restore</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/restore", response_class=HTMLResponse)
def restore(request: Request, response: Response, settings_json: str = Form(...)):
    session = get_or_create_session(request)
    flag_captured = None

    try:
        data = json.loads(settings_json)
    except json.JSONDecodeError as e:
        body = f'<div class="panel">Invalid JSON: {e}</div>'
        return page(SCENARIO, session, body)

    # VULNERABLE: the restored data is applied directly with no signature/
    # HMAC verification that it matches what was actually exported earlier
    # — a client can freely edit "role" before restoring.
    new_role = data.get("role", "customer")
    session["a08_role"] = new_role

    if new_role == "admin":
        capture_flag(session, FLAG)
        flag_captured = FLAG
        body = """
        <div class="panel">
          <p>✅ Role restored as <b>admin</b> — with no integrity check catching the
          edited field. In a real app this is how an attacker escalates
          privileges via a "backup" or "import" feature that trusts its
          input.</p>
        </div>"""
    else:
        body = f'<div class="panel"><p>Settings restored. Role is now "{new_role}".</p></div>'

    body += '<p><a href="/play/a08_software_data_integrity/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a08_software_data_integrity",
    owasp_id="A08:2025",
    title="Software or Data Integrity Failures",
    difficulty="Intermediate",
    tagline="A settings restore feature applies uploaded JSON with no signature/integrity check.",
    objective_md="""
The settings export/restore feature round-trips your account settings as
plain JSON with no signature, checksum, or HMAC protecting it from
tampering.

**Your goal:** edit the exported JSON to change `"role"` to `"admin"`,
then submit it through the restore form.
""",
    hints_md="""
- Copy the exported JSON, change the `role` field from `customer` to
  `admin` in the restore textarea, and submit.
- Nothing checks that the JSON you're submitting matches what was actually
  issued to you earlier.
""",
    fix_md="""
**Root cause:** the restore endpoint trusts submitted data as authoritative
with no cryptographic integrity check (HMAC/signature) tying it back to
what was actually exported for that user, and no server-side authorization
check on privilege-affecting fields like `role`.

**Fixes:**
- Sign exported data with an HMAC (or similar) using a server-held secret,
  and verify that signature before trusting any restored data.
- Never let a "restore" or "import" flow set privilege-sensitive fields
  (role, permissions, account flags) directly from client-supplied data —
  those changes should go through a separate, authorized, audited path.
- Treat any deserialization of client-supplied data as untrusted input,
  validated field-by-field against an explicit allowlist/schema.
""",
    flag_id=FLAG,
    router=router,
)
