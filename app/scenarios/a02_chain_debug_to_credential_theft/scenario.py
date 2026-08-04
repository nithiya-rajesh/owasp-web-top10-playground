from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{CHAIN_debug_leak_to_credential_theft}"

router = APIRouter()

BACKUP_ADMIN_PASSWORD = "Br0nz3-Falcon-77"


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = """
    <div class="panel">
      <h3>Step 1</h3>
      <p>This service has a leftover debug endpoint somewhere. Find it.</p>
    </div>
    <div class="panel">
      <h3>Step 2: internal admin login</h3>
      <form method="post" action="/play/a02_chain_debug_to_credential_theft/internal-login">
        <label>Username</label>
        <input name="username" value="admin">
        <label>Password</label>
        <input name="password" type="password">
        <button type="submit">Log in</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.get("/debug/config", response_class=HTMLResponse)
def debug_config(request: Request, response: Response):
    session = get_or_create_session(request)
    session["chain_debug_found"] = True
    body = f"""
    <div class="panel">
      <h3>⚠️ Debug config dump</h3>
      <pre class="mono" style="background:var(--panel-2);padding:12px;border-radius:8px;">
ENVIRONMENT=staging
BACKUP_ADMIN_USER=admin
BACKUP_ADMIN_PASSWORD={BACKUP_ADMIN_PASSWORD}
LAST_ROTATED=never
      </pre>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/internal-login", response_class=HTMLResponse)
def internal_login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    session = get_or_create_session(request)
    flag_captured = None

    if username == "admin" and password == BACKUP_ADMIN_PASSWORD:
        if session.get("chain_debug_found"):
            capture_flag(session, FLAG)
            flag_captured = FLAG
        body = "<div class='panel'><p>✅ Logged in to the internal admin panel.</p></div>"
    else:
        body = "<div class='panel'><p>Login failed.</p></div>"

    body += '<p><a href="/play/a02_chain_debug_to_credential_theft/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a02_chain_debug_to_credential_theft",
    owasp_id="A02:2025",
    title="Chained Exploit: Debug Leak to Credential Theft",
    difficulty="Advanced",
    tagline="Find a leftover debug endpoint that leaks a backup admin password, then use it to log into a separate internal panel.",
    objective_md="""
Two steps here.

**Step 1:** find a leftover debug/diagnostic endpoint on this service —
try common paths (this is the same category of finding as the standalone
Security Misconfiguration scenario, but the payoff is different here).

**Step 2:** use whatever credential it leaks to log into the separate
"internal admin login" form.
""",
    hints_md="""
- Try `/debug/config` under this scenario's URL.
- The leaked config includes a backup admin username and password — use
  those exact values in the internal login form.
""",
    fix_md="""
**Root cause:** a leftover debug endpoint leaks a real, currently-valid
credential (not just abstract "config details") — and that credential
provides direct access to a separate, sensitive login surface. The chain
is what turns an information-disclosure bug into full unauthorized access.

**Fixes:**
- Remove debug endpoints from any deployment reachable outside a fully
  trusted internal network — the fix for the underlying misconfiguration
  is the same as the standalone scenario.
- Never store real, live credentials in any config dump reachable by an
  endpoint, debug or otherwise — use a secrets manager with short-lived,
  scoped credentials instead.
- Treat "backup"/break-glass credentials with the same rotation and
  monitoring discipline as primary ones — a credential that's "never
  rotated" is a standing risk regardless of how it's stored.
""",
    flag_id=FLAG,
    router=router,
)
