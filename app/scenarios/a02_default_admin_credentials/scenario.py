from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A02_default_admin_credentials}"

router = APIRouter()

# VULNERABLE: these were the factory-default credentials, and nobody ever
# changed them after deployment — an extremely common real-world finding.
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin123"


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = """
    <div class="panel">
      <p>This is the admin panel for a device management dashboard.</p>
      <form method="post" action="/play/a02_default_admin_credentials/login">
        <label>Username</label>
        <input name="username" placeholder="admin">
        <label>Password</label>
        <input name="password" type="password">
        <button type="submit">Log in</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/login", response_class=HTMLResponse)
def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    session = get_or_create_session(request)
    flag_captured = None

    if username == DEFAULT_USERNAME and password == DEFAULT_PASSWORD:
        capture_flag(session, FLAG)
        flag_captured = FLAG
        body = """
        <div class="panel">
          <p>✅ Logged in as admin — using the factory-default credentials that
          were never changed after this device/dashboard was deployed.</p>
        </div>"""
    else:
        body = '<div class="panel"><p>Login failed.</p></div>'

    body += '<p><a href="/play/a02_default_admin_credentials/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a02_default_admin_credentials",
    owasp_id="A02:2025",
    title="Default Admin Credentials",
    difficulty="Beginner",
    tagline="This admin dashboard's factory-default login was never changed after deployment.",
    objective_md="""
This is a device management admin panel. It was deployed with a
factory-default username and password — and nobody ever changed them.

**Your goal:** log in as admin using well-known default credentials.
""",
    hints_md="""
- Try `admin` / `admin123` — one of the most common factory-default
  combinations still found in real deployments.
- If that doesn't work, common defaults worth trying: `admin`/`admin`,
  `admin`/`password`, `admin`/`changeme`.
""",
    fix_md="""
**Root cause:** the device/dashboard shipped with a default username and
password, and no step in deployment forced an administrator to change
them before going live.

**Fixes:**
- Never ship a product with a static default credential — require a
  mandatory password change (or full account setup) on first boot/login
  before any functionality is usable.
- Regularly scan production systems for known default credentials as part
  of routine security hygiene.
- Enforce strong password policies and multi-factor authentication for
  any administrative access.
""",
    flag_id=FLAG,
    router=router,
)
