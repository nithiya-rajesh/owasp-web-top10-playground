import re
from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A08_unverified_package_source_role_grant}"

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    role = session.get("a08b_role", "customer")
    body = f"""
    <div class="panel">
      <p>Current role: <b>{role}</b></p>
      <p>Install a plugin by providing its manifest source URL. There's no
      signature or publisher verification on the manifest content.</p>
      <form method="post" action="/play/a08_unverified_update_source/install">
        <label>Plugin manifest URL</label>
        <input name="url" placeholder="http://plugins.example.com/manifest?...">
        <button type="submit">Install</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/install", response_class=HTMLResponse)
def install(request: Request, response: Response, url: str = Form(...)):
    session = get_or_create_session(request)
    flag_captured = None

    # VULNERABLE: the "manifest" is derived directly from attacker-supplied
    # URL content with no signature/checksum verification against a known
    # publisher — here simulated by parsing a grant=... parameter straight
    # out of the URL and applying it directly.
    match = re.search(r"grant=([a-zA-Z0-9_]+)", url)
    if match:
        session["a08b_role"] = match.group(1)

    new_role = session.get("a08b_role", "customer")
    if new_role == "admin":
        capture_flag(session, FLAG)
        flag_captured = FLAG
        body = f"""
        <div class="panel">
          <p>✅ Plugin "installed" from <code>{url}</code> — role is now <b>admin</b>,
          granted with zero signature or publisher verification on the
          manifest content.</p>
        </div>"""
    else:
        body = f'<div class="panel"><p>Plugin installed from {url}. Role: {new_role}</p></div>'

    body += '<p><a href="/play/a08_unverified_update_source/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a08_unverified_update_source",
    owasp_id="A08:2025",
    title="Unverified Package Source",
    difficulty="Intermediate",
    tagline="Plugin manifests are trusted with no signature or publisher verification — including who gets what role.",
    objective_md="""
This "install plugin from URL" feature fetches a manifest from wherever
you point it, with no signature or publisher verification.

**Your goal:** craft a manifest URL that grants your account the `admin`
role.
""",
    hints_md="""
- Try a URL like `http://my-plugin-host.example/manifest?grant=admin`
- The manifest content isn't independently verified against anything —
  whatever it claims gets applied.
""",
    fix_md="""
**Root cause:** package/plugin manifests are trusted and applied directly
with no cryptographic signature verification tying them to a known,
trusted publisher — the same class of issue as an unsigned software
update or a supply-chain-compromised dependency.

**Fixes:**
- Require every installable package/plugin to be signed by a verified
  publisher, and verify that signature before applying anything from its
  manifest.
- Never let a manifest directly set privilege-affecting fields (roles,
  permissions) — those changes should require a separate, authorized,
  audited path regardless of what any manifest claims.
- Maintain an allowlist of trusted manifest sources rather than accepting
  arbitrary URLs.
""",
    flag_id=FLAG,
    router=router,
)
