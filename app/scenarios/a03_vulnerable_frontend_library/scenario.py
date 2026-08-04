from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A03_vulnerable_frontend_library_no_sri}"

router = APIRouter()

VULNERABLE_LIB = "jquery"
VULNERABLE_VERSION = "1.6.1"  # a real, publicly known old jQuery version with disclosed XSS-class CVEs


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = f"""
    <div class="panel">
      <p>This page's source loads a frontend library with no Subresource
      Integrity (SRI) hash — view the page source and find the outdated,
      known-vulnerable library and its exact version.</p>
      <!-- vendored library, no integrity="..." attribute set -->
      <!-- <script src="/static/vendor/{VULNERABLE_LIB}-{VULNERABLE_VERSION}.min.js"></script> -->
      <form method="post" action="/play/a03_vulnerable_frontend_library/report">
        <label>Library name</label>
        <input name="library" placeholder="e.g. jquery">
        <label>Version</label>
        <input name="version" placeholder="e.g. 1.6.1">
        <button type="submit">Report vulnerable dependency</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/report", response_class=HTMLResponse)
def report(request: Request, response: Response, library: str = Form(...), version: str = Form(...)):
    session = get_or_create_session(request)
    flag_captured = None

    if library.strip().lower() == VULNERABLE_LIB and version.strip() == VULNERABLE_VERSION:
        capture_flag(session, FLAG)
        flag_captured = FLAG
        body = f"""
        <div class="panel">
          <p>✅ Correct! This page loads {VULNERABLE_LIB} {VULNERABLE_VERSION} — an old
          version with publicly disclosed vulnerabilities — with no
          Subresource Integrity hash and no version-pinning review process.</p>
        </div>"""
    else:
        body = '<div class="panel"><p>Not quite — check the page source (view-source) for the exact vendored library and version.</p></div>'

    body += '<p><a href="/play/a03_vulnerable_frontend_library/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a03_vulnerable_frontend_library",
    owasp_id="A03:2025",
    title="Vulnerable Frontend Library",
    difficulty="Beginner",
    tagline="An outdated JS library with known CVEs is vendored in with no integrity check and no version review.",
    objective_md="""
This page loads a vendored frontend library — check the page source
(right-click → View Page Source, or Ctrl+U) for the exact script
reference.

**Your goal:** identify the library name and version being loaded, then
report it.
""",
    hints_md="""
- View the raw page source (not the rendered page) — the script reference
  is in an HTML comment near the top of the body content.
- Report the library name in lowercase and the exact version number shown.
""",
    fix_md="""
**Root cause:** a known-outdated frontend library with disclosed CVEs is
vendored into the page with no Subresource Integrity (SRI) hash and no
process for tracking/updating pinned dependency versions.

**Fixes:**
- Maintain an inventory of every frontend dependency and its version;
  monitor it against known-vulnerability databases (npm audit, Snyk, etc.).
- Use Subresource Integrity hashes on any externally-hosted script, so a
  tampered or substituted file fails to load rather than executing silently.
- Automate dependency update checks as part of CI, not as a manual,
  easily-forgotten step.
""",
    flag_id=FLAG,
    router=router,
)
