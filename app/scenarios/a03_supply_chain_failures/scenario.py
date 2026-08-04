from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A03_supply_chain_malicious_extension}"

router = APIRouter()

EXTENSIONS = {
    "pricetracker-pro": {
        "name": "PriceTracker Pro",
        "publisher": "Verified Partner Co.",
        "verified": True,
        "description": "Tracks price history on product pages.",
    },
    "pricetracker-pr0": {  # typosquat: zero instead of "o"
        "name": "PriceTracker Pro",
        "publisher": "unverified-uploader-xj29",
        "verified": False,
        "description": (
            "Tracks price history on product pages. Also silently reads "
            "and forwards your session cookies to an external analytics "
            "endpoint on every page load — not disclosed anywhere in the "
            "listing itself."
        ),
    },
}


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    rows = ""
    for ext_id, ext in EXTENSIONS.items():
        badge = "✅ Verified publisher" if ext["verified"] else "⚠️ Unverified uploader"
        rows += f"""
        <div class="panel">
          <h3 style="margin:0 0 4px;">{ext['name']} <span class="muted mono" style="font-size:11px;">({ext_id})</span></h3>
          <p class="muted" style="margin:4px 0;">{badge} — {ext['publisher']}</p>
          <p>{ext['description']}</p>
          <form method="post" action="/play/a03_supply_chain_failures/install/{ext_id}">
            <button type="submit">Install</button>
          </form>
        </div>"""

    body = f"""
    <div class="panel">
      <p>Extension marketplace. Two listings both call themselves "PriceTracker
      Pro" — look closely at the ID and publisher before installing.</p>
    </div>
    {rows}"""
    return page(SCENARIO, session, body)


@router.post("/install/{ext_id}", response_class=HTMLResponse)
def install(ext_id: str, request: Request, response: Response):
    session = get_or_create_session(request)
    ext = EXTENSIONS.get(ext_id)
    flag_captured = None

    if ext is None:
        body = '<div class="panel">Unknown extension.</div>'
    elif not ext["verified"]:
        capture_flag(session, FLAG)
        flag_captured = FLAG
        body = f"""
        <div class="panel">
          <p><b>Installed "{ext['name']}" from unverified publisher "{ext['publisher']}".</b></p>
          <p>{ext['description']}</p>
          <p class="muted">This is exactly how a real typosquatted extension/package compromises
          users — near-identical name, no publisher verification, buried
          malicious behavior in a wall of description text.</p>
        </div>"""
    else:
        body = f'<div class="panel">Installed "{ext["name"]}" from verified publisher "{ext["publisher"]}". Looks fine.</div>'

    body += '<p><a href="/play/a03_supply_chain_failures/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a03_supply_chain_failures",
    owasp_id="A03:2025",
    title="Supply Chain Failures",
    difficulty="Intermediate",
    tagline="Two near-identical extensions in the marketplace — one is a typosquat from an unverified uploader.",
    objective_md="""
This mini extension marketplace lists two entries that both call
themselves "PriceTracker Pro." One is from a verified publisher; the other
is a typosquat from an unverified uploader with quietly malicious behavior
buried in its description.

**Your goal:** identify and install the malicious one.
""",
    hints_md="""
- Compare the two listings' IDs character by character.
- Check the publisher field, not just the display name.
- Read the full description text on each — the malicious one discloses
  its bad behavior, just easy to skim past.
""",
    fix_md="""
**Root cause:** the marketplace has no publisher verification requirement
and no protection against near-identical (typosquatted) listing names,
letting a malicious upload sit right next to the legitimate one.

**Fixes:**
- Require verified publisher identity for anything installable, and
  visually distinguish unverified listings clearly (not just a small badge).
- Detect and block typosquatted names/IDs against existing verified listings.
- Sandbox extension permissions (e.g. cookie/session access) behind
  explicit, itemized user consent rather than blanket installation.
""",
    flag_id=FLAG,
    router=router,
)
