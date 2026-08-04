from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A09_no_audit_trail_privileged_action}"

router = APIRouter()

_AUDIT_LOG_V2: list[str] = []  # deliberately never written to below


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = """
    <div class="panel">
      <p>Admin action: promote a user to administrator.</p>
      <form method="post" action="/play/a09_no_audit_trail/promote">
        <label>User ID to promote</label>
        <input name="user_id" value="u_1002">
        <button type="submit">Promote to admin</button>
      </form>
      <p style="margin-top:10px;"><a href="/play/a09_no_audit_trail/audit-log">View audit log &rarr;</a></p>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/promote", response_class=HTMLResponse)
def promote(request: Request, response: Response, user_id: str = Form(...)):
    session = get_or_create_session(request)
    # VULNERABLE: a genuinely privileged, sensitive action (granting admin)
    # executes successfully with ZERO audit log entry written anywhere —
    # a missing-control issue, distinct from log forging (A09's other
    # scenario) where an entry exists but is falsified.
    session["a09b_promoted"] = user_id
    body = f'<div class="panel"><p>✅ User {user_id} promoted to admin.</p></div>'
    body += '<p><a href="/play/a09_no_audit_trail/audit-log">Now check the audit log &rarr;</a></p>'
    return page(SCENARIO, session, body)


@router.get("/audit-log", response_class=HTMLResponse)
def audit_log(request: Request, response: Response):
    session = get_or_create_session(request)
    flag_captured = None

    if session.get("a09b_promoted") and not _AUDIT_LOG_V2:
        capture_flag(session, FLAG)
        flag_captured = FLAG
        note = (
            "<p class='muted'>Notice: a privileged promotion just occurred, but "
            "the audit log below is completely empty — the action was never "
            "recorded anywhere.</p>"
        )
    else:
        note = ""

    log_html = "<br>".join(_AUDIT_LOG_V2) if _AUDIT_LOG_V2 else '<span class="muted">Log is empty.</span>'
    body = f'<div class="panel"><pre class="mono">{log_html}</pre>{note}</div>'
    body += '<p><a href="/play/a09_no_audit_trail/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a09_no_audit_trail",
    owasp_id="A09:2025",
    title="Missing Audit Trail",
    difficulty="Beginner",
    tagline="Promoting a user to admin succeeds — but nothing about it is ever logged.",
    objective_md="""
This admin panel can promote any user to administrator. That's about as
sensitive an action as a system has.

**Your goal:** perform the promotion, then check the audit log and
confirm that nothing about this privileged action was recorded at all.
""",
    hints_md="""
- Just promote any user ID, then click through to the audit log.
- This one isn't about crafting a clever payload — it's about noticing an
  absence. Compare this to the other A09 scenario, which is about a
  *forged* log entry; this one is about *no* entry at all.
""",
    fix_md="""
**Root cause:** a highly sensitive, privileged action (granting admin
rights) executes with no logging/alerting whatsoever — a missing control,
not a broken one.

**Fixes:**
- Explicitly identify every privileged/sensitive action in the system and
  require an audit log entry as a non-optional part of that action's code
  path (ideally enforced structurally, not just by convention).
- Alert security/ops teams in real time on privilege-escalation events —
  logging alone isn't enough if nobody's watching.
- Periodically audit which sensitive actions actually produce log entries
  in practice, not just which ones are documented as "should be logged."
""",
    flag_id=FLAG,
    router=router,
)
