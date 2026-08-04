from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A09_logging_failures_crlf_log_forging}"

router = APIRouter()

_LOG_TEXT = ""


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = """
    <div class="panel">
      <p>This app has a search feature that logs every query for security
      monitoring. Try searching for something normal first, then check the
      audit log below.</p>
      <form method="get" action="/play/a09_logging_alerting_failures/search">
        <label>Search products</label>
        <input name="q" placeholder="wireless mouse">
        <button type="submit">Search</button>
      </form>
      <p style="margin-top:14px;"><a href="/play/a09_logging_alerting_failures/audit-log">View audit log &rarr;</a></p>
    </div>"""
    return page(SCENARIO, session, body)


@router.get("/search", response_class=HTMLResponse)
def search(request: Request, response: Response, q: str = ""):
    global _LOG_TEXT
    session = get_or_create_session(request)
    # VULNERABLE: raw query logged with no sanitization of newline
    # characters — an attacker can inject fake log lines that look like
    # legitimate, unrelated security events (classic log/CRLF injection).
    # Using the raw string (not repr()) is deliberate: repr() would escape
    # embedded newlines as literal "\n" text, which would accidentally
    # defeat this exact vulnerability.
    _LOG_TEXT += f"[SEARCH] query={q} from=session\n"

    body = f"""
    <div class="panel"><p>Results for "{q}": (no matching products in this demo)</p></div>
    <p><a href="/play/a09_logging_alerting_failures/">&larr; Back</a> |
    <a href="/play/a09_logging_alerting_failures/audit-log">View audit log &rarr;</a></p>"""
    return page(SCENARIO, session, body)


@router.get("/audit-log", response_class=HTMLResponse)
def audit_log(request: Request, response: Response):
    session = get_or_create_session(request)
    flag_captured = None

    lines = _LOG_TEXT.split("\n")
    forged = any(
        line.strip().startswith("[ADMIN]") or line.strip().startswith("[SECURITY]")
        for line in lines
    )
    if forged:
        capture_flag(session, FLAG)
        flag_captured = FLAG

    log_html = "<br>".join(l for l in lines if l) if _LOG_TEXT else '<span class="muted">Log is empty.</span>'
    note = ""
    if forged:
        note = ("<p class='muted'>Notice a fabricated-looking log line above that didn't come "
                "from a real event — that's log injection: unsanitized input broke out of the "
                "intended log field format.</p>")

    body = f'<div class="panel"><pre class="mono" style="white-space:pre-wrap;">{log_html}</pre>{note}</div>'
    body += '<p><a href="/play/a09_logging_alerting_failures/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a09_logging_alerting_failures",
    owasp_id="A09:2025",
    title="Security Logging and Alerting Failures",
    difficulty="Intermediate",
    tagline="The search feature logs raw input with no sanitization — forge fake log entries.",
    objective_md="""
Every search query gets logged for "security monitoring." The logger
doesn't sanitize newline characters in what it writes.

**Your goal:** craft a search query that injects a fake, official-looking
log line (e.g. starting with `[ADMIN]` or `[SECURITY]`) that didn't
correspond to any real event, then view the audit log to confirm it shows
up as if it were legitimate.
""",
    hints_md="""
- Try including a literal newline in your search query to break out onto a
  new line in the log, followed by text that looks like a real log entry,
  e.g.: `test\\n[ADMIN] Privileged login succeeded for root`
- Depending on how you're sending the request (a raw URL vs a browser
  form), you may need to URL-encode the newline as `%0A`.
""",
    fix_md="""
**Root cause:** user-supplied input is written directly into log output
with no sanitization of control characters (newlines, carriage returns),
letting an attacker inject fabricated log entries that are
indistinguishable from real ones.

**Fixes:**
- Sanitize or encode control characters (`\\n`, `\\r`) out of any
  user-supplied value before it's written to logs — or use structured
  logging (e.g. JSON fields) instead of building log lines as raw strings.
- Never rely solely on free-text log content for security decisions;
  use structured, tamper-evident logging pipelines.
- Ensure privileged/sensitive actions are ALWAYS logged, with integrity
  protection (e.g. write-once storage, log signing) so entries can't be
  forged or silently altered after the fact.
""",
    flag_id=FLAG,
    router=router,
)
