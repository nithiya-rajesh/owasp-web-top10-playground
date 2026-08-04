import traceback
from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A10_verbose_stacktrace_disclosure}"

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = """
    <div class="panel">
      <p>A simple calculator: divides two numbers.</p>
      <form method="get" action="/play/a10_stacktrace_disclosure/calculate">
        <label>Numerator</label>
        <input name="a" value="10">
        <label>Denominator</label>
        <input name="b" value="2">
        <button type="submit">Calculate</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.get("/calculate", response_class=HTMLResponse)
def calculate(request: Request, response: Response, a: str = "0", b: str = "1"):
    session = get_or_create_session(request)
    flag_captured = None

    try:
        result = float(a) / float(b)
        body = f'<div class="panel"><p>Result: {result}</p></div>'
    except Exception:
        # VULNERABLE: a misconfigured "debug mode" left on in this
        # deployment dumps the FULL raw traceback — including internal
        # file paths and source lines — directly into the response.
        tb = traceback.format_exc()
        capture_flag(session, FLAG)
        flag_captured = FLAG
        body = f"""
        <div class="panel">
          <p>An error occurred:</p>
          <pre class="mono" style="background:var(--panel-2);padding:12px;border-radius:8px;white-space:pre-wrap;">{tb}</pre>
        </div>"""

    body += '<p><a href="/play/a10_stacktrace_disclosure/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a10_stacktrace_disclosure",
    owasp_id="A10:2025",
    title="Verbose Stack Trace Disclosure",
    difficulty="Beginner",
    tagline="A misconfigured debug mode dumps the full raw traceback — file paths and all — straight into the response.",
    objective_md="""
This calculator divides two numbers. It doesn't validate its inputs very
carefully.

**Your goal:** trigger an unhandled exception (think about what kind of
input would break a numeric divide) and get the full raw traceback,
including internal file paths, returned in the response.
""",
    hints_md="""
- Try dividing by zero (denominator = `0`).
- Try a non-numeric value in either field, like `abc`.
""",
    fix_md="""
**Root cause:** a debug/development-mode error handler that dumps full
tracebacks was left active in a deployment reachable by end users —
identical in spirit to Django's `DEBUG=True` in production or an
unhandled Werkzeug debugger page.

**Fixes:**
- Never enable verbose/debug error output in any environment reachable by
  real users — return a generic error message, and log the full trace
  server-side only, where only authorized engineers can see it.
- Validate and sanitize all input at the boundary (type-check, range-check)
  before it reaches business logic, so far fewer exceptions occur at all.
- Add automated checks in CI/deployment that fail the build if debug
  flags or verbose error handlers are enabled in a production-like config.
""",
    flag_id=FLAG,
    router=router,
)
