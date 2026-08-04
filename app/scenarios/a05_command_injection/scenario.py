import subprocess
from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A05_command_injection_ping_tool}"

router = APIRouter()

INJECTION_MARKERS = [";", "&&", "||", "|", "`", "$("]


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = """
    <div class="panel">
      <p>Network diagnostic tool — pings a host and shows the result.</p>
      <form method="post" action="/play/a05_command_injection/ping">
        <label>Host to ping</label>
        <input name="host" placeholder="127.0.0.1">
        <button type="submit">Ping</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/ping", response_class=HTMLResponse)
def ping(request: Request, response: Response, host: str = Form(...)):
    session = get_or_create_session(request)
    flag_captured = None

    # VULNERABLE: the host string is concatenated directly into a shell
    # command with shell=True — a genuine OS command injection, executed
    # for real inside this container (never expose this app publicly).
    command = f"ping -c 1 -W 2 {host}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
        output = (result.stdout or "") + (result.stderr or "")
    except Exception as e:  # noqa: BLE001
        output = f"Error running command: {e}"

    if any(marker in host for marker in INJECTION_MARKERS):
        capture_flag(session, FLAG)
        flag_captured = FLAG

    body = f"""
    <div class="panel">
      <p>Command executed: <code>{command}</code></p>
      <pre class="mono" style="background:var(--panel-2);padding:12px;border-radius:8px;white-space:pre-wrap;">{output}</pre>
    </div>"""
    body += '<p><a href="/play/a05_command_injection/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a05_command_injection",
    owasp_id="A05:2025",
    title="OS Command Injection",
    difficulty="Intermediate",
    tagline="A 'ping a host' tool builds a shell command by directly concatenating your input — genuine command injection.",
    objective_md="""
This diagnostic tool runs `ping` against whatever host you give it — by
directly concatenating your input into a shell command with no
sanitization.

**Your goal:** get a second command to execute alongside the ping, by
injecting a shell metacharacter into the host field.
""",
    hints_md="""
- Try: `127.0.0.1; whoami` or `127.0.0.1 && id`
- Any of `;`, `&&`, `||`, `|`, backticks, or `$(...)` will chain or
  substitute in a second command on most shells.
""",
    fix_md="""
**Root cause:** user input is concatenated directly into a shell command
string executed with `shell=True`, letting shell metacharacters change
what actually gets run.

**Fixes:**
- Never build shell commands via string concatenation with user input —
  use an argument-list API (e.g. `subprocess.run([...], shell=False)`)
  that passes arguments directly to the program, bypassing shell parsing
  entirely.
- If shell invocation is unavoidable, strictly validate/allowlist input
  against an expected format (e.g. a valid hostname/IP regex) before use.
- Run any process that must handle untrusted input with the least
  privilege possible, and in a sandboxed/contained environment.
""",
    flag_id=FLAG,
    router=router,
)
