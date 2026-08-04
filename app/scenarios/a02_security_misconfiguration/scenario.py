from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A02_security_misconfiguration_debug_endpoint}"

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = """
    <div class="panel">
      <p>Welcome to Northwind Gadgets' storefront (mini demo). Nothing to
      see on this page — but this app was deployed with a leftover
      developer convenience left switched on. Poke around a bit.</p>
    </div>"""
    return page(SCENARIO, session, body)


@router.get("/debug/info", response_class=HTMLResponse)
def debug_info(request: Request, response: Response):
    session = get_or_create_session(request)
    capture_flag(session, FLAG)

    body = f"""
    <div class="panel">
      <h3>⚠️ Debug Endpoint (should never be reachable in production)</h3>
      <pre class="mono" style="background:var(--panel-2);padding:14px;border-radius:8px;white-space:pre-wrap;">
FLASK_DEBUG=1
DATABASE_URL=postgres://admin:Sup3rSecret!@db.internal:5432/northwind_prod
INTERNAL_API_KEY=nw-internal-a1b2c3d4e5f6
LAST_DEPLOY_COMMIT=8f3a91c
SERVER=app-prod-03.internal (10.2.4.17)
STACK_TRACE (most recent call last):
  File "app/routes/checkout.py", line 142, in process_payment
    charge_result = payment_gateway.charge(card_token, amount)
  File "app/lib/payment_gateway.py", line 58, in charge
    raise GatewayTimeoutError("upstream timeout after 30s")
      </pre>
      <p class="muted">This route was meant to be removed before deploy and never was.</p>
    </div>"""
    return page(SCENARIO, session, body, flag_just_captured=FLAG)


SCENARIO = Scenario(
    id="a02_security_misconfiguration",
    owasp_id="A02:2025",
    title="Security Misconfiguration",
    difficulty="Beginner",
    tagline="A debug endpoint was left enabled in this 'production' deployment.",
    objective_md="""
Somewhere on this app, a developer debug endpoint was left reachable after
deployment. It leaks internal configuration details — database credentials,
API keys, stack traces — that should never be exposed to the public
internet.

**Your goal:** find and access it.
""",
    hints_md="""
- Common debug/diagnostic paths to try: `/debug`, `/debug/info`, `/_debug`,
  `/status`, `/health/detailed`.
- Real-world equivalents: Django's `DEBUG=True` error pages, Spring Boot
  Actuator endpoints left open, exposed `.env` files, phpinfo() pages.
""",
    fix_md="""
**Root cause:** a diagnostic/debug endpoint that dumps internal
configuration and stack traces was left reachable in a production-like
deployment, with no authentication and no environment check.

**Fixes:**
- Strip debug/diagnostic endpoints entirely from production builds, or
  gate them behind strong authentication AND an explicit environment check.
- Never let stack traces, connection strings, or API keys appear in any
  response reachable without authentication.
- Automate a deployment check that fails the build if debug flags or known
  debug routes are present in a production configuration.
""",
    flag_id=FLAG,
    router=router,
)
