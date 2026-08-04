from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.core.db import ORDERS
from app.scenarios.base import Scenario

FLAG = "FLAG{A01_broken_access_control_idor}"
SSRF_FLAG = "FLAG{A01_ssrf_internal_metadata_access}"

router = APIRouter()

USERS = {1: "alice", 2: "bob"}

INTERNAL_HOST_MARKERS = ["127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0", "internal", "::1"]


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    uid = session.get("logged_in_user_id")

    login_html = "".join(
        f'<a class="btn-secondary" style="margin-right:8px;" href="/play/a01_broken_access_control/login-as/{i}">Log in as {name}</a>'
        for i, name in USERS.items()
    )

    if not uid:
        body = f"""
        <div class="panel">
          <p>You're not logged in. Pick a demo account to continue:</p>
          {login_html}
        </div>"""
        return page(SCENARIO, session, body)

    my_orders = [o for o in ORDERS.values() if o["user_id"] == uid]
    rows = "".join(
        f'<tr><td>#{o["id"]}</td><td>{o["item"]}</td><td>${o["amount"]:.2f}</td>'
        f'<td>{o["status"]}</td><td><a href="/play/a01_broken_access_control/orders/{o["id"]}">View</a></td></tr>'
        for o in my_orders
    )
    body = f"""
    <div class="panel">
      <p>Logged in as <b>{USERS.get(uid)}</b> (user_id={uid}). {login_html}</p>
      <h3>My Orders</h3>
      <table><tr><th>Order</th><th>Item</th><th>Amount</th><th>Status</th><th></th></tr>{rows}</table>
      <p class="muted" style="margin-top:14px;">Try viewing an order ID that isn't listed above by editing the URL directly.</p>
    </div>
    <div class="panel">
      <h3>Import avatar from URL</h3>
      <form method="post" action="/play/a01_broken_access_control/import-avatar">
        <label>Avatar image URL</label>
        <input name="url" placeholder="https://example.com/avatar.png">
        <button type="submit">Import</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.get("/login-as/{user_id}")
def login_as(user_id: int, request: Request, response: Response):
    session = get_or_create_session(request)
    session["logged_in_user_id"] = user_id
    return RedirectResponse("/play/a01_broken_access_control/", status_code=302)


@router.get("/orders/{order_id}", response_class=HTMLResponse)
def view_order(order_id: int, request: Request, response: Response):
    session = get_or_create_session(request)
    uid = session.get("logged_in_user_id")
    order = ORDERS.get(order_id)

    if order is None:
        return page(SCENARIO, session, '<div class="panel">No such order.</div>')

    flag_captured = None
    # VULNERABLE: no check that order["user_id"] == uid — any logged-in user
    # can view ANY order by guessing/incrementing the ID.
    if uid is not None and order["user_id"] != uid:
        capture_flag(session, FLAG)
        flag_captured = FLAG

    body = f"""
    <div class="panel">
      <h3>Order #{order['id']}</h3>
      <p>Item: {order['item']}<br>Amount: ${order['amount']:.2f}<br>Status: {order['status']}<br>
      Belongs to user_id: <b>{order['user_id']}</b></p>
    </div>"""
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


@router.post("/import-avatar", response_class=HTMLResponse)
def import_avatar(request: Request, response: Response, url: str = Form(...)):
    session = get_or_create_session(request)
    flag_captured = None

    lowered = url.lower()
    if any(marker in lowered for marker in INTERNAL_HOST_MARKERS):
        capture_flag(session, SSRF_FLAG)
        flag_captured = SSRF_FLAG
        result = (
            f"<p><b>Server-side fetch result (simulated):</b></p>"
            f"<pre class='mono' style='background:var(--panel-2);padding:12px;border-radius:8px;'>"
            f"GET {url}\\n200 OK\\n\\n{{'instance-id': 'i-0abc123fake', 'iam-role-credentials': 'FAKE-NOT-REAL-...'}}"
            f"</pre>"
            f"<p class='muted'>The server fetched an internal-looking address on your behalf with no restriction — "
            f"in a real deployment this could reach cloud metadata endpoints or internal-only services.</p>"
        )
    else:
        result = f"<p>Fetched avatar from <code>{url}</code> (simulated — no real network request made by this lab).</p>"

    body = f'<div class="panel">{result}<p><a href="/play/a01_broken_access_control/">&larr; Back</a></p></div>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a01_broken_access_control",
    owasp_id="A01:2025",
    title="Broken Access Control",
    difficulty="Beginner",
    tagline="View any customer's order by guessing an ID. Also: an avatar importer that fetches internal addresses (SSRF).",
    objective_md="""
This mini storefront lets you log in as either of two demo customers and
view "My Orders." Order detail pages are served at `/orders/{id}` with no
check that the order actually belongs to you.

**Goal 1 (IDOR):** log in as one user, then view an order ID that belongs
to the *other* user by editing the URL directly.

**Goal 2 (SSRF):** the "Import avatar from URL" feature fetches whatever
URL you give it, server-side, with no restriction on the target host.
Try pointing it at an internal-looking address.
""",
    hints_md="""
- Log in as Alice, note which order IDs show up under "My Orders," then try
  an ID you *don't* own (e.g. if you're Alice, try Bob's order).
- Order IDs in this lab are small sequential integers — just try nearby numbers.
- For the SSRF path, try URLs containing `localhost`, `127.0.0.1`, or the
  classic cloud metadata address `169.254.169.254`.
""",
    fix_md="""
**Root cause (IDOR):** the order-detail route trusts the ID in the URL
with no server-side check that `order.user_id == current_user.id`.

**Root cause (SSRF):** the avatar importer fetches any URL server-side
with no allowlist on destination host/IP ranges.

**Fixes:**
- Enforce object-level authorization on every resource fetch — check
  ownership (or role) server-side on every request, never rely on the
  client "just not guessing" other IDs.
- For any server-side fetch of a user-supplied URL, allowlist destination
  hosts/schemes, block private/link-local IP ranges (RFC 1918, 169.254.0.0/16,
  loopback), and disable following redirects to disallowed targets.
""",
    flag_id=FLAG,
    router=router,
)
