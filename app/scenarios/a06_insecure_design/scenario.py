from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.core.db import PRODUCTS
from app.scenarios.base import Scenario

FLAG = "FLAG{A06_insecure_design_client_trusted_price}"

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    product = PRODUCTS[1]

    body = f"""
    <div class="panel">
      <h3>Checkout: {product['name']}</h3>
      <p class="muted">This form includes the price and quantity as regular
      editable fields — a real storefront would never trust these values
      from the client, but this one does.</p>
      <form method="post" action="/play/a06_insecure_design/checkout">
        <label>Product</label>
        <input value="{product['name']}" disabled>
        <label>Unit price ($)</label>
        <input name="price" value="{product['price']}">
        <label>Quantity</label>
        <input name="quantity" value="1">
        <button type="submit">Place order</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/checkout", response_class=HTMLResponse)
def checkout(request: Request, response: Response, price: str = Form(...), quantity: str = Form(...)):
    session = get_or_create_session(request)
    flag_captured = None

    try:
        price_val = float(price)
        qty_val = int(quantity)
    except ValueError:
        body = '<div class="panel">Invalid input.</div>'
        return page(SCENARIO, session, body)

    # VULNERABLE: the server recomputes the total from client-submitted
    # price/quantity with no re-validation against the actual catalog price
    # and no floor on quantity — a negative quantity or price produces a
    # negative total, i.e. the store paying the "customer."
    total = price_val * qty_val

    if total <= 0:
        capture_flag(session, FLAG)
        flag_captured = FLAG
        body = f"""
        <div class="panel">
          <p>✅ Order placed. Total: <b>${total:.2f}</b></p>
          <p class="muted">A total of ${total:.2f} was accepted with no server-side
          re-validation against the real catalog price or a minimum-quantity
          check — this is exactly how a manipulated checkout produces a
          "refund" or a free order.</p>
        </div>"""
    else:
        body = f'<div class="panel"><p>Order placed. Total: ${total:.2f}</p></div>'

    body += '<p><a href="/play/a06_insecure_design/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a06_insecure_design",
    owasp_id="A06:2025",
    title="Insecure Design",
    difficulty="Beginner",
    tagline="Checkout trusts client-submitted price and quantity with no server-side recalculation.",
    objective_md="""
This checkout form includes the unit price and quantity as regular,
editable form fields. The server uses whatever values you submit directly
— it never re-checks them against the real catalog price.

**Your goal:** manipulate the price and/or quantity to produce a total of
$0 or less.
""",
    hints_md="""
- Try a negative quantity, or a price of `0` or a negative number.
- Browser dev tools aren't even necessary here — the fields are already
  editable in the form itself.
""",
    fix_md="""
**Root cause:** this is a *design* flaw, not just a missing input check —
the checkout flow was built to trust client-supplied pricing data at all,
rather than treating the client as untrusted and the server as the sole
source of truth for price.

**Fixes:**
- Never send editable price/quantity fields to the client as the basis for
  a charge — look up the authoritative price server-side by product ID
  and recompute the total yourself, ignoring any price the client sent.
- Enforce sane bounds (quantity >= 1, price > 0) server-side regardless of
  what the client claims.
- Threat-model the checkout flow at design time: "what if the client sends
  whatever it wants" should be an explicit assumption, not an afterthought.
""",
    flag_id=FLAG,
    router=router,
)
