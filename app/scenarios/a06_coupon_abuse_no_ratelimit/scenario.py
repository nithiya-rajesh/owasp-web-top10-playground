from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.scenarios.base import Scenario

FLAG = "FLAG{A06_insecure_design_coupon_reuse_abuse}"

router = APIRouter()

VALID_CODE = "WELCOME10"
CREDIT_PER_REDEMPTION = 10.00
ABUSE_THRESHOLD = 50.00  # 5+ redemptions of a "single-use" coupon


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    credits = session.get("a06_credits", 0.0)
    body = f"""
    <div class="panel">
      <p>Account credit balance: <b>${credits:.2f}</b></p>
      <form method="post" action="/play/a06_coupon_abuse_no_ratelimit/redeem">
        <label>Coupon code (single-use, $10 credit)</label>
        <input name="code" value="WELCOME10">
        <button type="submit">Redeem</button>
      </form>
      <p class="muted" style="margin-top:10px;">This coupon is meant to be redeemable once per account.</p>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/redeem", response_class=HTMLResponse)
def redeem(request: Request, response: Response, code: str = Form(...)):
    session = get_or_create_session(request)
    flag_captured = None

    # VULNERABLE: no idempotency check (e.g. "has this account already
    # redeemed this code?") and no rate limit — the same "single-use"
    # coupon can be redeemed as many times as the request is repeated.
    if code.strip().upper() == VALID_CODE:
        session["a06_credits"] = session.get("a06_credits", 0.0) + CREDIT_PER_REDEMPTION
        body = f'<div class="panel"><p>Coupon redeemed! +${CREDIT_PER_REDEMPTION:.2f} credit. New balance: ${session["a06_credits"]:.2f}</p></div>'
    else:
        body = '<div class="panel"><p>Invalid coupon code.</p></div>'

    if session.get("a06_credits", 0.0) >= ABUSE_THRESHOLD:
        capture_flag(session, FLAG)
        flag_captured = FLAG

    body += '<p><a href="/play/a06_coupon_abuse_no_ratelimit/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a06_coupon_abuse_no_ratelimit",
    owasp_id="A06:2025",
    title="Coupon Redemption Abuse",
    difficulty="Beginner",
    tagline="A 'single-use' coupon has no check preventing it from being redeemed over and over.",
    objective_md="""
This "WELCOME10" coupon is supposed to be redeemable once per account for
a $10 credit. There's no server-side check enforcing that.

**Your goal:** redeem the same coupon code repeatedly until your credit
balance reaches $50 or more.
""",
    hints_md="""
- Just resubmit the redeem form with the same code multiple times — five
  redemptions gets you to $50.
- Nothing tracks whether you've already used this exact code before.
""",
    fix_md="""
**Root cause:** the coupon redemption endpoint has no idempotency check
(has this account/code combination already been used?) and no rate
limiting — a design gap, not just a missing validation rule, since the
system was never built with "what stops repeated redemption" as an
explicit requirement.

**Fixes:**
- Track redemption state per account+coupon combination server-side, and
  reject any repeat redemption of a code marked single-use.
- Add rate limiting on redemption endpoints regardless of the idempotency
  check, as defense-in-depth against automation/abuse.
- Treat "can this action be repeated to accumulate unintended value?" as
  an explicit design question for any credit/discount/reward feature.
""",
    flag_id=FLAG,
    router=router,
)
