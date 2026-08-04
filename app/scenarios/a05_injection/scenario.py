import re
from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.core.db import get_connection
from app.scenarios.base import Scenario

SQLI_FLAG = "FLAG{A05_injection_sql_login_bypass}"
XSS_FLAG = "FLAG{A05_injection_stored_xss}"

router = APIRouter()

_COMMENTS: list[str] = []


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = """
    <div class="panel">
      <h3>Goal 1: SQL injection login bypass</h3>
      <form method="post" action="/play/a05_injection/login">
        <label>Username</label>
        <input name="username" placeholder="admin">
        <label>Password</label>
        <input name="password" type="text" placeholder="(you don't know it)">
        <button type="submit">Log in</button>
      </form>
    </div>
    <div class="panel">
      <h3>Goal 2: stored XSS in comments</h3>
      <p><a href="/play/a05_injection/comments">Go to comments &rarr;</a></p>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/login", response_class=HTMLResponse)
def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    session = get_or_create_session(request)
    conn, lock = get_connection()

    # VULNERABLE: raw string interpolation directly into SQL. A real,
    # genuine SQL injection against a real (in-memory) sqlite database —
    # e.g. username = admin' -- bypasses the password check entirely.
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    flag_captured = None
    try:
        with lock:
            row = conn.execute(query).fetchone()
    except Exception as e:  # noqa: BLE001
        body = f'<div class="panel"><p>Query error: {e}</p><p class="muted mono">{query}</p></div>'
        return page(SCENARIO, session, body)

    if row:
        actual_password = row["password"]
        if password != actual_password:
            # Logged in WITHOUT knowing the real password — that's the injection succeeding.
            capture_flag(session, SQLI_FLAG)
            flag_captured = SQLI_FLAG
            body = f"""
            <div class="panel">
              <p>✅ Logged in as <b>{row['username']}</b> ({row['role']}) — without the real password!</p>
              <p class="muted mono">Query executed: {query}</p>
            </div>"""
        else:
            body = f'<div class="panel"><p>Logged in normally as {row["username"]}.</p></div>'
    else:
        body = f'<div class="panel"><p>Login failed.</p><p class="muted mono">{query}</p></div>'

    body += '<p><a href="/play/a05_injection/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


@router.get("/comments", response_class=HTMLResponse)
def comments_page(request: Request, response: Response):
    session = get_or_create_session(request)
    flag_captured = None

    # VULNERABLE: comments are rendered completely unescaped — any HTML/JS
    # a "customer" submits gets reflected back verbatim to every visitor.
    rendered = "".join(f'<div class="panel" style="padding:12px;">{c}</div>' for c in _COMMENTS)

    for c in _COMMENTS:
        if re.search(r"<script[^>]*>", c, re.IGNORECASE):
            capture_flag(session, XSS_FLAG)
            flag_captured = XSS_FLAG
            break

    body = f"""
    <div class="panel">
      <form method="post" action="/play/a05_injection/comments">
        <label>Leave a comment</label>
        <textarea name="comment" rows="3" placeholder="Great product!"></textarea>
        <button type="submit">Post</button>
      </form>
    </div>
    <h3>Comments</h3>
    {rendered if rendered else '<p class="muted">No comments yet.</p>'}
    """
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


@router.post("/comments", response_class=HTMLResponse)
def post_comment(request: Request, response: Response, comment: str = Form(...)):
    _COMMENTS.append(comment)
    from fastapi.responses import RedirectResponse
    get_or_create_session(request)
    return RedirectResponse("/play/a05_injection/comments", status_code=302)


SCENARIO = Scenario(
    id="a05_injection",
    owasp_id="A05:2025",
    title="Injection",
    difficulty="Beginner",
    tagline="A real SQL injection login bypass, plus stored XSS in a comments feature.",
    objective_md="""
**Goal 1 — SQL injection:** the login form builds its query by directly
inserting your username/password into a SQL string with no
parameterization. Log in as `admin` without knowing the real password.

**Goal 2 — Stored XSS:** the comments feature renders whatever you submit
completely unescaped. Get a `<script>` tag to persist and render on the
page.
""",
    hints_md="""
- Classic SQLi login bypass: try a username like `admin' --` (with a
  trailing space after `--`) and any password — this comments out the rest
  of the query, including the password check.
- For XSS: just submit a comment containing a literal `<script>` tag, e.g.
  `<script>alert(1)</script>`, then reload the comments page.
""",
    fix_md="""
**Root cause (SQLi):** the query is built with raw f-string interpolation
instead of parameterized queries/prepared statements, so user input can
alter the query's actual structure.

**Root cause (XSS):** comment content is inserted directly into the HTML
response with no escaping.

**Fixes:**
- Always use parameterized queries (`cursor.execute(query, (params,))`) —
  never string-format user input directly into SQL, ever.
- HTML-escape all user-generated content by default before rendering;
  use a templating engine with autoescaping enabled (and don't disable it
  for user content), or an explicit sanitization library if rich text is
  genuinely needed.
- Add a Content-Security-Policy header as defense-in-depth against XSS
  that slips through.
""",
    flag_id=SQLI_FLAG,
    router=router,
)
