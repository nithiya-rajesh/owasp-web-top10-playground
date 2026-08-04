import sqlite3
from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.core.db import get_connection
from app.scenarios.base import Scenario

FLAG = "FLAG{CHAIN_sqli_leak_to_idor_access}"

router = APIRouter()

# A protected resource keyed by user ID — same IDOR pattern as A01, but the
# ID needed to exploit it isn't visible anywhere in the UI. You have to
# extract it yourself first.
PRIVATE_NOTES = {2: "Bob's private notes: safe combination is 71-24-19."}

_conn, _lock = get_connection()
with _lock:
    _conn.execute("DROP TABLE IF EXISTS chain_products")
    _conn.execute("CREATE TABLE chain_products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    _conn.executemany(
        "INSERT INTO chain_products (id, name, price) VALUES (?, ?, ?)",
        [(1, "Wireless Mouse", 24.99), (2, "Mechanical Keyboard", 89.00), (3, "USB-C Hub", 34.50)],
    )
    _conn.commit()


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = """
    <div class="panel">
      <h3>Step 1: search products (vulnerable to SQL injection)</h3>
      <form method="get" action="/play/a01_chain_sqli_to_idor/search">
        <label>Search</label>
        <input name="q" placeholder="mouse">
        <button type="submit">Search</button>
      </form>
      <p class="muted" style="margin-top:10px;">Only products should be searchable here —
      but is the products table the only one this query can reach?</p>
    </div>
    <div class="panel">
      <h3>Step 2: view private notes by user ID (IDOR, no ownership check)</h3>
      <form method="get" action="/play/a01_chain_sqli_to_idor/notes">
        <label>User ID</label>
        <input name="user_id" placeholder="(you don't know a valid one yet)">
        <button type="submit">View notes</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.get("/search", response_class=HTMLResponse)
def search(request: Request, response: Response, q: str = ""):
    session = get_or_create_session(request)
    conn, lock = get_connection()

    # VULNERABLE: raw string interpolation into SQL against the products
    # table — a UNION-based payload can pivot into the completely
    # different `users` table, which this feature was never meant to touch.
    query = f"SELECT id, name, price FROM chain_products WHERE name LIKE '%{q}%'"
    leaked_users = False
    try:
        with lock:
            rows = conn.execute(query).fetchall()
        results = "<br>".join(f"id={r[0]} name={r[1]} price={r[2]}" for r in rows) or "No matches."
        if "union" in q.lower() and any(str(r[1]) in ("alice", "bob", "admin") for r in rows):
            leaked_users = True
    except sqlite3.Error as e:
        results = f"Query error: {e}"

    if leaked_users:
        session["chain_sqli_performed"] = True

    body = f"""
    <div class="panel">
      <p class="muted mono">{query}</p>
      <pre class="mono">{results}</pre>
    </div>"""
    body += '<p><a href="/play/a01_chain_sqli_to_idor/">&larr; Back</a></p>'
    return page(SCENARIO, session, body)


@router.get("/notes", response_class=HTMLResponse)
def notes(request: Request, response: Response, user_id: str = ""):
    session = get_or_create_session(request)
    flag_captured = None

    try:
        uid = int(user_id)
    except ValueError:
        body = '<div class="panel"><p>Invalid user ID.</p></div>'
        return page(SCENARIO, session, body)

    note = PRIVATE_NOTES.get(uid)
    if note:
        # Flag requires having actually performed the SQLi step first in
        # this session — proving the chain, not just guessing the ID.
        if session.get("chain_sqli_performed"):
            capture_flag(session, FLAG)
            flag_captured = FLAG
        body = f'<div class="panel"><p>{note}</p></div>'
    else:
        body = '<div class="panel"><p>No notes for that user (or you don\'t have access).</p></div>'

    body += '<p><a href="/play/a01_chain_sqli_to_idor/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a01_chain_sqli_to_idor",
    owasp_id="A01:2025",
    title="Chained Exploit: SQL Injection to IDOR",
    difficulty="Advanced",
    tagline="Use SQL injection to leak a user ID that isn't shown anywhere, then use that ID to bypass an IDOR check.",
    objective_md="""
This one requires **two chained steps**, not just one bug.

**Step 1:** the product search box is actually vulnerable to SQL
injection. Use it to extract user IDs from the `users` table — data the
search feature was never meant to expose.

**Step 2:** the "view private notes by user ID" feature has no ownership
check (classic IDOR) — but you need a valid user ID to use it, and none
are shown anywhere in the UI. Use the ID you leaked in Step 1.
""",
    hints_md="""
- For Step 1, try a UNION-based injection against the search box, e.g.:
  `' UNION SELECT id, username, role FROM users -- `
- That should return real user IDs, usernames, and roles from the
  underlying users table — including `bob` (id=2).
- For Step 2, take that leaked user ID and submit it in the notes lookup.
""",
    fix_md="""
**Root cause:** two independent vulnerabilities chain together to produce
a worse outcome than either alone — SQL injection (unparameterized query)
provides the reconnaissance data (valid user IDs) that IDOR (missing
ownership check) then exploits directly.

**Fixes:**
- Fix each vulnerability on its own merits (parameterized queries; proper
  ownership checks) — but also recognize that **chained** low-friction
  bugs often add up to a much higher-severity finding than either
  individually, which matters when prioritizing remediation.
- Apply defense-in-depth: even if IDOR is fixed, minimizing what SQL
  injection can expose (least-privilege DB accounts, no cross-table
  access from a search feature) limits chain potential too.
- Threat-model realistic attacker chains during design review, not just
  individual endpoints in isolation.
""",
    flag_id=FLAG,
    router=router,
)
