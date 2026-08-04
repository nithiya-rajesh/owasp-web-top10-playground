import hashlib
import jwt as pyjwt
from fastapi import APIRouter, Request, Response, Form
from fastapi.responses import HTMLResponse

from app.core.session import get_or_create_session, capture_flag
from app.core.layout import page
from app.core.db import get_connection, JWT_SECRET
from app.scenarios.base import Scenario

FLAG = "FLAG{A04_cryptographic_failures_cracked_md5}"
JWT_FLAG = "FLAG{A04_cryptographic_failures_forged_jwt}"

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def index(request: Request, response: Response):
    session = get_or_create_session(request)
    body = """
    <div class="panel">
      <p>Goal 1: a "leaked" database export below has unsalted MD5 password
      hashes. Crack one and submit it to prove it.</p>
      <p><a href="/play/a04_cryptographic_failures/leaked-export">View leaked export &rarr;</a></p>
    </div>
    <div class="panel">
      <h3>Crack a password</h3>
      <form method="post" action="/play/a04_cryptographic_failures/crack">
        <label>Username</label>
        <input name="username" placeholder="alice">
        <label>Guessed password</label>
        <input name="password" placeholder="try a common password">
        <button type="submit">Check</button>
      </form>
    </div>
    <div class="panel">
      <h3>Goal 2: forge an admin token</h3>
      <p>This app issues guest JWTs signed with a secret that... isn't very
      secret. <a href="/play/a04_cryptographic_failures/token">Get a guest token &rarr;</a></p>
      <form method="post" action="/play/a04_cryptographic_failures/verify-token">
        <label>Token to verify</label>
        <input name="token" placeholder="paste a JWT here">
        <button type="submit">Verify</button>
      </form>
    </div>"""
    return page(SCENARIO, session, body)


@router.get("/leaked-export", response_class=HTMLResponse)
def leaked_export(request: Request, response: Response):
    session = get_or_create_session(request)
    conn, lock = get_connection()
    with lock:
        rows = conn.execute("SELECT username, password_hash, email FROM users").fetchall()

    table_rows = "".join(
        f"<tr><td>{r['username']}</td><td class='mono' style='font-size:11px;'>{r['password_hash']}</td><td>{r['email']}</td></tr>"
        for r in rows
    )
    body = f"""
    <div class="panel">
      <h3>"users_export_final_v2.csv" (leaked)</h3>
      <table><tr><th>username</th><th>password_hash (MD5)</th><th>email</th></tr>{table_rows}</table>
      <p class="muted">Unsalted MD5 — crackable via rainbow tables or a plain dictionary attack against common passwords.</p>
    </div>"""
    return page(SCENARIO, session, body)


@router.get("/token", response_class=HTMLResponse)
def get_token(request: Request, response: Response):
    session = get_or_create_session(request)
    token = pyjwt.encode({"user": "guest", "role": "guest"}, JWT_SECRET, algorithm="HS256")
    body = f"""
    <div class="panel">
      <p>Your guest token:</p>
      <pre class="mono" style="background:var(--panel-2);padding:12px;border-radius:8px;word-break:break-all;">{token}</pre>
      <p class="muted">Decode it (e.g. at jwt.io or with PyJWT) — nothing in the payload is
      encrypted, only signed. If you can guess the signing secret, you can
      mint your own token with any payload you like.</p>
    </div>"""
    return page(SCENARIO, session, body)


@router.post("/crack", response_class=HTMLResponse)
def crack(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    session = get_or_create_session(request)
    conn, lock = get_connection()
    guess_hash = hashlib.md5(password.encode()).hexdigest()

    with lock:
        row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()

    flag_captured = None
    if row and row["password_hash"] == guess_hash:
        capture_flag(session, FLAG)
        flag_captured = FLAG
        body = f'<div class="panel"><p>✅ Correct! "{username}"\'s password is <b>{password}</b> — cracked via a plain dictionary guess against an unsalted MD5 hash.</p></div>'
    else:
        body = '<div class="panel">Not a match. Try a common/weak password for that username.</div>'

    body += '<p><a href="/play/a04_cryptographic_failures/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


@router.post("/verify-token", response_class=HTMLResponse)
def verify_token(request: Request, response: Response, token: str = Form(...)):
    session = get_or_create_session(request)
    flag_captured = None

    try:
        # VULNERABLE: the app trusts anything that verifies against its own
        # (weak, guessable) signing secret — if an attacker guesses
        # JWT_SECRET, they can mint a token with role="admin" from scratch.
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if payload.get("role") == "admin":
            capture_flag(session, JWT_FLAG)
            flag_captured = JWT_FLAG
            body = f'<div class="panel"><p>✅ Token verified with role=<b>admin</b>! Payload: <code>{payload}</code></p></div>'
        else:
            body = f'<div class="panel"><p>Token is valid but role is "{payload.get("role")}", not admin. Payload: <code>{payload}</code></p></div>'
    except pyjwt.InvalidTokenError as e:
        body = f'<div class="panel"><p>Invalid token: {e}</p></div>'

    body += '<p><a href="/play/a04_cryptographic_failures/">&larr; Back</a></p>'
    return page(SCENARIO, session, body, flag_just_captured=flag_captured)


SCENARIO = Scenario(
    id="a04_cryptographic_failures",
    owasp_id="A04:2025",
    title="Cryptographic Failures",
    difficulty="Intermediate",
    tagline="A leaked export with unsalted MD5 hashes, plus a JWT signed with a guessable secret.",
    objective_md="""
Two independent goals here:

**Goal 1:** the leaked export shows unsalted MD5 password hashes. Crack one
by guessing a common password for one of the listed usernames, then submit
it via the crack form to confirm.

**Goal 2:** the app issues guest JWTs signed with HS256 using a secret
that's... not very secret. Guess it, forge your own token with
`role: "admin"`, and submit it to verify.
""",
    hints_md="""
- For Goal 1: the seeded accounts use very common, guessable passwords —
  think classic "bad password" territory.
- For Goal 2: get a guest token first and note it's HS256. Common weak
  secrets are worth trying directly (e.g. tools like `jwt_tool` or a small
  script with PyJWT: `jwt.encode({"role":"admin"}, "<guess>", algorithm="HS256")`)
  — try short, simple, commonly-used strings.
""",
    fix_md="""
**Root cause (MD5):** passwords are hashed with a fast, unsalted algorithm
(MD5) that's crackable via rainbow tables or brute force at massive speed
on modern hardware.

**Root cause (JWT):** the signing secret is short/guessable, and there's no
secret rotation, complexity requirement, or use of asymmetric signing
(RS256) where only the server holds the private key.

**Fixes:**
- Use a slow, salted, purpose-built password hashing algorithm (bcrypt,
  scrypt, or Argon2) — never MD5/SHA1/SHA256 alone for passwords.
- Generate JWT signing secrets with real entropy (32+ random bytes from a
  CSPRNG), rotate them periodically, and prefer RS256 (asymmetric) for
  tokens verified by multiple services.
- Never trust a token's claims (like `role`) without also checking
  authorization server-side against the actual user record.
""",
    flag_id=FLAG,
    router=router,
)
