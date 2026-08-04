"""
Minimal server-side session store, keyed by an opaque session ID kept in a
cookie. No JWTs or signed cookies here on purpose — A04's scenario is the
one place JWTs show up, and it's deliberately weak there.

IMPORTANT implementation note: FastAPI/Starlette ignores the injected
`Response` parameter's headers whenever a route returns its OWN Response
object (RedirectResponse, or an HTMLResponse built inside a helper like
app.core.layout.page()) — only the returned object's headers actually go
out. Rather than thread a response object through every helper and route,
new-session cookies are set centrally by a middleware in app/main.py, which
reads `request.state.new_session_id` after the real handler has already
built whatever response it's returning.
"""

import uuid
from fastapi import Request

COOKIE_NAME = "session_id"

_SESSIONS: dict[str, dict] = {}


def _new_session() -> dict:
    return {"flags": set(), "logged_in_user_id": None}


def get_or_create_session(request: Request) -> dict:
    sid = request.cookies.get(COOKIE_NAME)
    if sid and sid in _SESSIONS:
        return _SESSIONS[sid]

    sid = uuid.uuid4().hex
    _SESSIONS[sid] = _new_session()
    # Middleware in main.py reads this and attaches the Set-Cookie header
    # to whatever response object the route ends up returning.
    request.state.new_session_id = sid
    return _SESSIONS[sid]


def get_session_readonly(request: Request) -> dict:
    """For read-only checks where we don't want to create a cookie (e.g. an
    API the frontend polls) — returns an empty stand-in if none exists yet."""
    sid = request.cookies.get(COOKIE_NAME)
    if sid and sid in _SESSIONS:
        return _SESSIONS[sid]
    return _new_session()


def capture_flag(session: dict, flag: str):
    session["flags"].add(flag)


def reset_session(session: dict):
    session["flags"] = set()
    session["logged_in_user_id"] = None
