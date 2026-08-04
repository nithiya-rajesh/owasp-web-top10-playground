"""
Shared fake "backend" data used across scenarios. Two different storage
styles on purpose:

  - A REAL sqlite3 in-memory database for the login/search flows, so A05's
    SQL injection is a genuine SQL injection against a real database, not a
    simulated string check. Single shared connection + lock since this is a
    single-user local training app, not a production service.
  - Plain Python dicts for everything else (orders, sessions, audit log,
    etc.) — no need for real SQL there, and it keeps those scenarios simple
    to read.

All "secrets" (passwords, JWT signing key) are obviously synthetic and
weak ON PURPOSE — that weakness IS the vulnerability being taught.
"""

import sqlite3
import threading
import hashlib

_lock = threading.Lock()
_conn = sqlite3.connect(":memory:", check_same_thread=False)
_conn.row_factory = sqlite3.Row


def _weak_hash(password: str) -> str:
    # VULNERABLE (intentionally, for A04): unsalted MD5. Do not do this in
    # anything real — it's here so a leaked export is crackable/rainbow
    # -table-able, which is the point of that scenario.
    return hashlib.md5(password.encode()).hexdigest()


def init_db():
    with _lock:
        cur = _conn.cursor()
        cur.execute("DROP TABLE IF EXISTS users")
        cur.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT,
                password_hash TEXT,
                email TEXT,
                role TEXT
            )
            """
        )
        seed_users = [
            (1, "alice", "sunshine1", "alice@example.com", "customer"),
            (2, "bob", "letmein22", "bob@example.com", "customer"),
            (3, "admin", "correct-horse-battery-staple", "admin@example.com", "admin"),
        ]
        for uid, username, password, email, role in seed_users:
            cur.execute(
                "INSERT INTO users (id, username, password, password_hash, email, role) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (uid, username, password, _weak_hash(password), email, role),
            )
        _conn.commit()


def get_connection():
    return _conn, _lock


# --- Plain dict stores for the other scenarios ---

ORDERS = {
    101: {"id": 101, "user_id": 1, "item": "Wireless Mouse", "amount": 24.99, "status": "shipped"},
    102: {"id": 102, "user_id": 2, "item": "Mechanical Keyboard", "amount": 89.00, "status": "processing"},
    103: {"id": 103, "user_id": 1, "item": "USB-C Hub", "amount": 34.50, "status": "delivered"},
}

PRODUCTS = {
    1: {"id": 1, "name": "Wireless Mouse", "price": 24.99},
    2: {"id": 2, "name": "Mechanical Keyboard", "price": 89.00},
    3: {"id": 3, "name": "USB-C Hub", "price": 34.50},
}

# In-memory audit log for A09 — deliberately NOT written to by privileged
# actions in that scenario's vulnerable endpoint, demonstrating missing
# logging on sensitive operations.
AUDIT_LOG: list[str] = []

# JWT signing secret — deliberately weak/guessable for A04's forgeable-token path.
JWT_SECRET = "secret123"

init_db()
