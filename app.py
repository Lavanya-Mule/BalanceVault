"""BalanceVault – Secure Financial Account and Transaction Management System."""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, g, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

DB_PATH = os.environ.get("BV_DB", "balancevault.db")
MAX_TRANSFER_CENTS = 10**11  # $1,000,000,000.00 upper bound per single txn
LOGIN_WINDOW_SECONDS = 60
LOGIN_MAX_FAILURES = int(os.environ.get("BV_LOGIN_MAX_ATTEMPTS", "10"))

ROLE_PERMISSIONS = {
    "customer": {
        "accounts:create",
        "accounts:read_own",
        "transfers:create",
        "transactions:read_own",
        "ledger:read_own",
    },
    "auditor": {
        "accounts:read_all",
        "transactions:read_all",
        "ledger:read_all",
        "users:read",
        "audit:read",
        "integrity:read",
    },
    "admin": {
        "accounts:read_all",
        "accounts:manage",
        "transfers:admin_ops",
        "transactions:read_all",
        "ledger:read_all",
        "users:read",
        "users:manage",
        "audit:read",
        "integrity:read",
    },
}

ACCOUNT_TRANSITIONS = {
    "pending": {"active", "rejected"},
    "active": {"frozen", "closed"},
    "frozen": {"active", "closed"},
    "rejected": set(),
    "closed": set(),
}

app = Flask(__name__, static_folder="static", static_url_path="")
app.secret_key = os.environ.get("BV_SECRET") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("BV_COOKIE_SECURE", "").lower() in ("1", "true"),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

_login_failures: dict[str, list[float]] = {}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('customer', 'auditor', 'admin')),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'disabled')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    number TEXT UNIQUE NOT NULL,
    account_name TEXT NOT NULL DEFAULT 'Primary Checking',
    account_type TEXT NOT NULL DEFAULT 'checking'
        CHECK(account_type IN ('checking', 'savings', 'business', 'system')),
    balance_cents INTEGER NOT NULL DEFAULT 0,
    is_system INTEGER NOT NULL DEFAULT 0 CHECK(is_system IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'active', 'frozen', 'rejected', 'closed')),
    onboarding_notes TEXT NOT NULL DEFAULT '',
    review_note TEXT NOT NULL DEFAULT '',
    reviewed_by INTEGER REFERENCES users(id),
    reviewed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK(balance_cents >= 0 OR is_system = 1)
);

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reference TEXT UNIQUE NOT NULL,
    txn_type TEXT NOT NULL DEFAULT 'transfer'
        CHECK(txn_type IN ('transfer', 'deposit', 'withdrawal')),
    idem_key TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    from_account INTEGER NOT NULL REFERENCES accounts(id),
    to_account INTEGER NOT NULL REFERENCES accounts(id),
    amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
    memo TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(created_by, idem_key),
    CHECK(from_account <> to_account)
);

CREATE TABLE IF NOT EXISTS ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    txn_id INTEGER NOT NULL REFERENCES transactions(id),
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    entry_type TEXT NOT NULL CHECK(entry_type IN ('DEBIT', 'CREDIT')),
    amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
    balance_after_cents INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    actor TEXT NOT NULL,
    actor_role TEXT NOT NULL DEFAULT 'anonymous',
    action TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_txn_accounts ON transactions(from_account, to_account);
CREATE INDEX IF NOT EXISTS idx_ledger_account ON ledger(account_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_txn ON ledger(txn_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, id DESC);

CREATE TRIGGER IF NOT EXISTS ledger_nu BEFORE UPDATE ON ledger
BEGIN SELECT RAISE(ABORT, 'ledger is immutable'); END;
CREATE TRIGGER IF NOT EXISTS ledger_nd BEFORE DELETE ON ledger
BEGIN SELECT RAISE(ABORT, 'ledger is immutable'); END;
CREATE TRIGGER IF NOT EXISTS txn_nu BEFORE UPDATE ON transactions
BEGIN SELECT RAISE(ABORT, 'transactions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS txn_nd BEFORE DELETE ON transactions
BEGIN SELECT RAISE(ABORT, 'transactions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_nu BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is immutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_nd BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is immutable'); END;
"""


def connect():
    """Open a SQLite connection configured for strict durability and concurrency."""
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def init_db():
    """Initialize schema, WAL mode, system settlement account, and default admin."""
    conn = connect()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.executescript(SCHEMA)
        if not conn.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
            admin_pw = os.environ.get("BV_ADMIN_PW", "Admin@123")
            conn.execute(
                "INSERT INTO users(username, full_name, email, password_hash, role) VALUES(?,?,?,?,?)",
                ("admin", "System Administrator", "admin@balancevault.local",
                 generate_password_hash(admin_pw), "admin"),
            )
        if not conn.execute("SELECT 1 FROM accounts WHERE is_system=1").fetchone():
            conn.execute(
                """INSERT INTO accounts(number, account_name, account_type, is_system, status)
                   VALUES('SYSTEM-0000', 'System Reserve & Settlement', 'system', 1, 'active')"""
            )
    finally:
        conn.close()


def db():
    """Return the per-request SQLite connection."""
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_):
    """Close the per-request SQLite connection."""
    conn = g.pop("db", None)
    if conn:
        conn.close()


@app.after_request
def apply_security_headers(resp):
    """Attach defensive security headers and prevent caching of API responses."""
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'"
    )
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def err(msg, code=400):
    """Return a standardized JSON error response."""
    return jsonify(error=msg), code


def body():
    """Parse JSON request body safely."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def client_ip():
    """Return the remote client address for audit records."""
    return (request.remote_addr or "local")[:45]


def write_audit(conn, action, detail="", target_type="", target_id="",
                actor_id=None, actor=None, actor_role=None):
    """Insert an immutable audit record using the provided database connection."""
    user = getattr(g, "user", None)
    if actor_id is None:
        actor_id = user["id"] if user else session.get("uid")
    if actor is None:
        actor = user["username"] if user else session.get("username", "anonymous")
    if actor_role is None:
        actor_role = user["role"] if user else session.get("role", "anonymous")
    conn.execute(
        """INSERT INTO audit_log(actor_id, actor, actor_role, action, target_type, target_id, detail, ip_address)
           VALUES(?,?,?,?,?,?,?,?)""",
        (actor_id, actor, actor_role, action, target_type, str(target_id), detail[:500], client_ip()),
    )


def _check_csrf_and_origin():
    """Verify same-origin and CSRF token on authenticated mutating requests."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    sec_fetch = request.headers.get("Sec-Fetch-Site")
    if sec_fetch and sec_fetch not in ("same-origin", "none"):
        return err("Cross-site request blocked", 403)
    origin = request.headers.get("Origin")
    if origin:
        parsed_origin = urlparse(origin)
        parsed_host = urlparse(request.host_url)
        if (parsed_origin.scheme, parsed_origin.netloc) != (parsed_host.scheme, parsed_host.netloc):
            return err("Origin mismatch", 403)
    header_token = request.headers.get("X-CSRF-Token")
    session_token = session.get("csrf_token")
    if header_token is not None:
        if not session_token or not hmac.compare_digest(header_token, session_token):
            return err("Invalid CSRF token", 403)
    elif origin and session_token and request.path not in ("/api/login", "/api/register"):
        return err("Missing CSRF token", 403)
    return None


def auth(*roles, permission=None):
    """Enforce authentication, live account status, CSRF checks, and RBAC."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            csrf_err = _check_csrf_and_origin()
            if csrf_err:
                return csrf_err
            uid = session.get("uid")
            if not uid:
                return err("Authentication required", 401)
            user = db().execute(
                "SELECT id, username, full_name, email, role, status, created_at FROM users WHERE id=?",
                (uid,),
            ).fetchone()
            if not user or user["status"] != "active":
                session.clear()
                return err("Account disabled or unavailable", 401)
            g.user = user
            perms = ROLE_PERMISSIONS.get(user["role"], set())
            if roles and user["role"] not in roles:
                return err("Forbidden: insufficient role", 403)
            if permission and permission not in perms:
                return err("Forbidden: missing permission", 403)
            return fn(*args, **kwargs)
        return wrapper
    return deco


def new_account_number():
    """Generate a unique 10-digit BalanceVault account number."""
    return "BV-" + "".join(secrets.choice("0123456789") for _ in range(10))


def new_txn_reference():
    """Generate a human-readable transaction reference ID."""
    return "TXN-" + secrets.token_hex(6).upper()


def _rate_limit_key(username):
    return f"{client_ip()}:{username.lower()}"


def _is_rate_limited(key):
    now = time.monotonic()
    attempts = [t for t in _login_failures.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    _login_failures[key] = attempts
    return len(attempts) >= LOGIN_MAX_FAILURES


def _record_login_failure(key):
    now = time.monotonic()
    attempts = [t for t in _login_failures.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    attempts.append(now)
    _login_failures[key] = attempts


def _clear_login_failures(key):
    _login_failures.pop(key, None)


def _compute_payload_hash(txn_type, from_id, to_id, amount_cents, memo):
    raw = f"{txn_type}|{from_id}|{to_id}|{amount_cents}|{memo}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _serialize_user(user):
    perms = sorted(ROLE_PERMISSIONS.get(user["role"], set()))
    return {
        "id": user["id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "email": user["email"],
        "role": user["role"],
        "status": user["status"],
        "permissions": perms,
        "csrf_token": session.get("csrf_token"),
    }


@app.post("/api/register")
def register():
    """Register a new customer user account."""
    csrf_err = _check_csrf_and_origin()
    if csrf_err:
        return csrf_err
    d = body()
    username = str(d.get("username", "")).strip()
    password = str(d.get("password", ""))
    full_name = str(d.get("full_name", "")).strip()[:80]
    email = str(d.get("email", "")).strip()[:120]

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        return err("Username must be 3-30 letters, digits, or underscores")
    if len(password) < 8 or not re.search(r"\d", password) or not re.search(r"[A-Za-z]", password):
        return err("Password must be 8+ characters with letters and digits")
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return err("Invalid email format")

    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            "INSERT INTO users(username, full_name, email, password_hash, role) VALUES(?,?,?,?, 'customer')",
            (username, full_name, email, generate_password_hash(password)),
        )
        uid = cur.lastrowid
        write_audit(conn, "REGISTER", f"Registered customer {username}", "user", uid,
                    actor_id=uid, actor=username, actor_role="customer")
        conn.execute("COMMIT")
        return jsonify(id=uid, username=username, role="customer"), 201
    except sqlite3.IntegrityError:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        return err("Username already taken", 409)
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


@app.post("/api/login")
def login():
    """Authenticate a user and establish an HttpOnly session."""
    csrf_err = _check_csrf_and_origin()
    if csrf_err:
        return csrf_err
    d = body()
    username = str(d.get("username", "")).strip()
    password = str(d.get("password", ""))
    rl_key = _rate_limit_key(username)
    if _is_rate_limited(rl_key):
        write_audit(db(), "LOGIN_RATE_LIMITED", f"Rate limited login for {username[:30]}",
                    "user", username[:30], actor_id=0, actor="anonymous", actor_role="anonymous")
        return err("Too many failed login attempts. Please wait and try again.", 429)

    conn = db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        _record_login_failure(rl_key)
        write_audit(conn, "LOGIN_FAILED", f"Failed login for {username[:30]}",
                    "user", username[:30], actor_id=0, actor="anonymous", actor_role="anonymous")
        return err("Invalid credentials", 401)
    if user["status"] != "active":
        write_audit(conn, "LOGIN_DENIED", "Disabled user attempted login",
                    "user", user["id"], actor_id=user["id"], actor=user["username"], actor_role=user["role"])
        return err("Account disabled", 403)

    _clear_login_failures(rl_key)
    session.clear()
    session.permanent = True
    session.update(
        uid=user["id"],
        username=user["username"],
        role=user["role"],
        csrf_token=secrets.token_urlsafe(32),
    )
    write_audit(conn, "LOGIN", "User signed in", "user", user["id"],
                actor_id=user["id"], actor=user["username"], actor_role=user["role"])
    return jsonify(_serialize_user(user))


@app.post("/api/logout")
def logout():
    """Terminate the current session and record logout."""
    csrf_err = _check_csrf_and_origin()
    if csrf_err:
        return csrf_err
    if "uid" in session:
        write_audit(db(), "LOGOUT", "User signed out", "user", session["uid"])
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
@auth()
def me():
    """Return the authenticated user's live profile, permissions, and CSRF token."""
    return jsonify(_serialize_user(g.user))


@app.post("/api/me/password")
@auth()
def change_password():
    """Allow an authenticated user to rotate their password."""
    d = body()
    current = str(d.get("current_password", ""))
    new_pw = str(d.get("new_password", ""))
    if len(new_pw) < 8 or not re.search(r"\d", new_pw) or not re.search(r"[A-Za-z]", new_pw):
        return err("New password must be 8+ characters with letters and digits")

    conn = db()
    row = conn.execute("SELECT password_hash FROM users WHERE id=?", (g.user["id"],)).fetchone()
    if not row or not check_password_hash(row["password_hash"], current):
        write_audit(conn, "PASSWORD_CHANGE_FAILED", "Invalid current password", "user", g.user["id"])
        return err("Current password is incorrect", 401)

    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (generate_password_hash(new_pw), g.user["id"]),
        )
        write_audit(conn, "PASSWORD_CHANGED", "User changed password", "user", g.user["id"])
        conn.execute("COMMIT")
        return jsonify(ok=True)
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


@app.post("/api/accounts")
@auth("customer", permission="accounts:create")
def open_account():
    """Submit a new account onboarding application (created in pending status)."""
    d = body()
    account_name = str(d.get("account_name", "Primary Checking")).strip() or "Primary Checking"
    account_type = str(d.get("account_type", "checking")).strip().lower()
    onboarding_notes = str(d.get("onboarding_notes", "")).strip()[:300]

    if len(account_name) > 60:
        return err("account_name must be 60 characters or fewer")
    if account_type not in ("checking", "savings", "business"):
        return err("account_type must be checking, savings, or business")

    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    try:
        number = new_account_number()
        cur = conn.execute(
            """INSERT INTO accounts(user_id, number, account_name, account_type, onboarding_notes)
               VALUES(?,?,?,?,?)""",
            (g.user["id"], number, account_name, account_type, onboarding_notes),
        )
        aid = cur.lastrowid
        write_audit(
            conn,
            "ACCOUNT_REQUESTED",
            f"Requested {account_type} account '{account_name}' ({number})",
            "account",
            aid,
        )
        conn.execute("COMMIT")
        return jsonify(id=aid, number=number, account_name=account_name, account_type=account_type, status="pending"), 201
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


@app.get("/api/accounts")
@auth()
def list_accounts():
    """List accounts visible to the current user based on RBAC permissions."""
    perms = ROLE_PERMISSIONS.get(g.user["role"], set())
    if "accounts:read_all" in perms:
        rows = db().execute(
            """SELECT a.*, u.username, u.full_name, rv.username AS reviewed_by_username
               FROM accounts a
               LEFT JOIN users u ON u.id = a.user_id
               LEFT JOIN users rv ON rv.id = a.reviewed_by
               ORDER BY a.id"""
        )
    else:
        rows = db().execute(
            """SELECT a.*, NULL AS username, NULL AS full_name, rv.username AS reviewed_by_username
               FROM accounts a
               LEFT JOIN users rv ON rv.id = a.reviewed_by
               WHERE a.user_id = ?
               ORDER BY a.id""",
            (g.user["id"],),
        )
    return jsonify([dict(r) for r in rows])


def _resolve_destination(conn, dst_field, dst_value):
    if dst_field == "id":
        if not isinstance(dst_value, int) or isinstance(dst_value, bool):
            return None
        return conn.execute("SELECT * FROM accounts WHERE id=?", (dst_value,)).fetchone()
    if dst_field == "number":
        num = str(dst_value or "").strip()
        if not num:
            return None
        return conn.execute("SELECT * FROM accounts WHERE number=?", (num,)).fetchone()
    return None


def _execute_transfer(txn_type, src_id, dst_field, dst_value, amount_cents, idem_key, memo, owner_check, audit_action):
    """Execute an atomic, idempotent, double-entry financial transfer using BEGIN IMMEDIATE."""
    if not isinstance(src_id, int) or isinstance(src_id, bool):
        return err("from_account_id must be an integer")
    if not isinstance(amount_cents, int) or isinstance(amount_cents, bool) or amount_cents <= 0 or amount_cents > MAX_TRANSFER_CENTS:
        return err("amount_cents must be a positive integer")
    key = str(idem_key or "").strip()
    if not key or len(key) > 100:
        return err("idempotency_key required (1-100 characters)")

    memo_norm = str(memo or "").strip()[:140]
    conn = db()
    uid = g.user["id"]

    conn.execute("BEGIN IMMEDIATE")
    try:
        src = conn.execute("SELECT * FROM accounts WHERE id=?", (src_id,)).fetchone()
        dst = _resolve_destination(conn, dst_field, dst_value)
        existing = conn.execute(
            "SELECT * FROM transactions WHERE created_by=? AND idem_key=?",
            (uid, key),
        ).fetchone()

        if existing:
            if not src or not dst:
                write_audit(conn, "IDEMPOTENCY_CONFLICT",
                            f"Idempotency key '{key}' reused with unknown accounts",
                            "transaction", existing["id"])
                conn.execute("COMMIT")
                return err("Idempotency key reused with different payload", 422)
            req_hash = _compute_payload_hash(txn_type, src["id"], dst["id"], amount_cents, memo_norm)
            if existing["payload_hash"] != req_hash:
                write_audit(conn, "IDEMPOTENCY_CONFLICT",
                            f"Idempotency key '{key}' reused with modified payload",
                            "transaction", existing["id"])
                conn.execute("COMMIT")
                return err("Idempotency key reused with different payload", 422)
            conn.execute("COMMIT")
            return jsonify(
                id=existing["id"],
                reference=existing["reference"],
                txn_type=existing["txn_type"],
                from_account=existing["from_account"],
                to_account=existing["to_account"],
                amount_cents=existing["amount_cents"],
                memo=existing["memo"],
                created_at=existing["created_at"],
                replayed=True,
            ), 200

        if not src or not dst:
            conn.execute("ROLLBACK")
            return err("Account not found", 404)
        if not owner_check(src, dst):
            write_audit(conn, "TRANSFER_DENIED",
                        f"Unauthorized {txn_type} attempt from account {src['id']} to {dst['id']}",
                        "account", src["id"])
            conn.execute("COMMIT")
            return err("Forbidden", 403)
        if src["id"] == dst["id"]:
            conn.execute("ROLLBACK")
            return err("Cannot transfer to the same account")
        if src["status"] != "active" or dst["status"] != "active":
            conn.execute("ROLLBACK")
            return err("Both accounts must be active", 409)
        if not src["is_system"] and src["balance_cents"] < amount_cents:
            conn.execute("ROLLBACK")
            return err("Insufficient funds", 409)

        src_new_balance = src["balance_cents"] - amount_cents
        dst_new_balance = dst["balance_cents"] + amount_cents

        # Deterministic ascending account-ID update order prevents cross-row lock cycles in multi-writer DBs.
        updates = {src["id"]: src_new_balance, dst["id"]: dst_new_balance}
        for acct_id in sorted(updates):
            conn.execute("UPDATE accounts SET balance_cents=? WHERE id=?", (updates[acct_id], acct_id))

        reference = new_txn_reference()
        payload_hash = _compute_payload_hash(txn_type, src["id"], dst["id"], amount_cents, memo_norm)
        tid = conn.execute(
            """INSERT INTO transactions(
                   reference, txn_type, idem_key, payload_hash, created_by,
                   from_account, to_account, amount_cents, memo
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (reference, txn_type, key, payload_hash, uid, src["id"], dst["id"], amount_cents, memo_norm),
        ).lastrowid

        conn.execute(
            """INSERT INTO ledger(txn_id, account_id, entry_type, amount_cents, balance_after_cents)
               VALUES(?, ?, 'DEBIT', ?, ?)""",
            (tid, src["id"], amount_cents, src_new_balance),
        )
        conn.execute(
            """INSERT INTO ledger(txn_id, account_id, entry_type, amount_cents, balance_after_cents)
               VALUES(?, ?, 'CREDIT', ?, ?)""",
            (tid, dst["id"], amount_cents, dst_new_balance),
        )

        write_audit(
            conn,
            audit_action,
            f"{reference}: {src['number']} -> {dst['number']} ({amount_cents}c)",
            "transaction",
            tid,
        )
        created = conn.execute("SELECT created_at FROM transactions WHERE id=?", (tid,)).fetchone()
        conn.execute("COMMIT")
        return jsonify(
            id=tid,
            reference=reference,
            txn_type=txn_type,
            from_account=src["id"],
            to_account=dst["id"],
            amount_cents=amount_cents,
            memo=memo_norm,
            created_at=created["created_at"],
            replayed=False,
        ), 201
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


@app.post("/api/transfers")
@auth("customer", permission="transfers:create")
def transfer():
    """Execute a peer-to-peer or own-account transfer between active accounts."""
    d = body()
    return _execute_transfer(
        txn_type="transfer",
        src_id=d.get("from_account_id"),
        dst_field="number",
        dst_value=d.get("to_account_number"),
        amount_cents=d.get("amount_cents"),
        idem_key=d.get("idempotency_key"),
        memo=d.get("memo", ""),
        owner_check=lambda s, dst: s["user_id"] == g.user["id"] and not dst["is_system"],
        audit_action="TRANSFER",
    )


@app.post("/api/admin/deposit")
@auth("admin", permission="transfers:admin_ops")
def admin_deposit():
    """Credit a customer account from the system reserve account."""
    d = body()
    sys_acct = db().execute("SELECT id FROM accounts WHERE is_system=1").fetchone()
    return _execute_transfer(
        txn_type="deposit",
        src_id=sys_acct["id"],
        dst_field="id",
        dst_value=d.get("account_id"),
        amount_cents=d.get("amount_cents"),
        idem_key=d.get("idempotency_key"),
        memo=d.get("memo") or "Admin deposit",
        owner_check=lambda s, dst: not dst["is_system"],
        audit_action="ADMIN_DEPOSIT",
    )


@app.post("/api/admin/withdraw")
@auth("admin", permission="transfers:admin_ops")
def admin_withdraw():
    """Debit a customer account back to the system reserve account."""
    d = body()
    sys_acct = db().execute("SELECT id FROM accounts WHERE is_system=1").fetchone()
    return _execute_transfer(
        txn_type="withdrawal",
        src_id=d.get("account_id"),
        dst_field="id",
        dst_value=sys_acct["id"],
        amount_cents=d.get("amount_cents"),
        idem_key=d.get("idempotency_key"),
        memo=d.get("memo") or "Admin withdrawal",
        owner_check=lambda s, dst: not s["is_system"],
        audit_action="ADMIN_WITHDRAW",
    )


@app.get("/api/transactions")
@auth()
def list_transactions():
    """Return transactions visible to the user, with optional account/type/search filters."""
    perms = ROLE_PERMISSIONS.get(g.user["role"], set())
    account_id = request.args.get("account_id", type=int)
    txn_type = (request.args.get("type") or "").strip().lower()
    query = (request.args.get("q") or "").strip()
    limit = min(max(request.args.get("limit", default=200, type=int), 1), 500)

    where = []
    params = []
    if "transactions:read_all" not in perms:
        where.append("(sf.user_id = ? OR st.user_id = ?)")
        params.extend([g.user["id"], g.user["id"]])
    if account_id:
        where.append("(t.from_account = ? OR t.to_account = ?)")
        params.extend([account_id, account_id])
    if txn_type in ("transfer", "deposit", "withdrawal"):
        where.append("t.txn_type = ?")
        params.append(txn_type)
    if query:
        like = f"%{query}%"
        where.append("(t.reference LIKE ? OR t.memo LIKE ? OR sf.number LIKE ? OR st.number LIKE ?)")
        params.extend([like, like, like, like])

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    sql = f"""
        SELECT t.*,
               sf.number AS from_account_number, sf.account_name AS from_account_name,
               st.number AS to_account_number, st.account_name AS to_account_name,
               u.username AS created_by_username
        FROM transactions t
        JOIN accounts sf ON sf.id = t.from_account
        JOIN accounts st ON st.id = t.to_account
        JOIN users u ON u.id = t.created_by
        {where_sql}
        ORDER BY t.id DESC
        LIMIT ?
    """
    params.append(limit)
    rows = db().execute(sql, params)
    return jsonify([dict(r) for r in rows])


@app.get("/api/accounts/<int:aid>/ledger")
@auth()
def account_ledger(aid):
    """Return immutable double-entry ledger statements for an authorized account."""
    acct = db().execute("SELECT * FROM accounts WHERE id=?", (aid,)).fetchone()
    if not acct:
        return err("Not found", 404)
    perms = ROLE_PERMISSIONS.get(g.user["role"], set())
    if "ledger:read_all" not in perms and acct["user_id"] != g.user["id"]:
        return err("Not found", 404)

    rows = db().execute(
        """SELECT l.*,
                  t.reference, t.txn_type, t.memo, t.from_account, t.to_account,
                  sf.number AS from_account_number, st.number AS to_account_number
           FROM ledger l
           JOIN transactions t ON t.id = l.txn_id
           JOIN accounts sf ON sf.id = t.from_account
           JOIN accounts st ON st.id = t.to_account
           WHERE l.account_id = ?
           ORDER BY l.id DESC
           LIMIT 300""",
        (aid,),
    )
    return jsonify([dict(r) for r in rows])


@app.post("/api/admin/accounts/<int:aid>/status")
@auth("admin", permission="accounts:manage")
def set_account_status(aid):
    """Approve, reject, freeze, unfreeze, or close a customer account."""
    d = body()
    next_status = str(d.get("status", "")).strip().lower()
    review_note = str(d.get("review_note", "")).strip()[:300]
    if next_status not in ("active", "frozen", "rejected", "closed"):
        return err("Invalid status")

    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    try:
        acct = conn.execute("SELECT * FROM accounts WHERE id=? AND is_system=0", (aid,)).fetchone()
        if not acct:
            conn.execute("ROLLBACK")
            return err("Not found", 404)
        allowed = ACCOUNT_TRANSITIONS.get(acct["status"], set())
        if next_status != acct["status"] and next_status not in allowed:
            conn.execute("ROLLBACK")
            return err(f"Cannot transition account from {acct['status']} to {next_status}", 409)
        if next_status == "closed" and acct["balance_cents"] != 0:
            conn.execute("ROLLBACK")
            return err("Account must have zero balance before closing", 409)

        conn.execute(
            """UPDATE accounts
               SET status=?, review_note=?, reviewed_by=?, reviewed_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (next_status, review_note or acct["review_note"], g.user["id"], aid),
        )
        write_audit(
            conn,
            "ACCOUNT_STATUS",
            f"Account {acct['number']} {acct['status']} -> {next_status}" + (f" ({review_note})" if review_note else ""),
            "account",
            aid,
        )
        conn.execute("COMMIT")
        return jsonify(ok=True, status=next_status)
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


@app.get("/api/admin/users")
@auth("admin", "auditor", permission="users:read")
def list_users():
    """List users along with their account counts for administration and oversight."""
    rows = db().execute(
        """SELECT u.id, u.username, u.full_name, u.email, u.role, u.status, u.created_at,
                  COUNT(a.id) AS account_count
           FROM users u
           LEFT JOIN accounts a ON a.user_id = u.id
           GROUP BY u.id
           ORDER BY u.id"""
    )
    return jsonify([dict(r) for r in rows])


@app.post("/api/admin/users/<int:uid>/status")
@auth("admin", permission="users:manage")
def set_user_status(uid):
    """Enable or disable a user account."""
    status = str(body().get("status", "")).strip().lower()
    if status not in ("active", "disabled") or uid == g.user["id"]:
        return err("Invalid request")

    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    try:
        target = conn.execute("SELECT id, username, role, status FROM users WHERE id=?", (uid,)).fetchone()
        if not target:
            conn.execute("ROLLBACK")
            return err("Not found", 404)
        if target["role"] == "admin" and status == "disabled":
            other_admins = conn.execute(
                "SELECT COUNT(*) AS c FROM users WHERE role='admin' AND status='active' AND id<>?",
                (uid,),
            ).fetchone()["c"]
            if other_admins == 0:
                conn.execute("ROLLBACK")
                return err("Cannot disable the last active administrator", 409)
        conn.execute("UPDATE users SET status=? WHERE id=?", (status, uid))
        write_audit(conn, "USER_STATUS", f"User {target['username']} status -> {status}", "user", uid)
        conn.execute("COMMIT")
        return jsonify(ok=True)
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


@app.post("/api/admin/users/<int:uid>/role")
@auth("admin", permission="users:manage")
def set_user_role(uid):
    """Update a user's RBAC role."""
    role = str(body().get("role", "")).strip().lower()
    if role not in ("customer", "auditor", "admin") or uid == g.user["id"]:
        return err("Invalid role request")

    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    try:
        target = conn.execute("SELECT id, username, role FROM users WHERE id=?", (uid,)).fetchone()
        if not target:
            conn.execute("ROLLBACK")
            return err("Not found", 404)
        if target["role"] == "admin" and role != "admin":
            other_admins = conn.execute(
                "SELECT COUNT(*) AS c FROM users WHERE role='admin' AND status='active' AND id<>?",
                (uid,),
            ).fetchone()["c"]
            if other_admins == 0:
                conn.execute("ROLLBACK")
                return err("Cannot demote the last active administrator", 409)
        conn.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
        write_audit(conn, "USER_ROLE", f"User {target['username']} role {target['role']} -> {role}", "user", uid)
        conn.execute("COMMIT")
        return jsonify(ok=True)
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


@app.get("/api/admin/audit")
@auth("admin", "auditor", permission="audit:read")
def get_audit_log():
    """Query the immutable audit trail with optional action and text filters."""
    action = (request.args.get("action") or "").strip().upper()
    query = (request.args.get("q") or "").strip()
    limit = min(max(request.args.get("limit", default=300, type=int), 1), 1000)

    where = []
    params = []
    if action:
        where.append("action = ?")
        params.append(action)
    if query:
        like = f"%{query}%"
        where.append("(actor LIKE ? OR action LIKE ? OR detail LIKE ? OR target_id LIKE ?)")
        params.extend([like, like, like, like])

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    params.append(limit)
    rows = db().execute(f"SELECT * FROM audit_log {where_sql} ORDER BY id DESC LIMIT ?", params)
    return jsonify([dict(r) for r in rows])


@app.get("/api/admin/integrity")
@auth("admin", "auditor", permission="integrity:read")
def integrity_check():
    """Reconcile all account balances, ledger entries, and zero-sum conservation."""
    conn = db()
    mismatched_accounts = conn.execute(
        """SELECT a.id, a.number, a.balance_cents,
                  COALESCE(SUM(CASE l.entry_type WHEN 'CREDIT' THEN l.amount_cents ELSE -l.amount_cents END), 0) AS ledger_cents
           FROM accounts a
           LEFT JOIN ledger l ON l.account_id = a.id
           GROUP BY a.id
           HAVING a.balance_cents <> ledger_cents"""
    ).fetchall()

    unbalanced_txns = conn.execute(
        """SELECT t.id, t.reference, t.amount_cents,
                  COUNT(l.id) AS entry_count,
                  COALESCE(SUM(CASE WHEN l.entry_type='CREDIT' THEN l.amount_cents ELSE 0 END), 0) AS credit_sum,
                  COALESCE(SUM(CASE WHEN l.entry_type='DEBIT' THEN l.amount_cents ELSE 0 END), 0) AS debit_sum
           FROM transactions t
           LEFT JOIN ledger l ON l.txn_id = t.id
           GROUP BY t.id
           HAVING entry_count <> 2 OR credit_sum <> t.amount_cents OR debit_sum <> t.amount_cents"""
    ).fetchall()

    totals = conn.execute(
        """SELECT COALESCE(SUM(balance_cents), 0) AS total_sum,
                  COUNT(*) AS account_count,
                  COALESCE(SUM(CASE WHEN is_system=0 THEN balance_cents ELSE 0 END), 0) AS customer_float_cents
           FROM accounts"""
    ).fetchone()
    txn_count = conn.execute("SELECT COUNT(*) AS c FROM transactions").fetchone()["c"]
    ledger_count = conn.execute("SELECT COUNT(*) AS c FROM ledger").fetchone()["c"]

    balanced = (totals["total_sum"] == 0 and not mismatched_accounts and not unbalanced_txns)
    return jsonify(
        balanced=balanced,
        total_balance_sum=totals["total_sum"],
        customer_float_cents=totals["customer_float_cents"],
        account_count=totals["account_count"],
        transaction_count=txn_count,
        ledger_entry_count=ledger_count,
        mismatched_accounts=[dict(r) for r in mismatched_accounts],
        unbalanced_transactions=[dict(r) for r in unbalanced_txns],
        checked_at=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/")
def index():
    """Serve the BalanceVault single-page web application."""
    return app.send_static_file("index.html")


init_db()
if __name__ == "__main__":
    app.run(debug=False, port=5000)
