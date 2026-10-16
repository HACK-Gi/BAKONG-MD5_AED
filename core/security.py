import secrets
import time
import logging
from functools import wraps
from flask import session, request, jsonify, abort

log = logging.getLogger("security")
if not log.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(asctime)s] SEC %(message)s", "%Y-%m-%d %H:%M:%S"))
    log.addHandler(h)
    log.setLevel(logging.INFO)


# --- CSRF ---
CSRF_SESSION_KEY = "_csrf"
CSRF_HEADER = "X-CSRF-Token"

def generate_csrf() -> str:
    tok = session.get(CSRF_SESSION_KEY)
    if not tok:
        tok = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = tok
    return tok


def validate_csrf(tok: str) -> bool:
    expect = session.get(CSRF_SESSION_KEY)
    if not expect or not tok:
        return False
    return secrets.compare_digest(expect, tok)


def csrf_protect(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return fn(*a, **kw)
        # Accept from header (JS) or form field
        tok = request.headers.get(CSRF_HEADER) or request.form.get("_csrf")
        if not validate_csrf(tok):
            log.warning("CSRF fail ip=%s path=%s", request.remote_addr, request.path)
            if request.path.startswith("/api"):
                return jsonify({"ok": False, "error": "csrf"}), 403
            abort(403)
        return fn(*a, **kw)
    return wrapped


# --- sanitize error to client ---
def safe_error(msg: str, default="internal error") -> str:
    """Strip internal detail — only pass through safe categories"""
    if not msg:
        return default
    m = str(msg).lower()
    # whitelist phrases that are safe to show
    safe_markers = [
        "token", "ip", "not found", "invalid",
        "expired", "amount", "currency", "md5",
    ]
    for s in safe_markers:
        if s in m:
            return str(msg)[:200]
    return default


# --- security event log ---
def sec_log(event: str, **kw):
    user = session.get("sid", "")[:8] if session else ""
    parts = " ".join(f"{k}={v}" for k, v in kw.items())
    log.info("%s ip=%s sid=%s %s", event, request.remote_addr if request else "?", user, parts)


# --- login lockout ---
LOCKOUT_ATTEMPTS = 5
LOCKOUT_WINDOW = 900    # 15 min
LOCKOUT_DURATION = 900  # 15 min

def is_locked(email: str) -> bool:
    from core.db import query
    row = query(
        "SELECT locked_until FROM login_attempts WHERE email=?",
        (email.lower(),), one=True,
    )
    if not row or not row["locked_until"]:
        return False
    return row["locked_until"] > time.time()


def record_fail(email: str):
    from core.db import execute, query
    now = int(time.time())
    email = email.lower()
    row = query(
        "SELECT attempts, first_at FROM login_attempts WHERE email=?",
        (email,), one=True,
    )
    if not row or (now - row["first_at"]) > LOCKOUT_WINDOW:
        execute(
            """INSERT INTO login_attempts(email, attempts, first_at, locked_until)
               VALUES (?, 1, ?, NULL)
               ON CONFLICT(email) DO UPDATE SET attempts=1, first_at=?, locked_until=NULL""",
            (email, now, now),
        )
        return
    attempts = row["attempts"] + 1
    lock = None
    if attempts >= LOCKOUT_ATTEMPTS:
        lock = now + LOCKOUT_DURATION
    execute(
        "UPDATE login_attempts SET attempts=?, locked_until=? WHERE email=?",
        (attempts, lock, email),
    )


def clear_attempts(email: str):
    from core.db import execute
    execute("DELETE FROM login_attempts WHERE email=?", (email.lower(),))
