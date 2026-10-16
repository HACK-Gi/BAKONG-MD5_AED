import re
import secrets
import time
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import session, request, redirect, url_for, g
from core.db import query, execute
from core.security import sec_log

_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SESSION_TTL = 60 * 60 * 24 * 7


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(hash_: str, pw: str) -> bool:
    try:
        _ph.verify(hash_, pw)
        return True
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def valid_email(email: str) -> bool:
    return bool(email and EMAIL_RE.match(email) and len(email) <= 254)


def valid_password(pw: str) -> tuple:
    """returns (ok, reason)"""
    if not pw:
        return False, "password required"
    if len(pw) < 10:
        return False, "password must be at least 10 characters"
    if len(pw) > 128:
        return False, "password too long"
    if not re.search(r"[A-Za-z]", pw):
        return False, "password must contain a letter"
    if not re.search(r"\d", pw):
        return False, "password must contain a digit"
    return True, ""


def _regenerate_session(user_id: int) -> str:
    """Wipe any pre-existing session, create fresh token — prevents fixation"""
    session.clear()
    token = secrets.token_urlsafe(48)
    expire = int(time.time()) + SESSION_TTL
    execute(
        "INSERT INTO sessions(token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, expire),
    )
    session.permanent = True
    session["sid"] = token
    return token


def create_session(user_id: int) -> str:
    return _regenerate_session(user_id)


def destroy_session(token: str):
    execute("DELETE FROM sessions WHERE token = ?", (token,))


def destroy_all_sessions(user_id: int):
    execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def current_user():
    if hasattr(g, "_user"):
        return g._user
    token = session.get("sid")
    g._user = None
    if not token:
        return None
    row = query(
        """SELECT u.id, u.email, s.expires_at
           FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token = ?""",
        (token,), one=True,
    )
    if not row or row["expires_at"] < time.time():
        if row:
            destroy_session(token)
        session.pop("sid", None)
        return None
    g._user = dict(row)
    return g._user


def login_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*a, **kw):
        if not current_user():
            return redirect(url_for("auth.login_page", next=request.path))
        return view(*a, **kw)
    return wrapped

def verification_required() -> bool:
    from core.config import Config
    return Config.EMAIL_MODE != "off"


def is_verified(user_id: int) -> bool:
    """Returns True if verified OR verification disabled globally."""
    from core.config import Config
    if Config.EMAIL_MODE == "off":
        return True
    row = query("SELECT email_verified FROM users WHERE id=?", (user_id,), one=True)
    return bool(row and row["email_verified"])
