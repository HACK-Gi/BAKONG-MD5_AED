import hashlib
import secrets
import time
from core.db import query, execute
from core.config import Config

RESEND_COOLDOWN = 60  # seconds


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_verify_token(user_id: int) -> str:
    """Returns raw token. DB stores hash only. Overwrites any previous."""
    raw = secrets.token_urlsafe(32)
    h = _hash(raw)
    now = int(time.time())
    expires = now + Config.VERIFY_TOKEN_TTL

    execute("DELETE FROM email_verify WHERE user_id=?", (user_id,))
    execute(
        "INSERT INTO email_verify(user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (user_id, h, expires, now),
    )
    execute("UPDATE users SET verify_last_sent=? WHERE id=?", (now, user_id))
    return raw


def consume_verify_token(raw: str):
    """Returns user_id on success. Deletes token."""
    if not raw or len(raw) < 20:
        return None
    h = _hash(raw)
    row = query(
        "SELECT user_id, expires_at FROM email_verify WHERE token_hash=?",
        (h,), one=True,
    )
    if not row:
        return None
    if row["expires_at"] < time.time():
        execute("DELETE FROM email_verify WHERE token_hash=?", (h,))
        return None
    uid = row["user_id"]
    execute("DELETE FROM email_verify WHERE token_hash=?", (h,))
    return uid


def resend_cooldown_left(user_id: int) -> int:
    """Seconds remaining before user can resend. 0 = can resend."""
    row = query("SELECT verify_last_sent FROM users WHERE id=?", (user_id,), one=True)
    if not row or not row["verify_last_sent"]:
        return 0
    elapsed = int(time.time()) - row["verify_last_sent"]
    left = RESEND_COOLDOWN - elapsed
    return max(0, left)


# ---------- login OTP ----------

OTP_TTL = 60 * 10        # 10 min
OTP_RESEND_COOLDOWN = 60
OTP_MAX_ATTEMPTS = 5


def generate_otp() -> str:
    n = secrets.randbelow(1000000)
    return f"{n:06d}"


def _otp_hash(email: str, code: str) -> str:
    return hashlib.sha256(f"{email}:{code}".encode()).hexdigest()


def issue_login_otp(email: str) -> str:
    """Returns 6-digit OTP (plain, to send via email)."""
    email = email.lower()
    now = int(time.time())
    code = generate_otp()
    h = _otp_hash(email, code)
    expires = now + OTP_TTL

    execute(
        """INSERT INTO login_otp(email, otp_hash, expires_at, attempts, created_at, last_sent)
           VALUES (?, ?, ?, 0, ?, ?)
           ON CONFLICT(email) DO UPDATE SET
             otp_hash=excluded.otp_hash,
             expires_at=excluded.expires_at,
             attempts=0,
             created_at=excluded.created_at,
             last_sent=excluded.last_sent""",
        (email, h, expires, now, now),
    )
    return code


def otp_resend_cooldown_left(email: str) -> int:
    row = query("SELECT last_sent FROM login_otp WHERE email=?", (email.lower(),), one=True)
    if not row or not row["last_sent"]:
        return 0
    elapsed = int(time.time()) - row["last_sent"]
    return max(0, OTP_RESEND_COOLDOWN - elapsed)


def verify_login_otp(email: str, code: str):
    """Returns (ok: bool, reason: str). Deletes OTP on success."""
    email = email.lower()
    code = (code or "").strip()

    if not code or not code.isdigit() or len(code) != 6:
        return False, "invalid_code"

    row = query(
        "SELECT otp_hash, expires_at, attempts FROM login_otp WHERE email=?",
        (email,), one=True,
    )
    if not row:
        return False, "no_otp"

    if row["expires_at"] < time.time():
        execute("DELETE FROM login_otp WHERE email=?", (email,))
        return False, "expired"

    if row["attempts"] >= OTP_MAX_ATTEMPTS:
        execute("DELETE FROM login_otp WHERE email=?", (email,))
        return False, "too_many_attempts"

    if _otp_hash(email, code) != row["otp_hash"]:
        execute(
            "UPDATE login_otp SET attempts = attempts + 1 WHERE email=?",
            (email,),
        )
        return False, "wrong_code"

    execute("DELETE FROM login_otp WHERE email=?", (email,))
    return True, "ok"


def clear_login_otp(email: str):
    execute("DELETE FROM login_otp WHERE email=?", (email.lower(),))
