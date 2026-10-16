import hashlib
import hmac
import secrets
import time
from core.db import query, execute

KEY_BYTES = 32  # → 64 hex chars

def generate_key() -> tuple[str, str, str]:
    """returns (plain, hash, prefix)"""
    plain = secrets.token_hex(KEY_BYTES)
    h = hashlib.sha256(plain.encode()).hexdigest()
    return plain, h, plain[:10]

def hash_key(plain: str) -> str:
    return hashlib.sha256(plain.encode()).hexdigest()

def find_key(plain: str):
    if not plain or len(plain) < 32:
        return None
    h = hash_key(plain)
    row = query(
        "SELECT id, user_id, revoked, key_hash FROM api_keys WHERE key_hash = ?",
        (h,), one=True,
    )
    if not row or row["revoked"]:
        return None
    if not hmac.compare_digest(row["key_hash"], h):
        return None
    return dict(row)

def touch_key(key_id: int):
    execute("UPDATE api_keys SET last_used = ? WHERE id = ?", (int(time.time()), key_id))

def log_usage(key_id: int, md5: str, status: str):
    execute(
        "INSERT INTO usage_log(key_id, md5, status, created_at) VALUES (?, ?, ?, ?)",
        (key_id, md5, status, int(time.time())),
    )

def user_has_active_sub(user_id: int) -> bool:
    row = query(
        "SELECT status, expires_at FROM subscriptions WHERE user_id = ?",
        (user_id,), one=True,
    )
    if not row or row["status"] != "active":
        return False
    return row["expires_at"] and row["expires_at"] > time.time()