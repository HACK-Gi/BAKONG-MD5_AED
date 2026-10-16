"""Strict input validation helpers — never trust client input."""
import re
import html

MD5_RE = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
NAME_RE = re.compile(r"^[\w\s\-\u1780-\u17ff]{1,64}$")  # allows Khmer block
HEX_RE = re.compile(r"^[a-f0-9]+$", re.IGNORECASE)


def clean_md5(value: str) -> str:
    v = (value or "").strip().lower()
    if not MD5_RE.match(v):
        raise ValueError("invalid md5")
    return v


def clean_email(value: str) -> str:
    v = (value or "").strip().lower()
    if len(v) > 254 or not EMAIL_RE.match(v):
        raise ValueError("invalid email")
    return v


def clean_name(value: str, max_len: int = 64) -> str:
    v = (value or "").strip()[:max_len]
    if not v or not NAME_RE.match(v):
        raise ValueError("invalid name")
    return v


def clean_code(value: str) -> str:
    v = (value or "").strip()
    if not v.isdigit() or len(v) != 6:
        raise ValueError("invalid code")
    return v


def clean_token(value: str) -> str:
    v = (value or "").strip()
    if not v or len(v) > 128 or not re.match(r"^[A-Za-z0-9_\-]+$", v):
        raise ValueError("invalid token")
    return v


def html_escape(value: str) -> str:
    return html.escape(value or "", quote=True)


def strip_control(value: str) -> str:
    """Remove null bytes and control chars except tab/newline."""
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value or "")


def safe_int(value, default=None, min_v=None, max_v=None):
    try:
        n = int(value)
    except (TypeError, ValueError):
        if default is not None:
            return default
        raise ValueError("invalid int")
    if min_v is not None and n < min_v:
        raise ValueError("out of range")
    if max_v is not None and n > max_v:
        raise ValueError("out of range")
    return n
