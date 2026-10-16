"""
Pattern-based Web Application Firewall.
Blocks obvious SQLi / XSS / path traversal / command injection payloads
before they reach the app logic.
"""
import re
import logging
from flask import request, jsonify, abort

log = logging.getLogger("waf")

# Suspicious patterns (case-insensitive)
PATTERNS = [
    # SQLi
    (re.compile(r"(\bunion\b.{0,20}\bselect\b)", re.I), "sqli_union"),
    (re.compile(r"(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)", re.I), "sqli_or"),
    (re.compile(r"(--|#|/\*)\s*(select|insert|update|delete|drop)", re.I), "sqli_comment"),
    (re.compile(r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", re.I), "sqli_time"),
    (re.compile(r"\b(information_schema|sysobjects|xp_cmdshell)\b", re.I), "sqli_meta"),
    (re.compile(r"['\"]\s*;\s*(select|insert|update|delete|drop|alter)", re.I), "sqli_stacked"),

    # Command injection
    (re.compile(r"[;&|`$]\s*(cat|ls|whoami|id|curl|wget|nc|bash|sh|python|perl)\b", re.I), "cmdi"),
    (re.compile(r"\$\([^)]+\)"), "cmdi_subshell"),
    (re.compile(r"`[^`]+`"), "cmdi_backtick"),

    # Path traversal
    (re.compile(r"\.\./\.\./"), "traversal"),
    (re.compile(r"\.\.\\\.\.\\"), "traversal_win"),
    (re.compile(r"%2e%2e(%2f|%5c)", re.I), "traversal_url"),

    # XSS
    (re.compile(r"<\s*script[^>]*>", re.I), "xss_script"),
    (re.compile(r"javascript\s*:", re.I), "xss_js"),
    (re.compile(r"on(error|load|click|mouse|focus)\s*=", re.I), "xss_event"),

    # Template / SSRF
    (re.compile(r"\{\{.{0,40}\}\}"), "template"),
    (re.compile(r"file://|gopher://|dict://", re.I), "ssrf"),

    # NoSQL
    (re.compile(r"\$where\b|\$ne\b", re.I), "nosqli"),
]

MAX_FIELD_LEN = 2000


def _scan(value: str):
    if not value or not isinstance(value, str):
        return None
    if len(value) > MAX_FIELD_LEN:
        return "oversized"
    for pattern, name in PATTERNS:
        if pattern.search(value):
            return name
    return None


def _iter_values():
    """Yield (source, key, value) for all input surfaces."""
    # query string
    for k, v in request.args.items():
        yield "query", k, v
    # form
    for k, v in request.form.items():
        yield "form", k, v
    # headers (specific ones only — User-Agent, Referer)
    for h in ("User-Agent", "Referer", "Origin"):
        v = request.headers.get(h)
        if v:
            yield "header", h, v
    # JSON body
    if request.is_json:
        try:
            data = request.get_json(silent=True)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, str):
                        yield "json", k, v
                    elif isinstance(v, list):
                        for i, item in enumerate(v):
                            if isinstance(item, str):
                                yield "json", f"{k}[{i}]", item
        except Exception:
            pass
    # path
    yield "path", "path", request.path


def waf_protect(fn):
    from functools import wraps

    @wraps(fn)
    def wrapped(*a, **kw):
        for source, key, value in _iter_values():
            hit = _scan(value)
            if hit:
                ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?")
                ip = ip.split(",")[0].strip()
                log.warning("WAF block ip=%s source=%s field=%s rule=%s value=%s",
                            ip, source, key, hit, value[:80])
                # ban repeat offenders
                try:
                    from core.ratelimit import ban_ip
                    ban_ip(ip, 1800)
                except Exception:
                    pass
                if request.path.startswith("/api") or request.is_json:
                    return jsonify({"ok": False, "error": "blocked"}), 403
                abort(403)
        return fn(*a, **kw)
    return wrapped
