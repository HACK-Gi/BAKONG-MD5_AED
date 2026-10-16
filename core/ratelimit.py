"""
Global multi-layer rate limiter.
- per-IP bucket
- per-route bucket
- auto-ban on abuse
- in-memory with bounded map
"""
import time
import threading
from collections import defaultdict
from flask import request, jsonify
from functools import wraps

_lock = threading.Lock()
_ip_hits = defaultdict(list)       # ip -> [timestamps]
_route_hits = defaultdict(list)     # (ip, route) -> [timestamps]
_banned = {}                        # ip -> ban_until

MAX_IPS_TRACKED = 10000
BAN_DURATION = 60 * 30              # 30 min
BAN_THRESHOLD = 200                 # abuse hits/min triggers ban

# Limits per minute
LIMITS = {
    "default":   120,
    "auth":      10,
    "api":       120,
    "pay":       30,
    "static":    600,
}


def _cleanup(now):
    """Bound memory — drop stale entries."""
    if len(_ip_hits) > MAX_IPS_TRACKED:
        stale = [ip for ip, ts in _ip_hits.items() if not ts or now - ts[-1] > 120]
        for ip in stale:
            _ip_hits.pop(ip, None)
    if len(_route_hits) > MAX_IPS_TRACKED * 2:
        stale = [k for k, ts in _route_hits.items() if not ts or now - ts[-1] > 120]
        for k in stale:
            _route_hits.pop(k, None)


def client_ip():
    """Trust X-Forwarded-For only behind a proxy; otherwise use remote_addr."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "?"


def check_rate(ip: str, route: str, limit: int) -> tuple:
    """Returns (ok: bool, remaining: int, retry_after: int)."""
    now = time.time()
    with _lock:
        _cleanup(now)

        # banned?
        until = _banned.get(ip)
        if until and until > now:
            return False, 0, int(until - now)

        # global per-IP
        bucket = _ip_hits[ip]
        bucket[:] = [t for t in bucket if now - t < 60]
        if len(bucket) >= BAN_THRESHOLD:
            _banned[ip] = now + BAN_DURATION
            return False, 0, BAN_DURATION
        bucket.append(now)

        # per-route
        key = (ip, route)
        r = _route_hits[key]
        r[:] = [t for t in r if now - t < 60]
        if len(r) >= limit:
            return False, 0, 60 - int(now - r[0])
        r.append(now)

    return True, limit - len(r), 0


def rate_limit(route_class: str = "default"):
    def deco(fn):
        @wraps(fn)
        def wrapped(*a, **kw):
            limit = LIMITS.get(route_class, LIMITS["default"])
            ip = client_ip()
            ok, remaining, retry = check_rate(ip, request.path, limit)
            if not ok:
                resp = jsonify({"ok": False, "error": "rate limit — slow down"})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(retry)
                return resp
            return fn(*a, **kw)
        return wrapped
    return deco


def ban_ip(ip: str, seconds: int = BAN_DURATION):
    with _lock:
        _banned[ip] = time.time() + seconds


def is_banned(ip: str) -> bool:
    with _lock:
        until = _banned.get(ip)
        return bool(until and until > time.time())
