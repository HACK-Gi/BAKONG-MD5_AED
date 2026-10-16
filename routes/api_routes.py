import time
import re
from flask import Blueprint, request, jsonify
from core.apikey import find_key, touch_key, log_usage, user_has_active_sub
from core.bakong import get_bakong, BakongError
from core.config import Config
from core.security import safe_error

bp = Blueprint("api", __name__)
MD5_RE = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)

_hits = {}
_HITS_MAX_KEYS = 5000


def _rate(key_id: int) -> bool:
    now = time.time()
    # bounded cleanup
    if len(_hits) > _HITS_MAX_KEYS:
        stale = [k for k, v in _hits.items() if not v or now - v[-1] > 120]
        for k in stale:
            _hits.pop(k, None)
    b = _hits.setdefault(key_id, [])
    b[:] = [t for t in b if now - t < 60]
    if len(b) >= Config.API_RATE_PER_MIN:
        return False
    b.append(now)
    return True


def _extract_key(req) -> str:
    k = req.args.get("key") or req.args.get("api_key")
    if k:
        return k.strip()
    k = req.headers.get("X-API-Key")
    if k:
        return k.strip()
    auth = req.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def _whitelist_response(bakong_body: dict) -> dict:
    if not isinstance(bakong_body, dict):
        return {"responseCode": 500, "message": "invalid upstream"}
    out = {
        "responseCode": bakong_body.get("responseCode"),
        "responseMessage": bakong_body.get("responseMessage"),
        "errorCode": bakong_body.get("errorCode"),
    }
    data = bakong_body.get("data")
    if isinstance(data, dict):
        out["data"] = {
            "hash": data.get("hash"),
            "md5": data.get("md5"),
            "amount": data.get("amount"),
            "currency": data.get("currency"),
            "fromAccountId": data.get("fromAccountId"),
            "toAccountId": data.get("toAccountId"),
            "paidAt": data.get("paidAt") or data.get("createdDate"),
            "status": data.get("status"),
        }
    return out


def _handle(md5: str, key: str):
    if not key:
        return jsonify({"responseCode": 401, "message": "missing api key"}), 401
    k = find_key(key)
    if not k:
        return jsonify({"responseCode": 401, "message": "invalid api key"}), 401
    if not user_has_active_sub(k["user_id"]):
        return jsonify({"responseCode": 402, "message": "subscription expired"}), 402
    from core.ratelimit import check_rate
    ok, _, retry = check_rate(f"k:{k['id']}", "/api_md5", Config.API_RATE_PER_MIN)
    if not ok:
        resp = jsonify({"responseCode": 429, "message": "rate limit"})
        resp.headers["Retry-After"] = str(retry)
        return resp, 429
    if not md5 or not MD5_RE.match(md5):
        touch_key(k["id"])
        log_usage(k["id"], md5 or "", "invalid")
        return jsonify({"responseCode": 400, "message": "invalid md5 format"}), 400

    md5 = md5.lower()
    touch_key(k["id"])

    try:
        bakong = get_bakong()
        body = bakong.check_md5(md5)
    except BakongError as e:
        log_usage(k["id"], md5, "error")
        return jsonify({"responseCode": 502, "message": safe_error(str(e), "upstream error")}), 502

    mirrored = _whitelist_response(body)
    status = "found" if mirrored.get("responseCode") == 0 else "not_found"
    log_usage(k["id"], md5, status)
    return jsonify(mirrored), 200


@bp.route("/api_md5", methods=["POST"])
def api_md5_post():
    data = request.get_json(silent=True) or {}
    md5 = (data.get("md5") or "").strip()
    key = data.get("key") or data.get("api_key") or _extract_key(request)
    return _handle(md5, key)


@bp.route("/api_md5/<md5>", methods=["GET"])
def api_md5_path(md5: str):
    return _handle(md5.strip(), _extract_key(request))


@bp.route("/api_md5", methods=["GET"])
def api_md5_get():
    raw = request.args.get("md5") or request.args.get("api_md5") or ""
    return _handle(raw.strip(), _extract_key(request))


@bp.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "ts": int(time.time())})
