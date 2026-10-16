import time
from flask import Blueprint, request, jsonify
from core.auth import login_required, current_user
from core.apikey import generate_key, user_has_active_sub
from core.db import query, execute
from core.security import csrf_protect, sec_log

bp = Blueprint("keys", __name__, url_prefix="/api/keys")


@bp.route("", methods=["POST"])
@login_required
@csrf_protect
def create_key():
    u = current_user()
    if not user_has_active_sub(u["id"]):
        return jsonify({"ok": False, "error": "active subscription required"}), 402

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "default").strip()[:64]

    plain, h, prefix = generate_key()
    kid = execute(
        "INSERT INTO api_keys(user_id, key_hash, key_prefix, name, created_at) VALUES (?, ?, ?, ?, ?)",
        (u["id"], h, prefix, name, int(time.time())),
    )
    sec_log("key_create", uid=u["id"], kid=kid)
    return jsonify({"ok": True, "id": kid, "key": plain, "prefix": prefix})


@bp.route("", methods=["GET"])
@login_required
def list_keys():
    u = current_user()
    rows = query(
        "SELECT id, key_prefix, name, revoked, created_at, last_used FROM api_keys WHERE user_id = ? ORDER BY id DESC",
        (u["id"],),
    )
    return jsonify({"ok": True, "keys": [dict(r) for r in rows]})


@bp.route("/<int:kid>/revoke", methods=["POST"])
@login_required
@csrf_protect
def revoke_key(kid: int):
    u = current_user()
    row = query(
        "SELECT id FROM api_keys WHERE id = ? AND user_id = ?",
        (kid, u["id"]), one=True,
    )
    if not row:
        return jsonify({"ok": False, "error": "not found"}), 404
    execute("UPDATE api_keys SET revoked = 1 WHERE id = ?", (kid,))
    sec_log("key_revoke", uid=u["id"], kid=kid)
    return jsonify({"ok": True})
