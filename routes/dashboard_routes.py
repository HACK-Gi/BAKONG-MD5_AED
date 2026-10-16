import time
from flask import Blueprint, render_template
from core.auth import login_required, current_user
from core.db import query
from core.plans import all_plans

bp = Blueprint("dashboard", __name__)

@bp.route("/")
def index():
    return render_template("index.html")

@bp.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    sub = query("SELECT status, expires_at FROM subscriptions WHERE user_id = ?", (u["id"],), one=True)
    keys = query("SELECT id, key_prefix, name, revoked, created_at, last_used FROM api_keys WHERE user_id = ? ORDER BY id DESC", (u["id"],))
    now = int(time.time())
    sub_dict = dict(sub) if sub else {"status": "pending", "expires_at": None}
    sub_dict["active"] = (sub_dict["status"] == "active" and sub_dict["expires_at"] and sub_dict["expires_at"] > now)
    return render_template("dashboard.html", user=u, sub=sub_dict, keys=[dict(k) for k in keys])

@bp.route("/pricing")
def pricing():
    return render_template("pricing.html", plans=all_plans(), choose=False)


@bp.route("/docs")
def docs():
    from flask import render_template
    return render_template("docs.html")
