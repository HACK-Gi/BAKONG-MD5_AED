import time
from flask import (
    Blueprint, request, jsonify, session, render_template,
    redirect, url_for,
)
from core.db import query, execute
from core.auth import (
    hash_password, verify_password, valid_email, valid_password,
    create_session, destroy_session, current_user, is_verified,
    verification_required,
)
from core.config import Config
from core.security import csrf_protect, is_locked, record_fail, clear_attempts, sec_log
from core.oauth import register_google, google_enabled, get_google
from core.tokens import (
    issue_verify_token, consume_verify_token, resend_cooldown_left,
    issue_login_otp, verify_login_otp, otp_resend_cooldown_left, clear_login_otp,
)
from core.emailer import send_verify_email, send_welcome_email, send_otp_email

bp = Blueprint("auth", __name__)


# ---------- register ----------

@bp.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html", google=google_enabled())


@bp.route("/api/register", methods=["POST"])
@csrf_protect
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not valid_email(email):
        return jsonify({"ok": False, "error": "invalid email"}), 400

    ok, reason = valid_password(password)
    if not ok:
        return jsonify({"ok": False, "error": reason}), 400

    existing = query("SELECT id, email_verified FROM users WHERE email=?", (email,), one=True)
    if existing:
        # If already registered but unverified → resend + redirect
        if not existing["email_verified"]:
            token = issue_verify_token(existing["id"])
            send_verify_email(email, token)
            return jsonify({
                "ok": True,
                "redirect": f"/verify-pending?email={email}",
                "resent": True,
            })
        return jsonify({"ok": False, "error": "email already registered"}), 409

    uid = execute(
        "INSERT INTO users(email, password_hash, created_at, email_verified) VALUES (?, ?, ?, 0)",
        (email, hash_password(password), int(time.time())),
    )
    execute("INSERT INTO subscriptions(user_id, status) VALUES (?, 'pending')", (uid,))
    sec_log("register_pending", uid=uid, email=email)

    # mode=off → auto-verify + session
    if Config.EMAIL_MODE == "off":
        execute("UPDATE users SET email_verified=1 WHERE id=?", (uid,))
        create_session(uid)
        return jsonify({"ok": True, "redirect": "/dashboard"})

    token = issue_verify_token(uid)
    sent = send_verify_email(email, token)
    sec_log("verify_sent", uid=uid, email=email, sent=sent)

    # NO session yet — force verify first
    return jsonify({
        "ok": True,
        "redirect": f"/verify-pending?email={email}",
        "email_sent": sent,
    })


# ---------- login ----------

@bp.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html", google=google_enabled())


@bp.route("/api/login", methods=["POST"])
@csrf_protect
def login():
    """Step 1 — validate password, issue OTP, send code."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"ok": False, "error": "missing credentials"}), 400

    if is_locked(email):
        sec_log("login_locked", email=email)
        return jsonify({"ok": False, "error": "account locked — try again later"}), 429

    row = query(
        "SELECT id, password_hash FROM users WHERE email=?",
        (email,), one=True,
    )
    if not row or not row["password_hash"] or not verify_password(row["password_hash"], password):
        record_fail(email)
        sec_log("login_fail", email=email)
        return jsonify({"ok": False, "error": "invalid email or password"}), 401

    clear_attempts(email)

    # mode=off → bypass OTP entirely (dev only)
    if Config.EMAIL_MODE == "off":
        create_session(row["id"])
        sec_log("login_ok_no_otp", uid=row["id"], email=email)
        return jsonify({"ok": True, "redirect": "/dashboard"})

    # issue OTP
    code = issue_login_otp(email)
    sent = send_otp_email(email, code)
    sec_log("login_otp_sent", uid=row["id"], email=email, sent=sent)

    resp = {
        "ok": True,
        "redirect": f"/login-otp?email={email}",
        "otp_sent": sent,
    }
    # DEV ONLY — expose OTP in response when console mode
    if Config.EMAIL_MODE == "console":
        resp["dev_otp"] = code
    return jsonify(resp)


@bp.route("/login-otp", methods=["GET"])
def login_otp_page():
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return redirect(url_for("auth.login_page"))
    row = query("SELECT id FROM users WHERE email=?", (email,), one=True)
    if not row:
        return redirect(url_for("auth.login_page"))
    cooldown = otp_resend_cooldown_left(email)
    return render_template("login_otp.html", email=email, cooldown=cooldown)


@bp.route("/api/login/otp", methods=["POST"])
@csrf_protect
def login_otp_submit():
    """Step 2 — validate OTP, create session."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    code = (data.get("code") or "").strip()

    if not email or not code:
        return jsonify({"ok": False, "error": "missing"}), 400

    row = query("SELECT id FROM users WHERE email=?", (email,), one=True)
    if not row:
        return jsonify({"ok": False, "error": "invalid"}), 401

    if is_locked(email):
        return jsonify({"ok": False, "error": "account locked"}), 429

    ok, reason = verify_login_otp(email, code)
    if not ok:
        sec_log("otp_fail", email=email, reason=reason)
        msgs = {
            "invalid_code": "កូដត្រូវមាន 6 ខ្ទង់",
            "no_otp": "គ្មានកូដសកម្ម — ចុចផ្ញើឡើងវិញ",
            "expired": "កូដផុតកំណត់ — សូមផ្ញើឡើងវិញ",
            "wrong_code": "កូដមិនត្រឹមត្រូវ",
            "too_many_attempts": "ព្យាយាមច្រើនពេក — សូមផ្ញើឡើងវិញ",
        }
        return jsonify({"ok": False, "error": msgs.get(reason, "invalid")}), 401

    # success — mark email verified (first successful OTP = verified)
    execute("UPDATE users SET email_verified=1 WHERE id=?", (row["id"],))
    create_session(row["id"])
    sec_log("login_otp_ok", uid=row["id"], email=email)
    return jsonify({"ok": True, "redirect": "/dashboard"})


@bp.route("/api/login/resend-otp", methods=["POST"])
@csrf_protect
def login_resend_otp():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify({"ok": False, "error": "missing email"}), 400

    row = query("SELECT id FROM users WHERE email=?", (email,), one=True)
    if not row:
        # don't leak — pretend ok
        return jsonify({"ok": True, "cooldown": 60})

    left = otp_resend_cooldown_left(email)
    if left > 0:
        return jsonify({"ok": False, "error": f"wait {left}s", "cooldown": left}), 429

    code = issue_login_otp(email)
    sent = send_otp_email(email, code)
    sec_log("otp_resend", email=email, sent=sent)
    resp = {"ok": True, "sent": sent, "cooldown": 60}
    if Config.EMAIL_MODE == "console":
        resp["dev_otp"] = code
    return jsonify(resp)


# ---------- logout ----------

@bp.route("/logout", methods=["POST", "GET"])
def logout():
    sid = session.get("sid")
    if sid:
        destroy_session(sid)
        sec_log("logout")
    session.clear()
    return redirect(url_for("dashboard.index"))


# ---------- verify pending page ----------

@bp.route("/verify-pending")
def verify_pending_page():
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return redirect(url_for("auth.login_page"))

    row = query("SELECT id, email_verified FROM users WHERE email=?", (email,), one=True)
    if not row:
        return redirect(url_for("auth.register_page"))
    if row["email_verified"]:
        # already verified → go to login
        return redirect(url_for("auth.login_page"))

    cooldown = resend_cooldown_left(row["id"])
    return render_template("verify_pending.html", email=email, cooldown=cooldown)


@bp.route("/api/verify/resend", methods=["POST"])
@csrf_protect
def api_resend():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not valid_email(email):
        return jsonify({"ok": False, "error": "invalid email"}), 400

    row = query("SELECT id, email_verified FROM users WHERE email=?", (email,), one=True)
    if not row:
        # Don't leak — pretend OK
        return jsonify({"ok": True, "cooldown": 60})
    if row["email_verified"]:
        return jsonify({"ok": True, "verified": True, "redirect": "/login"})

    left = resend_cooldown_left(row["id"])
    if left > 0:
        return jsonify({"ok": False, "error": f"wait {left}s", "cooldown": left}), 429

    token = issue_verify_token(row["id"])
    sent = send_verify_email(email, token)
    sec_log("verify_resend", uid=row["id"], email=email, sent=sent)
    return jsonify({"ok": True, "sent": sent, "cooldown": 60})


# ---------- verify link ----------

@bp.route("/verify/<token>")
def verify_email(token: str):
    uid = consume_verify_token(token)
    if not uid:
        return render_template("verify_result.html", ok=False,
                              message="Link មិនត្រឹមត្រូវ ឬ ផុតកំណត់")

    execute("UPDATE users SET email_verified=1 WHERE id=?", (uid,))
    row = query("SELECT email FROM users WHERE id=?", (uid,), one=True)

    # auto-login after verify
    create_session(uid)
    sec_log("email_verified", uid=uid, email=row["email"] if row else "?")

    if row:
        send_welcome_email(row["email"])

    return render_template("verify_result.html", ok=True,
                          message="អ៊ីមែលបានបញ្ជាក់រួចរាល់ — កំពុងបញ្ជូនទៅ dashboard...")


# ---------- google oauth ----------

@bp.route("/auth/google")
def google_login():
    if not google_enabled():
        return "Google login not configured", 503
    client = get_google()
    redirect_uri = url_for("auth.google_callback", _external=True)
    return client.authorize_redirect(redirect_uri)


@bp.route("/auth/google/callback")
def google_callback():
    if not google_enabled():
        return "Google login not configured", 503

    client = get_google()
    try:
        token = client.authorize_access_token()
    except Exception as e:
        sec_log("google_oauth_fail", err=str(e)[:100])
        return redirect(url_for("auth.login_page"))

    userinfo = token.get("userinfo") or {}
    google_id = userinfo.get("sub")
    email = (userinfo.get("email") or "").lower().strip()
    name = userinfo.get("name") or ""
    picture = userinfo.get("picture") or ""
    email_verified = userinfo.get("email_verified", False)

    if not google_id or not email:
        return redirect(url_for("auth.login_page"))

    row = query("SELECT id FROM users WHERE google_id=?", (google_id,), one=True)
    if not row:
        row = query("SELECT id FROM users WHERE email=?", (email,), one=True)
        if row:
            execute(
                "UPDATE users SET google_id=?, email_verified=?, display_name=COALESCE(display_name,?), avatar_url=COALESCE(avatar_url,?) WHERE id=?",
                (google_id, 1 if email_verified else 0, name, picture, row["id"]),
            )
        else:
            uid = execute(
                """INSERT INTO users(email, password_hash, created_at, google_id, email_verified, display_name, avatar_url)
                   VALUES (?, NULL, ?, ?, ?, ?, ?)""",
                (email, int(time.time()), google_id, 1 if email_verified else 0, name, picture),
            )
            execute("INSERT INTO subscriptions(user_id, status) VALUES (?, 'pending')", (uid,))
            row = {"id": uid}
            sec_log("google_register", uid=uid, email=email)

    create_session(row["id"])
    sec_log("google_login_ok", uid=row["id"], email=email)
    return redirect(url_for("dashboard.dashboard"))


# ---------- me ----------

@bp.route("/api/me", methods=["GET"])
def me():
    u = current_user()
    if not u:
        return jsonify({"ok": False}), 401
    sub = query("SELECT status, expires_at FROM subscriptions WHERE user_id=?", (u["id"],), one=True)
    row = query("SELECT email_verified, display_name, avatar_url FROM users WHERE id=?", (u["id"],), one=True)
    return jsonify({
        "ok": True,
        "user": {
            "id": u["id"],
            "email": u["email"],
            "email_verified": bool(row["email_verified"]) if row else False,
            "display_name": row["display_name"] if row else None,
            "avatar_url": row["avatar_url"] if row else None,
        },
        "subscription": dict(sub) if sub else None,
    })
