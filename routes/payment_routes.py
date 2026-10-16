import io, time, secrets, logging, qrcode
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, send_file
from core.auth import login_required, current_user
from core.config import Config
from core.db import query, execute
from core.bakong import get_bakong, BakongError
from core.plans import all_plans, get_plan
from core.security import csrf_protect, safe_error, sec_log

log = logging.getLogger("payment")
bp = Blueprint("payment", __name__, url_prefix="/pay")

@bp.route("/", methods=["GET"])
@login_required
def pay_page():
    plan_key = request.args.get("plan", "monthly")
    plan = get_plan(plan_key)
    if not plan:
        return redirect(url_for("payment.choose_plan"))
    u = current_user()
    now = int(time.time())
    execute("UPDATE payments SET status='cancelled' WHERE user_id=? AND status='pending'", (u["id"],))
    bill_number = f"INV-{u['id']}-{int(now)}-{secrets.token_hex(3)}"
    pid = execute(
        "INSERT INTO payments(user_id, amount, status, plan, bill_number, created_at) VALUES (?, ?, 'pending', ?, ?, ?)",
        (u["id"], plan["price"], plan["key"], bill_number, now),
    )
    try:
        bk = get_bakong()
        result = bk.create_qr(amount=plan["price"], bill_number=bill_number)
    except BakongError as e:
        return render_template("pay.html", error=str(e), plan=plan, payment_id=pid)
    execute("UPDATE payments SET md5=?, qr_md5=?, qr_string=? WHERE id=?", (result["md5"], result["md5"], result["qr"], pid))
    return render_template("pay.html", plan=plan, payment_id=pid, qr_string=result["qr"])

@bp.route("/choose", methods=["GET"])
@login_required
def choose_plan():
    return render_template("pricing.html", plans=all_plans(), choose=True)

@bp.route("/qr/<int:pid>.png", methods=["GET"])
@login_required
def qr_image(pid):
    u = current_user()
    row = query("SELECT bill_number, amount, qr_string FROM payments WHERE id=? AND user_id=?", (pid, u["id"]), one=True)
    if not row:
        return "not found", 404

    qr_text = row["qr_string"]
    if not qr_text:
        try:
            bk = get_bakong()
            result = bk.create_qr(amount=row["amount"], bill_number=row["bill_number"])
            qr_text = result["qr"]
            execute("UPDATE payments SET qr_string=? WHERE id=?", (qr_text, pid))
        except BakongError as e:
            return str(e), 502

    img = qrcode.make(qr_text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png", max_age=0)

@bp.route("/check", methods=["POST"])
@login_required
@csrf_protect
def check_payment():
    u = current_user()
    data = request.get_json(silent=True) or {}
    pid = data.get("payment_id")
    pay = query("SELECT id, md5, amount, status, plan FROM payments WHERE id=? AND user_id=?", (pid, u["id"]), one=True)
    if not pay:
        return jsonify({"ok": False, "error": "not found"}), 404
    if pay["status"] == "paid":
        return jsonify({"ok": True, "already_paid": True})
    if not pay["md5"]:
        return jsonify({"ok": False, "error": "no md5"}), 400
    try:
        bk = get_bakong()
    except BakongError as e:
        return jsonify({"ok": False, "error": safe_error(str(e), "payment gateway unavailable")}), 502
    last_err = None
    for attempt in range(2):
        result = None
        # 1) library check
        try:
            result = bk.check_payment(pay["md5"])
        except BakongError as e:
            last_err = str(e)
        log.info("lib check pid=%s attempt=%s resp=%s",
                 pay["id"], attempt + 1,
                 (result.get("responseCode") if isinstance(result, dict) else result))

        # 2) HTTP fallback — only if lib said not found
        if not (isinstance(result, dict) and result.get("responseCode") == 0):
            try:
                http_result = bk.check_payment_http(pay["md5"])
                log.info("http check pid=%s attempt=%s code=%s",
                         pay["id"], attempt + 1,
                         http_result.get("responseCode") if isinstance(http_result, dict) else http_result)
                if isinstance(http_result, dict) and http_result.get("responseCode") == 0:
                    result = http_result
            except BakongError as e:
                last_err = str(e)

        if isinstance(result, dict) and result.get("responseCode") == 0:
            plan = get_plan(pay["plan"]) or {"days": 30}
            now = int(time.time())
            expires = now + plan["days"] * 86400
            sub = query("SELECT expires_at FROM subscriptions WHERE user_id=?", (u["id"],), one=True)
            if sub and sub["expires_at"] and sub["expires_at"] > now:
                expires = sub["expires_at"] + plan["days"] * 86400
            execute(
                """INSERT INTO subscriptions(user_id, status, expires_at, last_payment_md5)
                   VALUES (?, 'active', ?, ?)
                   ON CONFLICT(user_id) DO UPDATE SET status='active', expires_at=excluded.expires_at, last_payment_md5=excluded.last_payment_md5""",
                (u["id"], expires, pay["md5"]),
            )
            execute("UPDATE payments SET status='paid', expires_at=? WHERE id=?", (expires, pay["id"]))
            return jsonify({"ok": True, "activated": True, "expires_at": expires})
        if attempt == 0:
            time.sleep(3)
    return jsonify({"ok": False, "error": last_err or "មិនទាន់ឃើញប្រាក់"}), 202

@bp.route("/status", methods=["GET"])
@login_required
def status():
    u = current_user()
    pid = request.args.get("payment_id")
    pay = query("SELECT status FROM payments WHERE id=? AND user_id=?", (pid, u["id"]), one=True)
    return jsonify({"status": pay["status"] if pay else "unknown"})
