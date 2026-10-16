import os
import logging
from flask import Flask, jsonify, request, session, abort, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

from core.config import Config
from core.db import init_db
from core.security import generate_csrf
from core.oauth import register_google
from core.ratelimit import check_rate, client_ip, LIMITS, is_banned, ban_ip
from core.waf import _scan, _iter_values

from routes.auth_routes import bp as auth_bp
from routes.dashboard_routes import bp as dash_bp
from routes.key_routes import bp as key_bp
from routes.payment_routes import bp as pay_bp
from routes.api_routes import bp as api_bp

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("app")


def _check_production_secrets():
    if os.getenv("FLASK_ENV") == "production":
        if Config.SECRET_KEY in ("dev-only-change-me", "", None):
            raise RuntimeError("SECRET_KEY must be set in production")


def create_app():
    _check_production_secrets()

    app = Flask(__name__, static_folder="static", template_folder="templates")

    # Render/proxy support — trust X-Forwarded-* headers
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1,
    )
    app.config.from_object(Config)
    app.config["MAX_CONTENT_LENGTH"] = 128 * 1024
    app.config["TRUSTED_HOSTS"] = None  # disable strict host check (proxy handles it)
    app.config["MAX_FORM_MEMORY_SIZE"] = 128 * 1024

    init_db()
    register_google(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(dash_bp)
    app.register_blueprint(key_bp)
    app.register_blueprint(pay_bp)
    app.register_blueprint(api_bp)

    app.jinja_env.globals["csrf_token"] = generate_csrf

    # ---------------- global shield ----------------
    @app.before_request
    def global_shield():
        ip = client_ip()

        if is_banned(ip):
            return jsonify({"ok": False, "error": "banned"}), 403

        # route class
        p = request.path
        if p.startswith("/static"):
            route_class = "static"
        elif p.startswith("/api/login") or p.startswith("/api/register"):
            route_class = "auth"
        elif p.startswith("/api/") or p.startswith("/api_md5"):
            route_class = "api"
        elif p.startswith("/pay"):
            route_class = "pay"
        else:
            route_class = "default"

        limit = LIMITS.get(route_class, LIMITS["default"])
        ok, _remaining, retry = check_rate(ip, p, limit)
        if not ok:
            resp = jsonify({"ok": False, "error": "rate limit"})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry)
            return resp

        # WAF — scan write requests
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            for source, key, value in _iter_values():
                hit = _scan(value)
                if hit:
                    ban_ip(ip, 1800)
                    log.warning(
                        "WAF block ip=%s src=%s field=%s rule=%s value=%s",
                        ip, source, key, hit, (value or "")[:80],
                    )
                    if p.startswith("/api") or request.is_json:
                        return jsonify({"ok": False, "error": "blocked"}), 403
                    abort(403)

    # ---------------- security headers ----------------
    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        resp.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        resp.headers["X-Download-Options"] = "noopen"
        resp.headers["X-DNS-Prefetch-Control"] = "off"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none'; "
            "media-src 'none'; "
            "worker-src 'none'"
        )
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    # ---------------- errors ----------------
    @app.errorhandler(403)
    def forbidden(e):
        if request.path.startswith("/api") or request.is_json:
            return jsonify({"ok": False, "error": "forbidden"}), 403
        return "<h1>403 Forbidden</h1>", 403

    @app.errorhandler(403)
    def forbidden(e):
        if request.path.startswith("/api") or request.is_json:
            return jsonify({"ok": False, "error": "forbidden"}), 403
        return render_template("error.html", code=403, title="Forbidden",
                               message="អ្នកមិនមានសិទ្ធិចូលទំព័រនេះទេ"), 403

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api") or request.is_json:
            return jsonify({"responseCode": 404, "message": "not found"}), 404
        return render_template("error.html", code=404, title="រកមិនឃើញ",
                               message="ទំព័រដែលអ្នកស្វែងរកមិនមានទេ"), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        if request.path.startswith("/api") or request.is_json:
            return jsonify({"ok": False, "error": "method not allowed"}), 405
        return render_template("error.html", code=405, title="Method មិនត្រឹមត្រូវ",
                               message="វិធីនេះមិនត្រូវបានអនុញ្ញាតទេ"), 405

    @app.errorhandler(413)
    def too_large(e):
        return jsonify({"ok": False, "error": "payload too large"}), 413

    @app.errorhandler(429)
    def rate_limited(e):
        if request.path.startswith("/api") or request.is_json:
            return jsonify({"ok": False, "error": "rate limit"}), 429
        return render_template("error.html", code=429, title="ច្រើនពេក",
                               message="សូមរង់ចាំបន្តិច រួចព្យាយាមម្ដងទៀត"), 429

    @app.errorhandler(500)
    def server_error(e):
        if request.path.startswith("/api") or request.is_json:
            return jsonify({"responseCode": 500, "message": "internal error"}), 500
        return render_template("error.html", code=500, title="Server Error",
                               message="មានបញ្ហាខាងក្នុង — សូមព្យាយាមម្ដងទៀត"), 500

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
