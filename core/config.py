import os
from dotenv import load_dotenv

load_dotenv()

def _parse_plans(raw: str):
    plans = {}
    for item in (raw or "").split(","):
        parts = item.strip().split(":")
        if len(parts) != 3:
            continue
        key, days, price = parts
        try:
            plans[key] = {"days": int(days), "price": float(price)}
        except ValueError:
            continue
    return plans


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
    # Render = ephemeral FS → use /tmp
    _default_db = "/tmp/app.db" if os.getenv("RENDER") else "data/app.db"
    DB_PATH = os.getenv("DB_PATH", _default_db)

    BAKONG_BASE = os.getenv("BAKONG_BASE", "https://api-bakong.nbc.gov.kh")
    BAKONG_TOKEN = os.getenv("BAKONG_TOKEN", "").strip()
    BAKONG_ACCOUNT = os.getenv("BAKONG_ACCOUNT", "").strip()
    BAKONG_MERCHANT_NAME = os.getenv("BAKONG_MERCHANT_NAME", "Store").strip()
    BAKONG_MERCHANT_CITY = os.getenv("BAKONG_MERCHANT_CITY", "Phnom Penh").strip()
    BAKONG_PHONE = os.getenv("BAKONG_PHONE", "").strip()

    PLANS = _parse_plans(os.getenv("PLANS", "monthly:30:2.50"))

    API_RATE_PER_MIN = int(os.getenv("API_RATE_PER_MIN", "60"))
    LOGIN_RATE_PER_MIN = int(os.getenv("LOGIN_RATE_PER_MIN", "5"))


    # --- Email / OAuth ---
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
    GOOGLE_DISCOVERY_URL = os.getenv(
        "GOOGLE_DISCOVERY_URL",
        "https://accounts.google.com/.well-known/openid-configuration",
    )

    EMAIL_MODE = os.getenv("EMAIL_MODE", "console").strip().lower()
    SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "").strip()
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
    SMTP_FROM = os.getenv("SMTP_FROM", "no-reply@localhost").strip()
    BREVO_API_KEY = os.getenv("BREVO_API_KEY", "").strip()
    RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()

    PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    VERIFY_TOKEN_TTL = 60 * 60 * 24

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("FLASK_ENV") == "production"
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 24 * 7
