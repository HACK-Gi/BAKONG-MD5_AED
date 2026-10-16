from authlib.integrations.flask_client import OAuth
from core.config import Config

oauth = OAuth()
_google_registered = False


def register_google(app):
    global _google_registered
    if _google_registered:
        return
    oauth.init_app(app)
    if Config.GOOGLE_CLIENT_ID and Config.GOOGLE_CLIENT_SECRET:
        oauth.register(
            name="google",
            client_id=Config.GOOGLE_CLIENT_ID,
            client_secret=Config.GOOGLE_CLIENT_SECRET,
            server_metadata_url=Config.GOOGLE_DISCOVERY_URL,
            client_kwargs={"scope": "openid email profile"},
        )
    _google_registered = True


def google_enabled() -> bool:
    return bool(Config.GOOGLE_CLIENT_ID and Config.GOOGLE_CLIENT_SECRET)


def get_google():
    return oauth.create_client("google") if google_enabled() else None
