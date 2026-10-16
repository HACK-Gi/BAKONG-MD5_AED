import smtplib
import ssl
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from core.config import Config

log = logging.getLogger("email")


def _smtp_ready() -> bool:
    return bool(Config.SMTP_HOST and Config.SMTP_USER and Config.SMTP_PASSWORD)


def _print_console(to: str, subject: str, text: str, reason: str = ""):
    bar = "=" * 72
    print(f"\n{bar}")
    print("EMAIL — console fallback")
    if reason:
        print(f"   reason:  {reason}")
    print(f"   to:      {to}")
    print(f"   subject: {subject}")
    print("   ---")
    for line in (text or "").splitlines():
        if line.strip():
            print(f"   {line}")
    print(f"{bar}\n")


def _send_via_resend(to: str, subject: str, html: str, text: str = "") -> bool:
    if not Config.RESEND_API_KEY:
        log.warning("RESEND_API_KEY missing")
        _print_console(to, subject, text or html, "resend key missing")
        return False
    try:
        import resend
    except ImportError:
        _print_console(to, subject, text or html, "resend module not installed")
        return False

    resend.api_key = Config.RESEND_API_KEY
    params = {
        "from": Config.SMTP_FROM,
        "to": [to],
        "subject": subject,
        "html": html,
        "text": text or html,
    }
    try:
        r = resend.Emails.send(params)
        rid = r.get("id") if isinstance(r, dict) else getattr(r, "id", None)
        log.info("resend sent to=%s id=%s", to, rid)
        return True
    except Exception as e:
        log.error("resend fail to=%s err=%s", to, e)
        _print_console(to, subject, text or html, f"resend error: {e}")
        return False


def _send_via_smtp(to: str, subject: str, html: str, text: str = "") -> bool:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = Config.SMTP_FROM
    msg["To"] = to
    if not text:
        text = html.replace("<br>", "\n").replace("</p>", "\n")
    msg.attach(MIMEText(text, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT, timeout=20) as s:
            s.ehlo()
            s.starttls(context=ctx)
            s.ehlo()
            s.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
            s.sendmail(Config.SMTP_USER, [to], msg.as_string())
        log.info("smtp sent to=%s", to)
        return True
    except Exception as e:
        log.error("smtp fail to=%s err=%s", to, e)
        _print_console(to, subject, text, f"smtp error: {e}")
        return False


def send_email(to: str, subject: str, html: str, text: str = "") -> bool:
    mode = Config.EMAIL_MODE

    if mode == "off":
        log.info("[email/off] to=%s subj=%s", to, subject)
        return True

    if mode == "resend":
        return _send_via_resend(to, subject, html, text)

    if mode == "console" or not _smtp_ready():
        _print_console(to, subject, text or html, f"mode={mode}")
        return True

    return _send_via_smtp(to, subject, html, text)


# ---------- high-level senders ----------

def send_verify_email(to: str, token: str) -> bool:
    url = f"{Config.PUBLIC_BASE_URL}/verify/{token}"
    subject = "បញ្ជាក់អ៊ីមែលរបស់អ្នក — MD5·Check"
    text = f"បញ្ជាក់អ៊ីមែលរបស់អ្នក:\n\n{url}\n\nLink ផុតកំណត់ក្នុង 24 ម៉ោង។"
    html = f"""
    <div style="font-family:system-ui,sans-serif;max-width:520px;margin:auto;padding:24px;background:#0b0d10;color:#e8eaed;border-radius:12px;">
      <h2 style="color:#4f8cff;margin:0 0 16px;">MD5·Check</h2>
      <p>សូមបញ្ជាក់អ៊ីមែលរបស់អ្នក។</p>
      <p style="margin:24px 0;">
        <a href="{url}" style="background:#4f8cff;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;display:inline-block;font-weight:600;">បញ្ជាក់អ៊ីមែល</a>
      </p>
      <p style="color:#8b929c;font-size:13px;">ឬ link: {url}</p>
      <p style="color:#8b929c;font-size:12px;">ផុតកំណត់ 24 ម៉ោង។</p>
    </div>
    """
    return send_email(to, subject, html, text)


def send_otp_email(to: str, code: str) -> bool:
    subject = f"លេខកូដចូល: {code} — MD5·Check"
    text = f"លេខកូដចូល MD5·Check:\n\n    {code}\n\nផុតកំណត់ក្នុង 10 នាទី។"
    html = f"""
    <div style="font-family:system-ui,sans-serif;max-width:520px;margin:auto;padding:24px;background:#0b0d10;color:#e8eaed;border-radius:12px;">
      <h2 style="color:#4f8cff;margin:0 0 8px;">MD5·Check</h2>
      <p style="color:#b8bcc4;">លេខកូដចូល:</p>
      <div style="font-family:monospace;font-size:36px;font-weight:700;letter-spacing:8px;color:#fff;background:#14171d;border:1px solid #23272e;border-radius:10px;padding:20px;text-align:center;margin:20px 0;">{code}</div>
      <p style="color:#8b929c;font-size:13px;">ផុតកំណត់ក្នុង 10 នាទី។</p>
    </div>
    """
    return send_email(to, subject, html, text)


def send_welcome_email(to: str) -> bool:
    subject = "សូមស្វាគមន៍មក MD5·Check"
    text = f"គណនី {to} បានបញ្ជាក់រួច។ {Config.PUBLIC_BASE_URL}/dashboard"
    html = f"""
    <div style="font-family:system-ui,sans-serif;max-width:520px;margin:auto;padding:24px;background:#0b0d10;color:#e8eaed;border-radius:12px;">
      <h2 style="color:#4f8cff;">MD5·Check</h2>
      <p>គណនី <b>{to}</b> បានបញ្ជាក់រួច។</p>
      <p><a href="{Config.PUBLIC_BASE_URL}/dashboard" style="color:#4f8cff;">{Config.PUBLIC_BASE_URL}/dashboard</a></p>
    </div>
    """
    return send_email(to, subject, html, text)
