import os
import json
import requests
from core.config import Config


class BakongError(Exception):
    pass


class BakongClient:
    TIMEOUT = 20

    def __init__(self):
        self.base = Config.BAKONG_BASE.rstrip("/")
        self.proxy = os.getenv("BAKONG_PROXY", "").strip() or None
        self.token = Config.BAKONG_TOKEN
        self.account = Config.BAKONG_ACCOUNT
        if not self.token:
            raise BakongError("BAKONG_TOKEN missing in .env")
        try:
            from bakong_khqr import KHQR
        except ImportError:
            raise BakongError("bakong-khqr not installed")
        if self.proxy:
            try:
                import requests as _rq
                _orig = _rq.Session.request
                _proxy = self.proxy
                def _patched(self_, method, url, **kw):
                    kw.setdefault("proxies", {"http": _proxy, "https": _proxy})
                    return _orig(self_, method, url, **kw)
                _rq.Session.request = _patched
            except Exception:
                pass
        self._khqr = KHQR(self.token)

    # --- QR generation ---
    def create_qr(self, amount, bill_number, currency="USD"):
        if not self.account:
            raise BakongError("BAKONG_ACCOUNT missing in .env")
        try:
            qr = self._khqr.create_qr(
                bank_account=self.account,
                merchant_name=Config.BAKONG_MERCHANT_NAME,
                merchant_city=Config.BAKONG_MERCHANT_CITY,
                amount=float(amount),
                currency=currency,
                store_label=Config.BAKONG_MERCHANT_NAME,
                phone_number=Config.BAKONG_PHONE,
                bill_number=bill_number,
                terminal_label="Web",
                static=False,
            )
        except Exception as e:
            raise BakongError(f"KHQR create failed: {e}")
        try:
            md5 = self._khqr.generate_md5(qr)
        except Exception as e:
            raise BakongError(f"KHQR md5 failed: {e}")
        return {"qr": qr, "md5": md5}

    # --- Payment check (bakong_khqr lib returns str OR dict depending on version) ---
    def check_payment(self, md5):
        try:
            raw = self._khqr.check_payment(md5)
        except Exception as e:
            raise BakongError(f"check_payment failed: {e}")
        return self._normalize_check(raw)

    @staticmethod
    def _normalize_check(raw):
        """Return canonical dict: {responseCode, responseMessage, data}"""
        # Case 1: already dict
        if isinstance(raw, dict):
            return raw

        # Case 2: JSON string
        if isinstance(raw, (str, bytes)):
            text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
            text = text.strip()
            # try JSON decode
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return parsed
            except (ValueError, TypeError):
                pass

            # Case 3: plain status strings from some library versions
            low = text.lower()
            if low in ("success", "ok", "paid", "found"):
                return {"responseCode": 0, "responseMessage": text, "data": {}}
            if low in ("not_found", "not found", "pending", "unpaid", ""):
                return {"responseCode": 1, "responseMessage": text or "not found", "data": {}}
            # unknown string — treat as error but log it
            return {"responseCode": -1, "responseMessage": text[:200], "data": {}}

        # Case 4: None
        if raw is None:
            return {"responseCode": 1, "responseMessage": "not found", "data": {}}

        # Fallback — unknown type
        return {"responseCode": -1, "responseMessage": f"unexpected: {type(raw).__name__}", "data": {}}

    # --- Fallback HTTP check (library may lie) ---
    def check_payment_http(self, md5):
        """Direct HTTP call — Bakong's own endpoint"""
        return self.check_md5(md5)

    # --- Raw HTTP (for API mirror endpoint) ---
    def check_md5(self, md5):
        url = f"{self.base}/v1/check_transaction_by_md5"
        try:
            proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
            r = requests.post(
                url,
                json={"md5": md5},
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                },
                timeout=self.TIMEOUT,
                proxies=proxies,
            )
        except requests.Timeout:
            raise BakongError("Bakong timeout")
        except requests.RequestException as e:
            raise BakongError(f"network: {e}")

        if r.status_code == 401:
            raise BakongError("Bakong token invalid")
        if r.status_code == 403:
            raise BakongError("Bakong 403 — IP not whitelisted?")

        try:
            return r.json()
        except ValueError:
            raise BakongError(f"non-JSON ({r.status_code})")


_bakong = None


def get_bakong():
    global _bakong
    if _bakong is None:
        _bakong = BakongClient()
    return _bakong
