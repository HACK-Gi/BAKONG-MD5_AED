#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from core.config import Config

BASE = "https://api.brevo.com/v3"


def get_public_ip():
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            r = requests.get(url, timeout=8)
            if r.ok:
                return r.text.strip()
        except Exception:
            continue
    return None


def headers():
    if not Config.BREVO_API_KEY:
        raise SystemExit("BREVO_API_KEY missing in .env")
    return {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": Config.BREVO_API_KEY,
    }


def try_endpoint(method, path, body=None):
    url = f"{BASE}{path}"
    r = requests.request(method, url, headers=headers(), json=body, timeout=15)
    print(f"  {method} {path} → {r.status_code}")
    try:
        print("    ", r.json())
    except Exception:
        print("    ", r.text[:300])
    return r


def main():
    ip = get_public_ip()
    if not ip:
        raise SystemExit("cannot get public IP")
    print(f"Public IP: {ip}\n")

    # try known endpoints
    candidates = [
        ("GET",  "/account/authorizedIps"),
        ("POST", "/account/authorizedIps", {"ip": ip}),
    ]
    for entry in candidates:
        method, path = entry[0], entry[1]
        body = entry[2] if len(entry) > 2 else None
        try_endpoint(method, path, body)
        print()


if __name__ == "__main__":
    main()
