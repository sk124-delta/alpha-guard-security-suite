"""Shared Supabase Auth helpers for AlphaGuard's Python code.

Supabase is the only authentication system. This module does not sign or verify tokens itself,
does not store passwords, and does not write to disk. It forwards sign-in and sign-up requests
to Supabase over HTTPS and reads the user back.

Env (set in Vercel and locally, never commit values):
  SUPABASE_URL        https://<project>.supabase.co
  SUPABASE_ANON_KEY   the public anon key (never the service-role key)
"""

import os
import re
from urllib.parse import urlsplit

import requests

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_PATTERN = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")
ADMIN_ROLES = frozenset({"admin", "legal"})
MIN_PASSWORD_LENGTH = 8
TIMEOUT = (3, 10)


class SupabaseAuthError(RuntimeError):
    """The message is written for the user, so it is safe to display."""


def _config() -> tuple[str, str]:
    url = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
    anon_key = os.getenv("SUPABASE_ANON_KEY", "").strip()
    if not url or not anon_key:
        raise SupabaseAuthError("Sign-in is not configured on this server.")
    if urlsplit(url).scheme != "https":
        raise SupabaseAuthError("SUPABASE_URL must start with https://.")
    return url, anon_key


def _json(response: requests.Response) -> dict:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def normalize_email(value: str) -> str:
    email = (value or "").strip().lower()
    if not EMAIL_PATTERN.fullmatch(email):
        raise SupabaseAuthError("Enter a valid email address.")
    return email


def extract_domain(url: str) -> str:
    """'https://www.MyStore.com/shop/' becomes 'mystore.com'."""
    value = (url or "").strip().lower()
    if not value:
        raise SupabaseAuthError("Enter your store URL, e.g. https://yourstore.com")
    if "://" not in value:
        value = "https://" + value
    host = (urlsplit(value).hostname or "").removeprefix("www.")
    if not DOMAIN_PATTERN.fullmatch(host):
        raise SupabaseAuthError("Enter a valid store URL, e.g. https://yourstore.com")
    return host


def supabase_sign_in(email: str, password: str) -> dict:
    """Return Supabase's session body (contains access_token and user)."""
    url, anon_key = _config()
    response = requests.post(
        f"{url}/auth/v1/token",
        params={"grant_type": "password"},
        headers={"apikey": anon_key, "Content-Type": "application/json"},
        json={"email": normalize_email(email), "password": password},
        timeout=TIMEOUT,
    )
    body = _json(response)
    if response.status_code != 200 or not body.get("access_token"):
        # The same message for a wrong password and an unknown email, so accounts can't be probed.
        raise SupabaseAuthError("Sign-in failed. Check your email and password.")
    return body


def supabase_sign_up(email: str, password: str, name: str, store_domain: str) -> dict | None:
    """Create an account. Return the session body if Supabase issued one, else None.

    None means the user must confirm their email address before signing in.
    """
    url, anon_key = _config()
    clean_name = (name or "").strip()
    if not clean_name:
        raise SupabaseAuthError("Enter a store name.")
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise SupabaseAuthError("Password must be at least 8 characters.")

    response = requests.post(
        f"{url}/auth/v1/signup",
        headers={"apikey": anon_key, "Content-Type": "application/json"},
        json={
            "email": normalize_email(email),
            "password": password,
            "data": {
                "full_name": clean_name,
                "store_name": clean_name,
                "store_url": store_domain,
            },
        },
        timeout=TIMEOUT,
    )
    body = _json(response)
    if response.status_code >= 400:
        message = body.get("msg") or body.get("error_description") or body.get("message")
        raise SupabaseAuthError(
            message if isinstance(message, str) and message else "Could not create the account."
        )
    return body if body.get("access_token") else None


def supabase_get_user(token: str) -> dict | None:
    """Return the Supabase user for a valid access token, else None."""
    url, anon_key = _config()
    try:
        response = requests.get(
            f"{url}/auth/v1/user",
            headers={"apikey": anon_key, "Authorization": f"Bearer {token}"},
            timeout=TIMEOUT,
        )
    except requests.RequestException:
        return None
    if response.status_code != 200:
        return None
    user = _json(response)
    return user if user.get("email") else None


def is_admin_user(user: dict | None) -> bool:
    """Admin status comes from app_metadata, which only the server or an admin can set."""
    if not user:
        return False
    role = (user.get("app_metadata") or {}).get("role")
    return role in ADMIN_ROLES
