"""AlphaGuard API: the Vercel serverless entry point.

  GET  /api/health                              public: liveness check
  POST /api/v1/inspect-domain                   public: free-trial store check (read-only, SSRF-protected)
  POST /api/v1/auth/check-availability          public: input check before sign-up
  POST /api/v1/auth/register                    public: welcome email, saves the store for a verified session
  POST /api/v1/webhooks/gumroad/{secret}        Gumroad purchase pings (verified with Gumroad)
  POST /api/send-reset                          public: password reset email (same reply for any address)
  GET  /api/v1/cron/scan                        Vercel Cron only: scans stores, queues matches, never sends
  GET  /api/v1/admin/notices                    admin only: notice review queue
  POST /api/v1/admin/notices/{id}/contact       admin only: sets the abuse contact for a notice that lacks one
  POST /api/v1/scan/execute-takedown            admin only: saves a manual draft to the queue, never sends
  POST /api/v1/admin/notices/{id}/send          admin only: sends an APPROVED notice, once, with an audit trail

Nothing is sent without an admin's approval. Every decision and send is written to the audit log.
"""

import hmac
import html
import ipaddress
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests
import resend
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field

# Vercel runs this file from api/, so make the project root importable.
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from billing import BillingError, process_ping, secret_matches  # noqa: E402
from dmca_dispatcher import (  # noqa: E402
    DmcaDeliveryUnknownError,
    DmcaProviderRejectedError,
    create_dmca_notice_draft,
    lookup_whois_contact,
    send_dmca_notice,
)
from scanner import (  # noqa: E402
    _validate_public_url,
    compare_hashes,
    compute_image_hash,
    public_only_session,
    search_web_for_matches,
)

logger = logging.getLogger("alphaguard.api")
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "").strip()
SUPABASE_SECRET_KEY = (
    os.environ.get("SUPABASE_SECRET_KEY") or os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or ""
).strip()
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
MAIL_SENDER = (os.environ.get("AUTH_EMAIL_FROM") or os.environ.get("RESEND_FROM_EMAIL") or "").strip()
LEGAL_SENDER = (os.environ.get("SENDER_LEGAL_EMAIL") or "").strip()
RESET_PAGE_URL = os.environ.get(
    "PASSWORD_RESET_REDIRECT_URL", "https://www.alphaguardsuite.com/update-password"
).strip()
CRON_SECRET = os.environ.get("CRON_SECRET", "").strip()
SERPAPI_KEY = os.environ.get("SERPAPI_KEY", "").strip()

ADMIN_ROLES = {"admin", "legal"}
MAX_BODY_BYTES = 4_000_000
MAX_REDIRECTS = 3
DISCLAIMER = "Similarity is not a legal determination. Review all evidence before sending."
# TODO: align these bands with the confirmed prices in src/site-config.js before launch.
TIER_BANDS = ((500, "Growth Tier"), (2000, "Pro Tier"))
ENTERPRISE_TIER = "Enterprise Tier"

# Scan limits. These cap SerpApi spend and keep each cron run inside the 60-second function limit.
MATCH_THRESHOLD = 90.0
MAX_STORES_PER_RUN = 5
MAX_IMAGES_PER_STORE = 3
MAX_IMAGES_PER_RUN = 15
SCAN_BUDGET_SECONDS = 40

IMAGE_SRC = re.compile(r"""<img\b[^>]*?\bsrc=["']([^"']+)["']""", re.IGNORECASE)
IMAGE_EXT = (".jpg", ".jpeg", ".png", ".webp")
DOMAIN_PATTERN = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")
UUID_PATTERN = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
UNKNOWN_USER_PHRASES = ("user not found", "no user found", "unable to find user", "user with this email")
GENERIC_RESET = {
    "status": "success",
    "success": True,
    "message": "If an account exists for that email, a reset link has been sent.",
}


class InspectRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class AvailabilityRequest(BaseModel):
    email: EmailStr
    store_url: str = Field(default="", max_length=2048)


class RegisterRequest(BaseModel):
    email: EmailStr
    name: str = Field(default="User", max_length=120)
    store_url: str = Field(default="", max_length=2048)


class ResetRequest(BaseModel):
    email: EmailStr


class ContactRequest(BaseModel):
    email: EmailStr


class TakedownRequest(BaseModel):
    store_id: int = Field(ge=1)
    host_abuse_email: EmailStr
    target_infringing_url: str = Field(min_length=8, max_length=2048)
    infringing_image_url: str = Field(min_length=8, max_length=2048)
    original_image_url: str = Field(min_length=8, max_length=2048)


# ---------- store inspection (free trial)

def normalize_domain(raw: str) -> str:
    value = (raw or "").strip().lower()
    if not value:
        raise ValueError("Enter a store URL, e.g. https://yourstore.com")
    if "://" not in value:
        value = "https://" + value
    host = (urlsplit(value).hostname or "").removeprefix("www.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a website domain, not an IP address.")
    if not DOMAIN_PATTERN.fullmatch(host):
        raise ValueError("Enter a valid store URL, e.g. https://yourstore.com")
    return host


def _same_site(url: str, domain: str) -> bool:
    host = (urlsplit(url).hostname or "").removeprefix("www.")
    return host == domain or host.endswith("." + domain)


def _get_text(session, url: str, domain: str) -> tuple[int, str, str]:
    """Fetch a page through the public-only session. Redirects are checked on every hop."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        _validate_public_url(current)
        response = session.get(current, timeout=(3, 10), allow_redirects=False, stream=True)
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location", "")
            response.close()
            current = urljoin(current, location)
            if not location or not _same_site(current, domain):
                raise ValueError("The store redirects to another website, which is not checked.")
            continue
        try:
            ctype = response.headers.get("Content-Type", "").lower()
            body = bytearray()
            for chunk in response.iter_content(chunk_size=64 * 1024):
                body.extend(chunk)
                if len(body) > MAX_BODY_BYTES:
                    break
            text = bytes(body[:MAX_BODY_BYTES]).decode("utf-8", errors="replace")
            return response.status_code, ctype, text
        finally:
            response.close()
    raise ValueError("The store redirects too many times.")


def _shopify_product_count(session, domain: str) -> int | None:
    try:
        status, ctype, text = _get_text(session, f"https://{domain}/products.json?limit=250", domain)
    except ValueError:
        return None
    if status != 200 or "json" not in ctype:
        return None
    try:
        products = json.loads(text).get("products")
    except (ValueError, AttributeError):
        return None
    if not isinstance(products, list):
        return None
    return sum(1 for p in products if isinstance(p, dict) and p.get("images"))


def _tier_for(count: int) -> str:
    for limit, name in TIER_BANDS:
        if count < limit:
            return name
    return ENTERPRISE_TIER


def inspect_store(domain: str) -> dict:
    base = f"https://{domain}/"
    with public_only_session() as session:
        shop_count = _shopify_product_count(session, domain)
        if shop_count:
            count, platform = shop_count, "Shopify store"
            note = "Counted products with images in the store's public catalog (first 250 products)."
        else:
            status, _, text = _get_text(session, base, domain)
            if status >= 400:
                return {"valid": False, "message": f"We could not read {domain} (HTTP {status})."}
            images = set()
            for src in IMAGE_SRC.findall(text):
                clean = src.split("?")[0]
                if clean.lower().endswith(IMAGE_EXT):
                    images.add(urljoin(base, clean))
            count, platform = len(images), None
            note = "Estimated from images on the homepage. The full catalog may be larger."

    if count