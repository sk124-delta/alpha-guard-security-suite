"""AlphaGuard API: the Vercel serverless entry point.

vercel.json sends every /api/* request here. Routes:

  GET  /api/health                              public: liveness check, no secrets
  POST /api/v1/inspect-domain                   public: free-trial store check (read-only, SSRF-protected)
  POST /api/v1/auth/check-availability          public: input check before sign-up
  POST /api/v1/auth/register                    public: welcome email, only to a verified session email
  POST /api/v1/webhooks/gumroad/{secret}        Gumroad purchase pings (verified with Gumroad)
  POST /api/send-reset                          public: password reset email (same reply for any address)
  GET  /api/v1/admin/notices                    admin only: notice review queue
  POST /api/v1/scan/execute-takedown            admin only: saves a draft to the review queue, never sends
  POST /api/v1/admin/notices/{id}/send          admin only: sends an APPROVED notice, once, with an audit trail

Sending is only possible for a notice an admin has approved, and each send is recorded.
"""

import html
import ipaddress
import json
import logging
import os
import re
import sys
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
    send_dmca_notice,
)
from scanner import _validate_public_url, public_only_session  # noqa: E402

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

ADMIN_ROLES = {"admin", "legal"}
MAX_BODY_BYTES = 4_000_000
MAX_REDIRECTS = 3
DISCLAIMER = "Similarity is not a legal determination. Review all evidence before sending."
# TODO: align these bands with the confirmed prices in src/site-config.js before launch.
TIER_BANDS = ((500, "Growth Tier"), (2000, "Pro Tier"))
ENTERPRISE_TIER = "Enterprise Tier"

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

    if count < 1:
        return {"valid": False, "message": "No product images were found on this page."}
    return {
        "valid": True,
        "detected_category": platform,
        "catalog_images_indexed": count,
        "recommended_tier": _tier_for(count),
        "inspection_note": note,
    }


@app.post("/api/v1/inspect-domain")
def inspect_domain(body: InspectRequest):
    try:
        domain = normalize_domain(body.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        return inspect_store(domain)
    except ValueError as exc:
        return {"valid": False, "message": str(exc)}
    except requests.RequestException:
        return {"valid": False, "message": f"We could not reach {domain}. Check the URL and try again."}


# ---------- sign-up helpers

@app.post("/api/v1/auth/check-availability")
def check_availability(body: AvailabilityRequest):
    if body.store_url.strip():
        try:
            normalize_domain(body.store_url)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "status": "success",
        "available": True,
        "message": "Duplicate email addresses are rejected at sign-up.",
    }


# ---------- Supabase session checks

def _bearer_token(request: Request) -> str:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def _supabase_user(token: str) -> dict | None:
    """Return the Supabase user for a valid access token, else None."""
    if not token or not SUPABASE_URL or not SUPABASE_ANON_KEY:
        return None
    try:
        response = requests.get(
            f"{SUPABASE_URL}/auth/v1/user",
            headers={"apikey": SUPABASE_ANON_KEY, "Authorization": f"Bearer {token}"},
            timeout=(3, 10),
        )
        if response.status_code != 200:
            return None
        user = response.json()
    except (requests.RequestException, ValueError):
        return None
    return user if isinstance(user, dict) and user.get("email") else None


def _require_admin(request: Request) -> dict:
    user = _supabase_user(_bearer_token(request))
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in again to continue.")
    role = (user.get("app_metadata") or {}).get("role")
    if role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Admin access required.")
    return user


def _send_mail(to: str, subject: str, html_body: str) -> None:
    if not RESEND_API_KEY or not MAIL_SENDER:
        raise RuntimeError("Email is not configured.")
    resend.api_key = RESEND_API_KEY
    resend.Emails.send({
        "from": f"AlphaGuard Security <{MAIL_SENDER}>",
        "to": [to],
        "subject": subject,
        "html": html_body,
    })


# ---------- sign-up welcome

@app.post("/api/v1/auth/register")
def register(body: RegisterRequest, request: Request):
    email = str(body.email).strip().lower()
    session_user = _supabase_user(_bearer_token(request))
    verified = str(session_user.get("email", "")).strip().lower() if session_user else ""
    sent = False
    # Only the address the caller has proven with a valid session gets a welcome email.
    if session_user and verified == email:
        try:
            _send_mail(
                email,
                "Welcome to AlphaGuard Security Suite",
                f"<h2>Welcome {html.escape(body.name)}!</h2>"
                "<p>Your trial account has been created.</p>",
            )
            sent = True
        except Exception:
            logger.exception("Welcome email failed")
    return {
        "status": "success",
        "success": True,
        "message": "Account recorded.",
        "email_dispatched": sent,
        "role": "customer",
    }


# ---------- payments (Gumroad)

@app.post("/api/v1/webhooks/gumroad/{secret}")
async def gumroad_webhook(secret: str, request: Request):
    # Gumroad sends form-encoded pings.
    if not secret_matches(secret):
        raise HTTPException(status_code=404, detail="Not found.")
    form = dict((await request.form()).items())
    try:
        return process_ping(form)
    except BillingError as exc:
        logger.warning("Gumroad ping not applied: %s", exc)
        # 503 makes Gumroad retry, so a temporary Supabase or Gumroad outage doesn't lose the sale.
        raise HTTPException(status_code=503, detail="Could not apply the purchase yet.")


# ---------- password reset

def _recovery_link(email: str) -> str | None:
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        raise RuntimeError("Password reset is not configured.")
    response = requests.post(
        f"{SUPABASE_URL}/auth/v1/admin/generate_link",
        headers={
            "apikey": SUPABASE_SECRET_KEY,
            "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
            "Content-Type": "application/json",
        },
        json={"type": "recovery", "email": email, "redirect_to": RESET_PAGE_URL},
        timeout=(3, 10),
    )
    text = (response.text or "").lower()
    if response.status_code in (400, 404, 422) and any(p in text for p in UNKNOWN_USER_PHRASES):
        return None  # unknown address: the caller still gets the generic reply
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict):
        raise RuntimeError("Unexpected response from the auth service.")
    link = body.get("action_link") or (body.get("properties") or {}).get("action_link")
    if not isinstance(link, str) or not link:
        raise RuntimeError("No recovery link returned.")
    return link


@app.post("/api/send-reset")
def send_reset(body: ResetRequest):
    email = str(body.email).strip().lower()
    try:
        link = _recovery_link(email)
        if link is None:
            return GENERIC_RESET
        _send_mail(
            email,
            "Reset your AlphaGuard password",
            "<p>We received a request to reset your password.</p>"
            f'<p><a href="{html.escape(link, quote=True)}">Reset your password</a></p>'
            "<p>If you did not request this, you can ignore this email.</p>",
        )
        return GENERIC_RESET
    except Exception:
        logger.exception("send-reset failed")
        raise HTTPException(
            status_code=503,
            detail="Could not send a password reset email. Please try again later.",
        )


# ---------- notice storage (Supabase, server side only)

def _sb_request(method: str, path: str, *, json=None, params=None, prefer: str | None = None):
    """Call the Supabase REST API with the secret key. The key never leaves the server."""
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Database is not configured.")
    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    try:
        response = requests.request(
            method,
            f"{SUPABASE_URL}{path}",
            headers=headers,
            json=json,
            params=params,
            timeout=(3, 10),
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=503, detail="Database is unreachable.") from exc
    if response.status_code >= 400:
        logger.error("Database %s %s returned HTTP %s", method, path, response.status_code)
        raise HTTPException(status_code=502, detail="Database request failed.")
    return response.json() if response.content else None


def _audit(actor: str, action: str, target_id: str) -> None:
    _sb_request(
        "POST",
        "/rest/v1/admin_audit_log",
        json={"actor": actor or "unknown", "action": action, "target_id": str(target_id)},
        prefer="return=minimal",
    )


def _set_notice_status(notice_id: str, status: str, extra: dict | None = None) -> None:
    _sb_request(
        "PATCH",
        "/rest/v1/notice_reviews",
        params={"id": f"eq.{notice_id}"},
        json={"status": status, **(extra or {})},
        prefer="return=minimal",
    )


@app.get("/api/v1/admin/notices")
def admin_notices(request: Request):
    _require_admin(request)
    rows = _sb_request(
        "GET",
        "/rest/v1/notice_reviews",
        params={
            "select": "id,target_url,original_url,score,status,decided_by,created_at,sent_at",
            "order": "created_at.desc",
            "limit": "100",
        },
    )
    return rows or []


# ---------- drafting (saves to the review queue; never sends)

@app.post("/api/v1/scan/execute-takedown")
def execute_takedown(body: TakedownRequest, request: Request):
    admin = _require_admin(request)
    actor = admin.get("email") or "unknown"
    try:
        draft = create_dmca_notice_draft(
            host_abuse_email=str(body.host_abuse_email),
            target_infringing_url=body.target_infringing_url,
            original_asset_url=body.original_image_url,
            sender_email=LEGAL_SENDER or None,
            recipient_source="provided",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    _sb_request(
        "POST",
        "/rest/v1/notice_reviews",
        json={
            "target_url": body.target_infringing_url,
            "original_url": body.original_image_url,
            "status": "ready",
            "recipient": draft["recipient"],
            "sender": draft["sender"],
            "subject": draft["subject"],
            "body_html": draft["html"],
        },
        prefer="return=minimal",
    )
    _audit(actor, "draft_created", body.target_infringing_url)
    return {
        "message": "Draft saved to the review queue. It has not been sent.",
        "disclaimer": DISCLAIMER,
    }


# ---------- sending (only for approved notices, once, with an audit trail)

@app.post("/api/v1/admin/notices/{notice_id}/send")
def send_notice(notice_id: str, request: Request):
    admin = _require_admin(request)
    actor = admin.get("email") or "unknown"
    if not UUID_PATTERN.fullmatch(notice_id):
        raise HTTPException(status_code=422, detail="Invalid notice id.")
    if not RESEND_API_KEY or not LEGAL_SENDER:
        raise HTTPException(status_code=503, detail="Email sending is not configured.")

    # Atomic claim: only an APPROVED notice can move to 'sending', so a double click cannot send twice.
    claimed = _sb_request(
        "PATCH",
        "/rest/v1/notice_reviews",
        params={"id": f"eq.{notice_id}", "status": "eq.approved"},
        json={"status": "sending"},
        prefer="return=representation",
    )
    if not claimed:
        raise HTTPException(status_code=409, detail="This notice is not approved, or it was already sent.")
    notice = claimed[0]

    _audit(actor, "send_authorized", notice_id)

    try:
        message_id = send_dmca_notice(
            api_key=RESEND_API_KEY,
            sender_email=LEGAL_SENDER,
            recipient=notice["recipient"],
            subject=notice["subject"],
            html=notice["body_html"],
        )
    except DmcaProviderRejectedError as exc:
        _set_notice_status(notice_id, "send_failed")
        _audit(actor, "send_failed", notice_id)
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except DmcaDeliveryUnknownError as exc:
        _set_notice_status(notice_id, "send_unknown")
        _audit(actor, "send_unknown", notice_id)
        raise HTTPException(
            status_code=502,
            detail="The email provider did not confirm the result. Check its logs before doing anything else.",
        ) from exc

    _set_notice_status(notice_id, "sent", {"sent_at": datetime.now(timezone.utc).isoformat()})
    _audit(actor, "sent", notice_id)
    return {"success": True, "notice_id": notice_id, "status": "sent", "provider_message_id": message_id}


@app.get("/api/health")
def health():
    return {"status": "ok"}