"""Gumroad purchase handling.

Sets app_metadata.subscription_status in Supabase, which src/trial-status.js reads.
Only this server code writes that field. Every sale is confirmed with Gumroad's API before
access is granted, because webhook payloads alone can be forged or replayed.

Env (Vercel and local, never commit values):
  GUMROAD_WEBHOOK_SECRET   random string, 32+ characters, used in the webhook URL
  GUMROAD_ACCESS_TOKEN     Gumroad API token (Settings > Advanced > Application)
  SUPABASE_URL             https://<project>.supabase.co
  SUPABASE_SECRET_KEY      service key, server only, never in frontend code
"""

import hmac
import logging
import os

import requests

logger = logging.getLogger("alphaguard.billing")

GUMROAD_API = "https://api.gumroad.com/v2"
TIMEOUT = (3, 10)

# Permalinks of the Gumroad products sold on the site (from src/site-config.js).
KNOWN_PERMALINKS = frozenset({
    "dbexqj", "lkqkkc", "cygzyw", "hmpejz", "oibele", "hygggq", "wbvjft",
    "irlzfz", "gsvzuq", "fudbbv", "jroqz", "vlnxs", "izzea", "jrwsha",
})
REVOKE_EVENTS = frozenset({"refund", "cancellation", "subscription_ended", "subscription_cancelled"})


class BillingError(RuntimeError):
    """Safe to log. Never includes keys or tokens."""


def secret_matches(given: str) -> bool:
    expected = os.getenv("GUMROAD_WEBHOOK_SECRET", "")
    if len(expected) < 32:
        return False
    return hmac.compare_digest(given or "", expected)


def decide_status(event: str, refunded: bool, cancelled: bool) -> str | None:
    """'active', 'inactive', or None when the event should not change access."""
    if event in REVOKE_EVENTS or refunded or cancelled:
        return "inactive"
    if event == "sale":
        return "active"
    return None


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"true", "1", "yes"}


def fetch_sale(sale_id: str) -> dict:
    """Read the sale from Gumroad. Raises BillingError if Gumroad does not confirm it."""
    token = os.getenv("GUMROAD_ACCESS_TOKEN", "").strip()
    if not token:
        raise BillingError("Gumroad access is not configured.")
    try:
        response = requests.get(
            f"{GUMROAD_API}/sales/{sale_id}",
            params={"access_token": token},
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise BillingError("Could not reach Gumroad to confirm the sale.") from exc
    if response.status_code != 200:
        raise BillingError(f"Gumroad did not confirm the sale (HTTP {response.status_code}).")
    body = response.json()
    sale = body.get("sale") if isinstance(body, dict) else None
    if not body.get("success") or not isinstance(sale, dict):
        raise BillingError("Gumroad returned an unexpected response for the sale.")
    return sale


def _supabase_config() -> tuple[str, str]:
    url = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
    key = os.getenv("SUPABASE_SECRET_KEY", "").strip()
    if not url or not key:
        raise BillingError("Supabase admin access is not configured.")
    return url, key


def _find_user(email: str) -> dict | None:
    url, key = _supabase_config()
    headers = {"apikey": key, "Authorization": f"Bearer {key}"}
    # Scans the first 1000 accounts. Replace with a profiles table once you pass that size.
    response = requests.get(
        f"{url}/auth/v1/admin/users", params={"page": 1, "per_page": 1000},
        headers=headers, timeout=TIMEOUT,
    )
    if response.status_code != 200:
        raise BillingError("Could not look up the customer account.")
    for user in response.json().get("users", []):
        if str(user.get("email", "")).strip().lower() == email:
            return user
    return None


def set_subscription_status(email: str, status: str) -> bool:
    """Write subscription_status without dropping other app_metadata such as role."""
    user = _find_user(email)
    if user is None:
        return False
    url, key = _supabase_config()
    metadata = dict(user.get("app_metadata") or {})
    metadata["subscription_status"] = status
    response = requests.put(
        f"{url}/auth/v1/admin/users/{user['id']}",
        headers={"apikey": key, "Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        json={"app_metadata": metadata},
        timeout=TIMEOUT,
    )
    if response.status_code != 200:
        raise BillingError("Could not update the customer's subscription status.")
    return True


def process_ping(form: dict) -> dict:
    """Handle one Gumroad ping. Returns {'outcome': ...}; raises BillingError to request a retry."""
    permalink = str(form.get("product_permalink") or form.get("permalink") or "").strip()
    if permalink not in KNOWN_PERMALINKS:
        logger.info("Ignored ping for unknown product %r", permalink)
        return {"outcome": "ignored_unknown_product"}

    event = str(form.get("resource_name") or "sale").strip().lower()
    refunded = _truthy(form.get("refunded"))
    cancelled = _truthy(form.get("cancelled"))
    status = decide_status(event, refunded, cancelled)
    if status is None:
        return {"outcome": "ignored_event"}

    email = str(form.get("email") or "").strip().lower()
    sale_id = str(form.get("sale_id") or "").strip()
    if not email or not sale_id:
        raise BillingError("Ping is missing the buyer email or sale id.")

    # Confirm the sale with Gumroad before changing anything.
    sale = fetch_sale(sale_id)
    sale_email = str(sale.get("email") or "").strip().lower()
    if sale_email != email:
        raise BillingError("Sale email does not match the ping.")
    if str(sale.get("product_permalink") or "") not in ("", permalink):
        raise BillingError("Sale product does not match the ping.")

    if status == "active" and sale.get("refunded"):
        status = "inactive"

    updated = set_subscription_status(email, status)
    if not updated:
        # Account not created yet. Gumroad retries on error, so return success and log it.
        logger.warning("Purchase for %s has no matching account yet", email)
        return {"outcome": "no_account_yet"}
    return {"outcome": f"set_{status}"}