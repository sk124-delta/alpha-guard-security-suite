from dataclasses import asdict, dataclass
from html import escape
import ipaddress
import os
import re
import socket
from urllib.parse import urlsplit

import requests
import whois


RESEND_API_URL = "https://api.resend.com/emails"


class DmcaDeliveryError(RuntimeError):
    pass


class DmcaDeliveryUnknownError(DmcaDeliveryError):
    pass


class DmcaProviderRejectedError(DmcaDeliveryError):
    pass


class WhoisLookupError(RuntimeError):
    pass


def lookup_whois_contact(domain: str) -> str | None:
    hostname = domain.strip().rstrip(".").encode("idna").decode("ascii").lower()
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("WHOIS contact lookup requires a domain name, not an IP address.")

    labels = hostname.split(".")
    if (
        len(labels) < 2
        or len(hostname) > 253
        or any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        )
    ):
        raise ValueError("A valid domain name is required for WHOIS contact lookup.")

    try:
        record = whois.whois(hostname, inc_raw=True, quiet=True)
    except (OSError, socket.timeout, TimeoutError, whois.parser.PywhoisError) as exc:
        raise WhoisLookupError("WHOIS contact lookup failed.") from exc

    raw_record = record.get("raw") if hasattr(record, "get") else None
    if isinstance(raw_record, str) and raw_record.startswith("Socket not responding:"):
        raise WhoisLookupError("WHOIS contact lookup failed.")

    for field in ("abuse_email", "abuse_contact_email", "emails", "email"):
        value = record.get(field) if hasattr(record, "get") else getattr(record, field, None)
        candidates = value if isinstance(value, (list, tuple, set)) else [value]
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            try:
                return _validate_email_address(candidate)
            except ValueError:
                continue
    return None


def get_resend_settings() -> tuple[str, str]:
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    sender_email = (
        os.getenv("SENDER_LEGAL_EMAIL") or os.getenv("RESEND_FROM_EMAIL", "")
    ).strip()
    if not api_key or not sender_email:
        raise RuntimeError("Email dispatch is not configured.")
    return api_key, _validate_email_address(sender_email)


def send_dmca_notice(
    *,
    api_key: str,
    sender_email: str,
    recipient: str,
    subject: str,
    html: str,
) -> str | None:
    try:
        response = requests.post(
            RESEND_API_URL,
            json={
                "from": f"AlphaGuard Legal <{sender_email}>",
                "to": [recipient],
                "reply_to": sender_email,
                "subject": subject,
                "html": html,
            },
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=(3, 15),
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise DmcaDeliveryUnknownError(
            "Email provider outcome is unknown; check provider logs before retrying."
        ) from exc

    if 500 <= response.status_code:
        raise DmcaDeliveryUnknownError(
            f"Email provider returned HTTP {response.status_code}; check provider logs before retrying."
        )
    if not 200 <= response.status_code < 300:
        raise DmcaProviderRejectedError(
            f"Email provider rejected the notice (HTTP {response.status_code})."
        )

    try:
        response_body = response.json()
    except ValueError:
        return None
    message_id = response_body.get("id") if isinstance(response_body, dict) else None
    return message_id if isinstance(message_id, str) else None


@dataclass(frozen=True)
class DmcaNoticeDraft:
    recipient: str
    sender: str
    subject: str
    html: str


def _validate_email_address(email: str) -> str:
    address = email.strip()
    if (
        not address
        or len(address) > 254
        or address.count("@") != 1
        or any(character.isspace() for character in address)
    ):
        raise ValueError("A valid recipient email address is required.")

    local_part, domain = address.rsplit("@", 1)
    if not local_part or not domain or "." not in domain:
        raise ValueError("A valid recipient email address is required.")

    return address


def _validate_http_url(value: str, field_name: str) -> str:
    url = value.strip()
    parsed_url = urlsplit(url)
    if (
        any(ord(character) < 32 or ord(character) == 127 for character in url)
        or parsed_url.scheme not in {"http", "https"}
        or not parsed_url.hostname
        or parsed_url.username
        or parsed_url.password
    ):
        raise ValueError(f"{field_name} must be an absolute HTTP or HTTPS URL.")

    return url


def create_dmca_notice_draft(
    host_abuse_email: str,
    target_infringing_url: str,
    original_asset_url: str,
    sender_email: str | None = None,
    store_domain: str | None = None,
    recipient_source: str = "provided",
) -> dict[str, str]:
    if recipient_source not in {"provided", "whois"}:
        raise ValueError("recipient_source must be 'provided' or 'whois'.")
    recipient = _validate_email_address(host_abuse_email)
    sender = _validate_email_address(
        sender_email
        or os.getenv("SENDER_LEGAL_EMAIL")
        or os.getenv("RESEND_FROM_EMAIL", "legal@alphaguardsuite.com")
    )
    infringing_url = _validate_http_url(target_infringing_url, "Infringing URL")
    asset_url = _validate_http_url(original_asset_url, "Original asset URL")

    safe_infringing_url = escape(infringing_url, quote=True)
    safe_asset_url = escape(asset_url, quote=True)
    safe_store_domain = escape(store_domain or urlsplit(infringing_url).hostname or "", quote=True)
    recipient_note = (
        "<p><strong>Recipient note:</strong> This address was suggested "
        "from WHOIS registration data and is not verified as an abuse contact. "
        "Confirm the recipient before dispatch.</p>"
        if recipient_source == "whois"
        else ""
    )

    draft = DmcaNoticeDraft(
        recipient=recipient,
        sender=sender,
        subject=(
            "LEGAL NOTICE: Formal DMCA Copyright Infringement Notice - "
            f"{store_domain or urlsplit(infringing_url).hostname}"
        ),
        html=(
            "<h2>DMCA TAKEDOWN NOTICE</h2>"
            "<p><strong>To the Abuse and Legal Department:</strong></p>"
            "<p>Please review this report of suspected unauthorized use of "
            f"protected media hosted at <strong>{safe_store_domain}</strong>:</p>"
            "<ul>"
            f"<li><strong>Infringing URL:</strong> {safe_infringing_url}</li>"
            f"<li><strong>Original Asset Reference:</strong> {safe_asset_url}</li>"
            "</ul>"
            "<p>The reported imagery was identified by the AlphaGuard image "
            "similarity scanner. Please review the materials and take any "
            "appropriate action under your applicable policies and legal obligations.</p>"
            "<p>Please direct any response to the AlphaGuard Legal Enforcement Team "
            f"at {escape(sender, quote=True)}.</p>"
            f"{recipient_note}"
        ),
    )
    result = asdict(draft)
    result["recipient_source"] = recipient_source
    return result
