from dataclasses import asdict, dataclass
from html import escape
import os
from urllib.parse import urlsplit

import requests


RESEND_API_URL = "https://api.resend.com/emails"


class DmcaDeliveryError(RuntimeError):
    pass


class DmcaDeliveryUnknownError(DmcaDeliveryError):
    pass


class DmcaProviderRejectedError(DmcaDeliveryError):
    pass


def get_resend_settings() -> tuple[str, str]:
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    sender_email = os.getenv("RESEND_FROM_EMAIL", "").strip()
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
                "from": sender_email,
                "to": [recipient],
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
) -> dict[str, str]:
    recipient = _validate_email_address(host_abuse_email)
    sender = _validate_email_address(
        sender_email or os.getenv("RESEND_FROM_EMAIL", "legal@alphaguardsecurity.suite")
    )
    infringing_url = _validate_http_url(target_infringing_url, "Infringing URL")
    asset_url = _validate_http_url(original_asset_url, "Original asset URL")

    safe_infringing_url = escape(infringing_url, quote=True)
    safe_asset_url = escape(asset_url, quote=True)

    draft = DmcaNoticeDraft(
        recipient=recipient,
        sender=sender,
        subject=(
            "Notice of Copyright Infringement and Takedown Request - "
            f"{infringing_url}"
        ),
        html=(
            "<h3>DMCA TAKEDOWN NOTICE</h3>"
            "<p>To Hosting Provider Abuse Desk,</p>"
            "<p>Please review this report of suspected unauthorized duplication "
            "of protected media assets hosted on your network:</p>"
            "<ul>"
            f"<li><strong>Infringing URL:</strong> {safe_infringing_url}</li>"
            f"<li><strong>Original Asset Reference:</strong> {safe_asset_url}</li>"
            "</ul>"
            "<p>Please review the materials and take any appropriate action "
            "under your applicable policies and legal obligations.</p>"
        ),
    )
    return asdict(draft)
