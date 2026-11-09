"""Send a test password-reset email to confirm the reset template and sender work.

Run directly: python send_test_reset_email.py
Required in .env: RESEND_API_KEY, AUTH_EMAIL_FROM (or RESEND_FROM_EMAIL), TEST_RECIPIENT
Importing this module never sends email.

The link below is a sample for testing only. It does not reset a real password.
"""

import html
import os
from pathlib import Path

import resend
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))

SAMPLE_RESET_LINK = (
    "https://www.alphaguardsuite.com/update-password"
    "?mode=resetPassword&oobCode=SAMPLE_TEST_CODE"
)


def send_test_password_reset_email(
    to_email: str | None = None,
    reset_link: str = SAMPLE_RESET_LINK,
) -> dict:
    """Send the sample reset email. Raises RuntimeError if configuration is missing."""
    recipient = (to_email or os.getenv("TEST_RECIPIENT", "")).strip()
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    sender = (os.getenv("AUTH_EMAIL_FROM") or os.getenv("RESEND_FROM_EMAIL", "")).strip()

    if not api_key or not sender:
        raise RuntimeError(
            "Set RESEND_API_KEY and AUTH_EMAIL_FROM (or RESEND_FROM_EMAIL) "
            "to your verified domain sender."
        )
    if not recipient:
        raise RuntimeError("Set TEST_RECIPIENT in .env to the address that should receive the test email.")

    resend.api_key = api_key
    safe_link = html.escape(reset_link, quote=True)
    return resend.Emails.send({
        "from": f"AlphaGuard <{sender}>",
        "to": [recipient],
        "subject": "[TEST] Reset your AlphaGuard password",
        "html": (
            "<p>This is a test password reset email.</p>"
            f'<p><a href="{safe_link}">Reset your password</a></p>'
            "<p>This sample link is for testing only and will not reset a real password.</p>"
        ),
        "text": f"This is a test password reset email.\nReset your password: {reset_link}\n",
    })


def main() -> int:
    try:
        result = send_test_password_reset_email()
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return 1
    except Exception as exc:
        # Print only the exception type, never request details that could include the API key.
        print(f"[!] Test reset email failed: {type(exc).__name__}")
        return 1

    message_id = result.get("id") if isinstance(result, dict) else None
    print(f"[*] Sent. Message ID: {message_id or 'unknown'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())