"""Send a one-off test email to confirm outbound email is configured.

Run directly: python send_test_email.py
Required in .env: RESEND_API_KEY, SENDER_LEGAL_EMAIL, TEST_RECIPIENT
Importing this module never sends email.
"""

import os
from html import escape
from pathlib import Path

import resend
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))


def build_test_params(sender: str, recipient: str) -> dict:
    safe_sender = escape(sender, quote=True)
    return {
        "from": sender,
        "to": [recipient],
        "subject": "AlphaGuard Security Suite - Test Dispatch",
        "html": (
            '<div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">'
            '<h2 style="color: #0f172a;">AlphaGuard Security Suite - Email Verification</h2>'
            "<p>This is a test message confirming that outbound email is configured.</p>"
            f"<p><strong>Sender:</strong> {safe_sender}</p>"
            "</div>"
        ),
    }


def main() -> int:
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    sender = os.getenv("SENDER_LEGAL_EMAIL", "").strip()
    recipient = os.getenv("TEST_RECIPIENT", "").strip()

    if not api_key or not sender:
        print("Set RESEND_API_KEY and SENDER_LEGAL_EMAIL in .env before running.")
        return 1
    if not recipient:
        print("Set TEST_RECIPIENT in .env to the address that should receive the test email.")
        return 1

    resend.api_key = api_key
    params = build_test_params(sender, recipient)

    try:
        print(f"[*] Sending test email to {recipient}...")
        response = resend.Emails.send(params)
        print("[*] Sent. Response:", response)
        return 0
    except Exception as exc:
        # Print only the exception type and message, never the API key.
        print(f"[!] Email dispatch failed: {type(exc).__name__}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())