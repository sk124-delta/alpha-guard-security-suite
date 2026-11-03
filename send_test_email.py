import os
from pathlib import Path

import resend
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))

api_key = os.getenv("RESEND_API_KEY", "").strip()
sender = os.getenv("SENDER_LEGAL_EMAIL", "").strip()
recipient = "saniaiqbal870@gmail.com"

if not api_key or not sender:
    raise SystemExit("Set RESEND_API_KEY and SENDER_LEGAL_EMAIL in .env before running.")

resend.api_key = api_key

params = {
    "from": sender,
    "to": [recipient],
    "subject": "AlphaGuard Security Suite - Test Dispatch",
    "html": """
        <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
            <h2 style="color: #0f172a;">AlphaGuard Security Suite - Email Verification</h2>
            <p>This is a test message confirming that outbound email is configured.</p>
            <p><strong>Sender:</strong> """ + sender + """</p>
        </div>
    """,
}

try:
    print(f"[*] Sending test email to {recipient}...")
    response = resend.Emails.send(params)
    print("[*] Sent. Response:", response)
except Exception as exc:
    print(f"[!] Email dispatch failed: {exc}")
    raise SystemExit(1)
