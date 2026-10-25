import html
import os

import resend

TEST_RECIPIENT = "saniaiqbal870@gmail.com"
SAMPLE_RESET_LINK = "https://www.alphaguardsuite.com/update-password?mode=resetPassword&oobCode=SAMPLE_TEST_CODE"


def send_test_password_reset_email(
    to_email: str = TEST_RECIPIENT,
    reset_link: str = SAMPLE_RESET_LINK,
) -> dict:
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    sender = (os.getenv("AUTH_EMAIL_FROM") or os.getenv("RESEND_FROM_EMAIL", "")).strip()
    if not api_key or not sender:
        raise RuntimeError(
            "Set RESEND_API_KEY and AUTH_EMAIL_FROM (or RESEND_FROM_EMAIL) to your verified domain sender."
        )

    resend.api_key = api_key
    safe_link = html.escape(reset_link, quote=True)
    return resend.Emails.send({
        "from": f"AlphaGuard <{sender}>",
        "to": [to_email],
        "subject": "[TEST] Reset your AlphaGuard password",
        "html": (
            "<p>This is a test password reset email.</p>"
            f'<p><a href="{safe_link}">Reset your password</a></p>'
            "<p>This sample link is for testing only and will not reset a real password.</p>"
        ),
        "text": f"This is a test password reset email.\nReset your password: {reset_link}\n",
    })


if __name__ == "__main__":
    print(send_test_password_reset_email())
