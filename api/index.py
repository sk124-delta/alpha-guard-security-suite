import html
import json
import logging
import os
import resend
import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr

app = FastAPI()
logger = logging.getLogger(__name__)

RESEND_KEY = os.environ.get("RESEND_API_KEY")
if RESEND_KEY:
    resend.api_key = RESEND_KEY

RESET_PAGE_URL = "https://www.alphaguardsuite.com/update-password.html"
RESET_SENDER = "no-reply@alphaguardsuite.com"
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")


class SendResetRequest(BaseModel):
    email: EmailStr


def _get_supabase_recovery_link(email: str) -> str | None:
    supabase_url = SUPABASE_URL or os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    supabase_key = (
        os.environ.get("SUPABASE_SECRET_KEY", "").strip()
        or os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    )
    if not supabase_url:
        raise RuntimeError("SUPABASE_URL is not configured.")
    if not supabase_key:
        raise RuntimeError("SUPABASE_SECRET_KEY is not configured.")

    response = requests.post(
        f"{supabase_url}/auth/v1/admin/generate_link",
        headers={
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
        },
        json={
            "type": "recovery",
            "email": email,
            "redirect_to": RESET_PAGE_URL,
        },
        timeout=(3, 10),
    )
    if response.status_code in (400, 404) and any(
        phrase in response.text.lower()
        for phrase in ("user not found", "no user found")
    ):
        return None
    response.raise_for_status()

    result = response.json()
    action_link = result.get("action_link")
    if not action_link and isinstance(result.get("properties"), dict):
        action_link = result["properties"].get("action_link")
    if not isinstance(action_link, str) or not action_link:
        raise RuntimeError("Supabase did not return a recovery link.")
    return action_link


@app.post("/api/send-reset")
@app.post("/send-reset")
def send_reset(data: SendResetRequest):
    # Same response whether or not the account exists, so emails can't be enumerated.
    generic = {"status": "success", "success": True, "message": "If an account exists for that email, a reset link has been sent."}
    try:
        resend.api_key = os.environ.get("RESEND_API_KEY")
        if not resend.api_key:
            raise RuntimeError("RESEND_API_KEY is not configured.")

        recovery_link = _get_supabase_recovery_link(str(data.email).strip().lower())
        if recovery_link is None:
            return generic

        reset_link = html.escape(recovery_link, quote=True)

        resend.Emails.send({
            "from": f"AlphaGuard Security <{RESET_SENDER}>",
            "to": [data.email],
            "subject": "Reset Password - AlphaGuard Suite",
            "html": f"""
                <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #0d1117; color: #c9d1d9; border-radius: 8px;">
                    <h2 style="color: #06b6d4;">Password Reset Request</h2>
                    <p>We received a request to reset your password for your AlphaGuard account.</p>
                    <p>Click the button below to set your new password:</p>
                    <a href="{reset_link}"
                       style="background: #06b6d4; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold; margin-top: 10px; margin-bottom: 20px;">
                       Reset Password
                    </a>
                    <p style="color: #8b949e; font-size: 12px;">If you didn't request this, you can safely ignore this email.</p>
                </div>
            """,
        })
        return generic
    except Exception as e:
        logger.exception("send-reset failed: %s", e)
        raise HTTPException(
            status_code=500,
            detail="Could not send a password reset email. Please try again later.",
        ) from e


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path: str = ""):
    try:
        body = await request.json()
    except Exception:
        body = {}

    action = body.get("action")
    if not action:
        if "register" in path or "signup" in path:
            action = "signup"
        elif "token" in path or "login" in path:
            action = "login"
        elif "reset" in path or "forgot" in path:
            action = "forgot"
        else:
            action = "signup"

    email = body.get("email", "")
    name = body.get("name", "User")
    email_sent = False

    if RESEND_KEY and email:
        try:
            if action in ["signup", "register"]:
                resend.Emails.send({
                    "from": "AlphaGuard Security <no-reply@alphaguardsuite.com>",
                    "to": [email],
                    "subject": "Welcome to AlphaGuard Security Suite",
                    "html": f"<h2>Welcome {name}!</h2><p>Your trial account has been created successfully.</p>"
                })
                email_sent = True
            elif action in ["forgot", "reset"]:
                resend.Emails.send({
                    "from": "AlphaGuard Security <no-reply@alphaguardsuite.com>",
                    "to": [email],
                    "subject": "Reset Password - AlphaGuard Suite",
                    "html": f"<p>Password reset instructions requested for {email}.</p>"
                })
                email_sent = True
        except Exception as e:
            print(f"Resend dispatch error: {e}")

    # Return fields matching what frontend auth parsers look for
    return JSONResponse(content={
        "status": "success",
        "success": True,
        "token": "demo_token_xyz_12345",
        "access_token": "demo_token_xyz_12345",
        "message": f"Action '{action}' completed successfully",
        "email_dispatched": email_sent
    })
