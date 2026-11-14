import html
import logging
import os

import requests
import resend
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, ValidationError

app = FastAPI()
logger = logging.getLogger(__name__)

RESEND_KEY = os.environ.get("RESEND_API_KEY")
if RESEND_KEY:
    resend.api_key = RESEND_KEY

RESET_PAGE_URL = os.environ.get(
    "PASSWORD_RESET_REDIRECT_URL",
    "https://www.alphaguardsuite.com/update-password",
).strip()
RESET_SENDER = os.environ.get("AUTH_EMAIL_FROM") or os.environ.get(
    "RESEND_FROM_EMAIL", "no-reply@alphaguardsuite.com"
)
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
UNKNOWN_USER_PHRASES = (
    "user not found",
    "no user found",
    "unable to find user",
    "user with this email",
)

GENERIC_RESET = {
    "status": "success",
    "success": True,
    "message": "If an account exists for that email, a reset link has been sent.",
}


class SendResetRequest(BaseModel):
    email: EmailStr


class SignupNotifyRequest(BaseModel):
    email: EmailStr
    name: str = "User"


def _combined_path(request: Request, path: str = "") -> str:
    parts = [
        path,
        request.url.path,
        request.headers.get("x-invoke-path", ""),
        request.headers.get("x-matched-path", ""),
        request.headers.get("x-forwarded-uri", ""),
        request.headers.get("x-vercel-original-path", ""),
    ]
    return " ".join(part for part in parts if part).lower()


def _is_unknown_user_response(response: requests.Response) -> bool:
    text = (response.text or "").lower()
    return response.status_code in (400, 404, 422) and any(
        phrase in text for phrase in UNKNOWN_USER_PHRASES
    )


def _service_role_key() -> str:
    return (
        os.environ.get("SUPABASE_SECRET_KEY", "").strip()
        or os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    )


def _get_supabase_recovery_link(email: str) -> str | None:
    supabase_url = SUPABASE_URL or os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    supabase_key = _service_role_key()
    if not supabase_url:
        raise RuntimeError("SUPABASE_URL is not configured.")
    if not supabase_key:
        raise RuntimeError("SUPABASE_SECRET_KEY is not configured.")

    response = requests.post(
        f"{supabase_url}/auth/v1/admin/generate_link",
        headers={
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json",
        },
        json={
            "type": "recovery",
            "email": email,
            "redirect_to": RESET_PAGE_URL,
        },
        timeout=(3, 10),
    )
    if _is_unknown_user_response(response):
        return None
    response.raise_for_status()

    result = response.json()
    action_link = result.get("action_link")
    if not action_link and isinstance(result.get("properties"), dict):
        action_link = result["properties"].get("action_link")
    if not isinstance(action_link, str) or not action_link:
        raise RuntimeError("Supabase did not return a recovery link.")
    return action_link


def send_reset(data: SendResetRequest):
    # Same response whether or not the account exists, so emails can't be enumerated.
    try:
        api_key = os.environ.get("RESEND_API_KEY")
        resend.api_key = api_key
        if not api_key:
            raise RuntimeError("RESEND_API_KEY is not configured.")

        recovery_link = _get_supabase_recovery_link(str(data.email).strip().lower())
        if recovery_link is None:
            return GENERIC_RESET

        reset_link = html.escape(recovery_link, quote=True)
        resend.Emails.send({
            "from": f"AlphaGuard Security <{RESET_SENDER}>",
            "to": [str(data.email).strip().lower()],
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
        return GENERIC_RESET
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("send-reset failed: %s", e)
        # 503 (not 500) so the client can fall back to Supabase-hosted recovery mail.
        raise HTTPException(
            status_code=503,
            detail="Could not send a password reset email. Please try again later.",
        ) from e


def _verified_supabase_email(request: Request) -> str | None:
    """Email of the caller's Supabase session, or None if absent/invalid."""
    auth_header = request.headers.get("authorization", "")
    scheme, _, token = auth_header.partition(" ")
    key = _service_role_key()
    if scheme.lower() != "bearer" or not token or not SUPABASE_URL or not key:
        return None
    try:
        response = requests.get(
            f"{SUPABASE_URL}/auth/v1/user",
            headers={"apikey": key, "Authorization": f"Bearer {token}"},
            timeout=(3, 10),
        )
        if response.status_code != 200:
            return None
        email = response.json().get("email")
    except (requests.RequestException, ValueError):
        return None
    return email.strip().lower() if isinstance(email, str) else None


def _signup_welcome(data: SignupNotifyRequest, verified_email: str | None) -> JSONResponse:
    email_sent = False
    recipient = str(data.email).strip().lower()
    # Only mail the address the caller has proven they own via a Supabase session.
    if RESEND_KEY and verified_email == recipient:
        try:
            resend.api_key = os.environ.get("RESEND_API_KEY")
            resend.Emails.send({
                "from": f"AlphaGuard Security <{RESET_SENDER}>",
                "to": [recipient],
                "subject": "Welcome to AlphaGuard Security Suite",
                "html": f"<h2>Welcome {html.escape(data.name)}!</h2><p>Your trial account has been created successfully.</p>",
            })
            email_sent = True
        except Exception as e:
            logger.exception("Welcome email failed: %s", e)

    return JSONResponse(content={
        "status": "success",
        "success": True,
        "message": "Account recorded.",
        "email_dispatched": email_sent,
        "role": "customer",
    })


@app.post("/api/send-reset")
@app.post("/send-reset")
def send_reset_route(data: SendResetRequest):
    return send_reset(data)


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path: str = ""):
    if request.method != "POST":
        return JSONResponse(status_code=404, content={"detail": "Not found."})

    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    action = str(body.get("action") or "").strip().lower()
    combined = _combined_path(request, path)

    if (
        action in {"forgot", "reset"}
        or "send-reset" in combined
        or "forgot-password" in combined
        or "reset-password" in combined
    ):
        try:
            reset_request = SendResetRequest.model_validate({"email": body.get("email", "")})
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="A valid email address is required.") from exc
        return JSONResponse(content=send_reset(reset_request))

    if "check-availability" in combined:
        return JSONResponse(content={
            "status": "success",
            "available": True,
            "message": "Availability is enforced by Supabase Auth.",
        })

    if action in {"signup", "register"} or "register" in combined or "signup" in combined:
        try:
            notify = SignupNotifyRequest.model_validate({
                "email": body.get("email", ""),
                "name": body.get("name") or "User",
            })
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="A valid email address is required.") from exc
        return _signup_welcome(notify, _verified_supabase_email(request))

    if action == "login" or "token" in combined or "login" in combined:
        return JSONResponse(
            status_code=401,
            content={
                "detail": "Sign in with your AlphaGuard account. Demo tokens are disabled.",
            },
        )

    return JSONResponse(status_code=404, content={"detail": "Not found."})
