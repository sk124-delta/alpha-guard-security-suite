import hmac
import os
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel

ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30
TOKEN_ISSUER = "alphaguard-api"
bearer_scheme = HTTPBearer(auto_error=False)


class AdminLoginSchema(BaseModel):
    email: str
    password: str


def _get_admin_credentials() -> tuple[dict[str, str], str]:
    admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    legal_email = os.getenv("LEGAL_EMAIL", "").strip().lower()
    legal_password = os.getenv("LEGAL_PASSWORD", "")
    secret_key = os.getenv("JWT_SECRET_KEY", "")

    if (
        not admin_email
        or len(admin_password) < 16
        or len(secret_key) < 32
        or bool(legal_email) != bool(legal_password)
        or (legal_email and len(legal_password) < 16)
        or (legal_email and legal_email == admin_email)
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Admin authentication is not configured. Set ADMIN_EMAIL, "
                "an ADMIN_PASSWORD of at least 16 characters, and a "
                "JWT_SECRET_KEY of at least 32 characters. To enable legal "
                "account access, also set a unique LEGAL_EMAIL and a "
                "LEGAL_PASSWORD of at least 16 characters."
            ),
        )

    users = {admin_email: admin_password}
    if legal_email:
        users[legal_email] = legal_password
    return users, secret_key


def issue_admin_token(login: AdminLoginSchema) -> str:
    users, secret_key = _get_admin_credentials()
    supplied_email = str(login.email).strip().lower()

    authenticated_email = None
    for configured_email, configured_password in users.items():
        email_matches = hmac.compare_digest(supplied_email, configured_email)
        password_matches = hmac.compare_digest(login.password, configured_password)
        if email_matches and password_matches:
            authenticated_email = configured_email

    if authenticated_email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": authenticated_email, "iss": TOKEN_ISSUER, "exp": expires_at},
        secret_key,
        algorithm=ALGORITHM,
    )


def verify_admin_access(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    users, secret_key = _get_admin_credentials()
    try:
        payload = jwt.decode(
            credentials.credentials,
            secret_key,
            algorithms=[ALGORITHM],
            issuer=TOKEN_ISSUER,
            options={"require_exp": True, "require_sub": True, "require_iss": True},
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user_email = payload.get("sub")
    if not isinstance(user_email, str) or not any(
        hmac.compare_digest(user_email, configured_email) for configured_email in users
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin authorization required.",
        )
    return user_email
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

SMTP_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("MAIL_PORT", 587))
SENDER_EMAIL = os.getenv("MAIL_FROM", "alphaguard.securitysuite@gmail.com")
SENDER_PASSWORD = os.getenv("MAIL_PASSWORD", "")

def send_email(recipient: str, subject: str, body: str):
    if not SENDER_PASSWORD:
        print("Warning: MAIL_PASSWORD not configured. Email not sent.")
        return False
        
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"AlphaGuard Security <{SENDER_EMAIL}>"
    msg["To"] = recipient

    html_part = MIMEText(body, "html")
    msg.attach(html_part)

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, recipient, msg.as_string())
        server.close()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@router.post("/forgot-password")
async def forgot_password(data: dict):
    email = data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
        
    reset_token = "sample_reset_token_123"  # Replace with generated JWT/token logic
    reset_url = f"https://alphaguardsuite.com/reset-password?token={reset_token}"
    
    html_content = f"""
    <h3>AlphaGuard Security - Password Reset</h3>
    <p>You requested a password reset for your account.</p>
    <p>Click <a href="{reset_url}">here</a> to reset your password.</p>
    """
    
    sent = send_email(email, "Reset Your AlphaGuard Password", html_content)
    if not sent:
        raise HTTPException(status_code=500, detail="Failed to dispatch email. Check SMTP server configuration.")
        
    return {"message": "Password reset link sent successfully."}