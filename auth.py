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


def _get_admin_credentials() -> tuple[str, str, str]:
    admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    secret_key = os.getenv("JWT_SECRET_KEY", "")

    if not admin_email or len(admin_password) < 16 or len(secret_key) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Admin authentication is not configured. Set ADMIN_EMAIL, "
                "an ADMIN_PASSWORD of at least 16 characters, and a "
                "JWT_SECRET_KEY of at least 32 characters."
            ),
        )
    return admin_email, admin_password, secret_key


def issue_admin_token(login: AdminLoginSchema) -> str:
    admin_email, admin_password, secret_key = _get_admin_credentials()
    supplied_email = str(login.email).strip().lower()

    email_matches = hmac.compare_digest(supplied_email, admin_email)
    password_matches = hmac.compare_digest(login.password, admin_password)
    if not email_matches or not password_matches:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": admin_email, "iss": TOKEN_ISSUER, "exp": expires_at},
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

    admin_email, _, secret_key = _get_admin_credentials()
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
    if not isinstance(user_email, str) or not hmac.compare_digest(user_email, admin_email):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin authorization required.",
        )
    return user_email
