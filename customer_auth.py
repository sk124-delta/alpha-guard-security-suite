import hashlib
import hmac
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from html import escape
from urllib.parse import urlsplit

import requests
from jose import jwt
from pydantic import BaseModel, Field, field_validator


CUSTOMER_TOKEN_ISSUER = "alphaguard-customer-api"
CUSTOMER_TOKEN_EXPIRE_MINUTES = 30
PASSWORD_HASH_ITERATIONS = 600_000
PASSWORD_RESET_EXPIRE_MINUTES = 30
RESEND_API_URL = "https://api.resend.com/emails"
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class CustomerRegistrationSchema(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Name cannot be blank.")
        return value

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("Enter a valid email address.")
        return value


class CustomerLoginSchema(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("Enter a valid email address.")
        return value


class PasswordResetRequestSchema(BaseModel):
    email: str = Field(min_length=3, max_length=254)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("Enter a valid email address.")
        return value


class PasswordResetConfirmSchema(BaseModel):
    token: str = Field(min_length=32, max_length=128)
    password: str = Field(min_length=8, max_length=128)


def hash_customer_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_customer_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, iteration_text, salt_hex, digest_hex = encoded_hash.split("$")
        iterations = int(iteration_text)
        salt = bytes.fromhex(salt_hex)
        expected_digest = bytes.fromhex(digest_hex)
    except (AttributeError, TypeError, ValueError):
        return False

    if (
        algorithm != "pbkdf2_sha256"
        or not 100_000 <= iterations <= 1_000_000
        or len(salt) != 16
        or len(expected_digest) != 32
    ):
        return False

    actual_digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(actual_digest, expected_digest)


def issue_customer_token(email: str) -> str:
    secret_key = os.getenv("JWT_SECRET_KEY", "")
    if len(secret_key) < 32:
        raise RuntimeError("Customer authentication requires a JWT_SECRET_KEY of at least 32 characters.")

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=CUSTOMER_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {
            "sub": email,
            "iss": CUSTOMER_TOKEN_ISSUER,
            "role": "customer",
            "exp": expires_at,
        },
        secret_key,
        algorithm="HS256",
    )


def get_account_email_settings() -> tuple[str, str]:
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    sender_email = (
        os.getenv("AUTH_EMAIL_FROM") or os.getenv("RESEND_FROM_EMAIL", "")
    ).strip()
    if not api_key or not sender_email:
        raise RuntimeError(
            "Account email is not configured. Set RESEND_API_KEY and "
            "AUTH_EMAIL_FROM (or RESEND_FROM_EMAIL)."
        )
    if not EMAIL_PATTERN.fullmatch(sender_email):
        raise RuntimeError("The configured account email sender is invalid.")
    return api_key, sender_email


def get_password_reset_settings() -> tuple[str, str, str]:
    api_key, sender_email = get_account_email_settings()
    public_app_url = os.getenv("PUBLIC_APP_URL", "").strip()

    if not public_app_url:
        raise RuntimeError(
            "Password recovery is not configured. Set PUBLIC_APP_URL."
        )

    try:
        parsed_url = urlsplit(public_app_url)
        parsed_url.port
    except ValueError as exc:
        raise RuntimeError("PUBLIC_APP_URL is invalid.") from exc
    local_http_host = parsed_url.hostname in {"localhost", "127.0.0.1"}
    invalid_scheme = parsed_url.scheme != "https" and not (
        parsed_url.scheme == "http" and local_http_host
    )
    if (
        invalid_scheme
        or not parsed_url.hostname
        or parsed_url.username
        or parsed_url.password
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise RuntimeError("PUBLIC_APP_URL must be an HTTPS application URL.")

    return api_key, sender_email, public_app_url.rstrip("/")


def create_password_reset_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, token_hash


def send_welcome_email(
    name: str,
    email: str,
    settings: tuple[str, str],
) -> None:
    api_key, sender_email = settings
    safe_name = escape(name)
    response = None
    try:
        response = requests.post(
            RESEND_API_URL,
            json={
                "from": f"AlphaGuard Security <{sender_email}>",
                "to": [email],
                "subject": "Welcome to AlphaGuard Security Suite!",
                "html": (
                    f"<h2>Welcome to AlphaGuard, {safe_name}!</h2>"
                    "<p>Your digital asset security account has been created.</p>"
                    "<p>Continue to the plan setup wizard to get a recommendation. "
                    "No trial or subscription is activated automatically.</p>"
                    "<p>Best regards,<br>AlphaGuard Security Operations</p>"
                ),
            },
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=(3, 15),
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise RuntimeError("Welcome email could not be sent.") from exc

    if not 200 <= response.status_code < 300:
        raise RuntimeError(
            f"Welcome email provider returned HTTP {response.status_code}."
        )


def send_password_reset_email(
    email: str,
    token: str,
    settings: tuple[str, str, str],
) -> None:
    api_key, sender_email, public_app_url = settings
    reset_url = f"{public_app_url}/#reset-password={token}"
    response = None
    try:
        response = requests.post(
            RESEND_API_URL,
            json={
                "from": f"AlphaGuard <{sender_email}>",
                "to": [email],
                "subject": "Reset your AlphaGuard password",
                "html": (
                    "<p>We received a request to reset your AlphaGuard password.</p>"
                    f'<p><a href="{escape(reset_url, quote=True)}">Reset your password</a></p>'
                    "<p>This link expires in 30 minutes. If you did not request a reset, "
                    "you can ignore this email.</p>"
                ),
            },
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=(3, 15),
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise RuntimeError("Password recovery email could not be sent.") from exc

    if not 200 <= response.status_code < 300:
        raise RuntimeError(
            f"Password recovery email provider returned HTTP {response.status_code}."
        )
