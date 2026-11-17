import hashlib
import hmac
import json
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from ipaddress import ip_address
from urllib.parse import urljoin, urlsplit

from dotenv import load_dotenv

import requests
from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from fastapi.security import HTTPAuthorizationCredentials
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from auth import (
    TOKEN_EXPIRE_MINUTES,
    AdminLoginSchema,
    bearer_scheme,
    issue_admin_token,
    verify_admin_access,
)
from customer_auth import (
    CUSTOMER_TOKEN_EXPIRE_MINUTES,
    PASSWORD_RESET_EXPIRE_MINUTES,
    CustomerLoginSchema,
    CustomerRegistrationSchema,
    MerchantSignupSchema,
    PasswordResetConfirmSchema,
    PasswordResetRequestSchema,
    RegistrationAvailabilitySchema,
    create_password_reset_token,
    get_account_email_settings,
    get_password_reset_settings,
    hash_customer_password,
    issue_customer_token,
    send_password_reset_email,
    send_welcome_email,
    verify_customer_password,
    verify_customer_token,
)
from dmca_dispatcher import (
    DmcaDeliveryError,
    DmcaDeliveryUnknownError,
    DmcaProviderRejectedError,
    WhoisLookupError,
    create_dmca_notice_draft,
    get_resend_settings,
    lookup_whois_contact,
    send_dmca_notice,
)
from scanner import (
    _validate_public_url,
    compare_hashes,
    compute_image_hash,
    public_only_session,
    run_scheduled_scans,
)
from watermarker import (
    DEFAULT_PAYLOAD_ID,
    MAX_DOWNLOAD_BYTES,
    ImageProcessingError,
    process_digital_asset_or_code,
    process_image_in_memory,
)

load_dotenv()

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Set the DATABASE_URL environment variable before starting the API.")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class StoreModel(Base):
    __tablename__ = "connected_stores"

    id = Column(Integer, primary_key=True, index=True)
    store_url = Column(String, unique=True, index=True)
    owner_email = Column(String)
    active_skus = Column(Integer)
    scans_performed = Column(Integer, default=0)


class NoticeModel(Base):
    __tablename__ = "dmca_notices"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    store_id = Column(Integer, ForeignKey("connected_stores.id"), nullable=False, index=True)
    similarity_score = Column(Float, nullable=False)
    target_infringing_url = Column(String, nullable=False)
    original_asset_url = Column(String, nullable=False)
    recipient = Column(String, nullable=False)
    sender = Column(String, nullable=False)
    subject = Column(String, nullable=False)
    body_html = Column(Text, nullable=False)
    status = Column(String, nullable=False, default="PENDING", index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    dispatched_at = Column(DateTime(timezone=True), nullable=True)
    dispatched_by = Column(String, nullable=True)
    provider_message_id = Column(String, nullable=True)


class NoticeAuditLogModel(Base):
    """Append-only record of every outbound legal notice action."""

    __tablename__ = "dmca_notice_audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    event = Column(String, nullable=False)
    user = Column(String, nullable=False)
    target = Column(String, nullable=False)
    recipient = Column(String, nullable=False)
    notice_id = Column(String(36), nullable=False, index=True)
    status = Column(String, nullable=False)


class CustomerAccountModel(Base):
    __tablename__ = "customer_accounts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(120), nullable=False)
    email = Column(String(254), nullable=False, unique=True, index=True)
    password_hash = Column(String(128), nullable=False)
    store_domain = Column(String(253), nullable=True, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class PasswordResetModel(Base):
    __tablename__ = "customer_password_resets"

    token_hash = Column(String(64), primary_key=True)
    email = Column(String(254), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)


class ScanRequestSchema(BaseModel):
    store_id: int
    target_infringing_url: HttpUrl
    infringing_image_url: HttpUrl
    original_image_url: HttpUrl
    host_abuse_email: str | None = None


class DispatchNoticeSchema(BaseModel):
    confirm_dispatch: bool


class DomainInspectionSchema(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class DigitalAssetFingerprintSchema(BaseModel):
    content_string: str = Field(max_length=1_000_000)


class _PageInspector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.title_parts: list[str] = []
        self.meta_description = ""
        self._inside_title = False
        self.image_count = 0
        self.is_shopify = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag.lower() == "title":
            self._inside_title = True
        if tag.lower() == "meta":
            meta_name = (attributes.get("name") or attributes.get("property") or "").lower()
            if meta_name in {"description", "og:description"} and attributes.get("content"):
                self.meta_description = attributes["content"] or ""
        if tag.lower() == "img":
            self.image_count += 1
        if tag.lower() == "script":
            script_type = (attributes.get("type") or "").lower()
            if script_type == "application/ld+json":
                self.text_parts.append(attributes.get("data-shopify") or "")
        for value in attributes.values():
            if value and ("cdn.shopify.com" in value.lower() or "shopify" in value.lower()):
                self.is_shopify = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._inside_title = False

    def handle_data(self, data: str) -> None:
        self.text_parts.append(data)
        if self._inside_title:
            self.title_parts.append(data)
        if "cdn.shopify.com" in data.lower() or "/products.json" in data.lower():
            self.is_shopify = True


MAX_DOMAIN_PAGE_BYTES = 2 * 1024 * 1024
DOMAIN_REQUEST_TIMEOUT = (3, 7)
INDUSTRY_KEYWORDS = {
    "E-commerce & Apparel": [
        "clothing", "apparel", "fashion", "wear", "dress", "shirts", "shoes",
        "cart", "checkout", "store", "collection", "stitching", "unstitched", "fabric",
    ],
    "Education & Academics": [
        "university", "school", "course", "curriculum", "tuition", "degree",
        "student", "faculty", "academy", "admissions", "scholarship",
    ],
    "Software & SaaS": [
        "software", "api", "dashboard", "pricing", "integration", "developer",
        "documentation", "saas", "platform",
    ],
    "Digital Goods & Media": [
        "ebook", "preset", "template", "vector", "download", "font", "graphics",
    ],
}


def _normalize_inspection_url(value: str) -> str:
    target_url = value.strip()
    if any(ord(character) < 32 or ord(character) == 127 for character in target_url):
        raise ValueError("URL contains invalid control characters.")
    if not target_url:
        raise ValueError("Enter a domain to inspect.")
    if "://" not in target_url:
        target_url = f"https://{target_url}"

    parsed_url = urlsplit(target_url)
    if (
        parsed_url.scheme.lower() not in {"http", "https"}
        or not parsed_url.hostname
        or parsed_url.username
        or parsed_url.password
    ):
        raise ValueError("Enter a public HTTP or HTTPS domain without credentials.")
    try:
        port = parsed_url.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port.") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("URL contains an invalid port.")

    try:
        if parsed_url.hostname.lower() in {"localhost", "localhost.localdomain"}:
            raise ValueError("Only publicly routable domains may be inspected.")
        host_ip = ip_address(parsed_url.hostname)
    except ValueError as exc:
        if "publicly routable" in str(exc):
            raise
        host_ip = None
    if host_ip is not None and not host_ip.is_global:
        raise ValueError("Only publicly routable domains may be inspected.")
    normalized = target_url.rstrip("/")
    return normalized


MAX_DOMAIN_REDIRECTS = 3


def _fetch_public_page(url: str) -> tuple[bytes, str]:
    current_url = url
    with public_only_session() as session:
        for hop in range(MAX_DOMAIN_REDIRECTS + 1):
            # Every hop (including the first) is re-validated before any request is made.
            _validate_public_url(current_url)
            with session.get(
                current_url,
                headers={"User-Agent": "AlphaGuard-Audit-Bot/1.0"},
                timeout=DOMAIN_REQUEST_TIMEOUT,
                allow_redirects=False,
                stream=True,
            ) as response:
                if 300 <= response.status_code < 400:
                    location = response.headers.get("Location")
                    if not location:
                        raise ValueError("Domain redirect did not include a destination.")
                    if hop >= MAX_DOMAIN_REDIRECTS:
                        raise ValueError("Domain redirected too many times.")
                    current_url = urljoin(current_url, location)
                    continue
                response.raise_for_status()
                content_length = response.headers.get("Content-Length")
                if content_length:
                    try:
                        if int(content_length) > MAX_DOMAIN_PAGE_BYTES:
                            raise ValueError("Domain page exceeds the inspection size limit.")
                    except ValueError as exc:
                        if "size limit" in str(exc):
                            raise
                        raise ValueError("Domain response has an invalid Content-Length.") from exc

                content = bytearray()
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    content.extend(chunk)
                    if len(content) > MAX_DOMAIN_PAGE_BYTES:
                        raise ValueError("Domain page exceeds the inspection size limit.")
                return bytes(content), response.headers.get("Content-Type", "").lower()
    raise ValueError("Domain redirected too many times.")


Base.metadata.create_all(bind=engine)

app = FastAPI(title="AlphaGuard Security API", version="3.4")
frontend_origins = [
    origin.strip()
    for origin in os.getenv(
        "FRONTEND_ORIGINS",
        "https://www.alphaguardsuite.com,http://localhost:3000",
    ).split(",")
    if origin.strip()
]
if frontend_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=frontend_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["X-AlphaGuard-Perceptual-Hash", "X-AlphaGuard-Payload-Id"],
    )


INDEX_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def read_index():
    if os.path.exists(INDEX_HTML_PATH):
        with open(INDEX_HTML_PATH, "r", encoding="utf-8") as f:
            return f.read()
    return HTMLResponse("<h1>index.html not found</h1>", status_code=404)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Principal(BaseModel):
    email: str
    role: str


def get_current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> Principal:
    """Accept an admin or customer bearer token; role comes only from the verified token."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    customer_email = verify_customer_token(credentials.credentials)
    if customer_email:
        return Principal(email=customer_email, role="customer")
    try:
        return Principal(email=verify_admin_access(credentials), role="admin")
    except HTTPException as exc:
        if exc.status_code == 503:
            raise
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def require_store_access(db: Session, store_id: int, principal: Principal) -> StoreModel:
    store = db.query(StoreModel).filter(StoreModel.id == store_id).first()
    # Same response for missing and foreign stores so IDs cannot be enumerated.
    if not store or (
        principal.role != "admin"
        and (store.owner_email or "").strip().lower() != principal.email
    ):
        raise HTTPException(status_code=404, detail="Store not found")
    return store


@app.post("/api/v1/inspect-domain")
def inspect_domain(data: DomainInspectionSchema):
    try:
        target_url = _normalize_inspection_url(data.url)
        page_bytes, content_type = _fetch_public_page(target_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve the public domain for inspection.",
        ) from exc

    if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
        raise HTTPException(status_code=422, detail="The inspected URL did not return an HTML page.")

    parser = _PageInspector()
    page_html = page_bytes.decode("utf-8", errors="replace")
    parser.feed(page_html)
    page_text = " ".join(parser.text_parts).lower()
    is_shopify = parser.is_shopify or "/products.json" in page_html.lower()
    is_ecommerce = is_shopify or any(
        keyword in page_text
        for keyword in ("cart", "checkout", "sku", "add to cart", "price")
    )
    if not is_ecommerce:
        return {
            "valid": False,
            "message": "This page does not appear to be a commercial store or product catalog.",
        }

    asset_count = parser.image_count
    count_source = "homepage_image_tags"
    inspection_note = None
    if is_shopify:
        products_url = urljoin(f"{target_url.rstrip('/')}/", "products.json?limit=250")
        try:
            products_bytes, products_content_type = _fetch_public_page(products_url)
            if "json" in products_content_type:
                products_payload = json.loads(products_bytes)
                products = products_payload.get("products", []) if isinstance(products_payload, dict) else []
                if isinstance(products, list):
                    asset_count = max(asset_count, len(products) * 4)
                    count_source = "shopify_product_estimate"
                else:
                    inspection_note = "Shopify product data was unavailable; count uses homepage image tags."
            else:
                inspection_note = "Shopify product data was unavailable; count uses homepage image tags."
        except (requests.RequestException, ValueError):
            inspection_note = "Shopify product data was unavailable; count uses homepage image tags."

    hostname = urlsplit(target_url).hostname.lower()
    is_major_brand = hostname == "junaidjamshed.com" or hostname.endswith(".junaidjamshed.com")
    if asset_count > 1000 or is_major_brand:
        tier_name = "Enterprise Tier"
        price = "$899 / month"
        recommended_plan_id = "enterprise_899"
    elif asset_count > 250:
        tier_name = "High-Risk Tier"
        price = "$299 / month"
        recommended_plan_id = "highrisk_299"
    else:
        tier_name = "Growth SaaS Tier"
        price = "$79 / month"
        recommended_plan_id = "growth_79"

    return {
        "valid": True,
        "detected_category": "Apparel / E-Commerce",
        "catalog_images_indexed": asset_count,
        "catalog_count_source": count_source,
        "inspection_note": inspection_note,
        "recommended_tier": tier_name,
        "price": price,
        "plan_id": recommended_plan_id,
    }


@app.post(
    "/api/v1/protection/process-image",
    response_class=Response,
    responses={
        200: {
            "content": {"image/png": {}},
            "description": "Sanitized, watermarked PNG. Metadata is returned in response headers.",
        }
    },
)
def process_protected_image(image_file: UploadFile = File(...)):
    image_bytes = image_file.file.read(MAX_DOWNLOAD_BYTES + 1)
    if len(image_bytes) > MAX_DOWNLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Image exceeds the maximum allowed size.")

    try:
        processed_image, phash_signature = process_image_in_memory(
            image_bytes, DEFAULT_PAYLOAD_ID
        )
    except ImageProcessingError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return Response(
        content=processed_image,
        media_type="image/png",
        headers={
            "Content-Disposition": 'attachment; filename="alphaguard-watermarked.png"',
            "X-AlphaGuard-Perceptual-Hash": phash_signature,
            "X-AlphaGuard-Payload-Id": DEFAULT_PAYLOAD_ID,
        },
    )


@app.post("/api/v1/protection/fingerprint-digital-asset")
def fingerprint_digital_asset(data: DigitalAssetFingerprintSchema):
    return process_digital_asset_or_code(data.content_string)


@app.post("/api/v1/detect-category")
def detect_website_category(data: DomainInspectionSchema):
    try:
        target_url = _normalize_inspection_url(data.url)
        page_bytes, content_type = _fetch_public_page(target_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve the public domain for category detection.",
        ) from exc

    if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
        raise HTTPException(status_code=422, detail="The inspected URL did not return an HTML page.")

    parser = _PageInspector()
    parser.feed(page_bytes.decode("utf-8", errors="replace"))
    title = " ".join(" ".join(parser.title_parts).split())
    meta_description = parser.meta_description.strip()
    searchable_text = f"{title} {meta_description}".lower()

    scores = {
        category: sum(
            bool(re.search(r"\b" + re.escape(keyword) + r"\b", searchable_text))
            for keyword in keywords
        )
        for category, keywords in INDUSTRY_KEYWORDS.items()
    }
    detected_category = max(scores, key=scores.get)
    confidence_score = scores[detected_category]
    if confidence_score == 0:
        detected_category = "General Business / Unclassified"

    return {
        "status": "success",
        "detected_category": detected_category,
        "confidence_score": confidence_score,
        "title": title or target_url,
    }


REGISTRATION_EMAIL_ERROR = "An account with this email address already exists. Please sign in instead."
REGISTRATION_DOMAIN_ERROR = "This store URL is already registered under another account."


def ensure_registration_available(db: Session, email: str, store_domain: str | None) -> None:
    reserved_emails = {
        os.getenv("ADMIN_EMAIL", "").strip().lower(),
        os.getenv("LEGAL_EMAIL", "").strip().lower(),
    }
    if email in reserved_emails:
        raise HTTPException(status_code=409, detail="This email cannot be used for a customer account.")
    if db.query(CustomerAccountModel).filter(CustomerAccountModel.email == email).first():
        raise HTTPException(status_code=400, detail=REGISTRATION_EMAIL_ERROR)
    if store_domain and db.query(CustomerAccountModel).filter(CustomerAccountModel.store_domain == store_domain).first():
        raise HTTPException(status_code=400, detail=REGISTRATION_DOMAIN_ERROR)
    if store_domain and db.query(StoreModel).filter(StoreModel.store_url == store_domain).first():
        raise HTTPException(status_code=400, detail=REGISTRATION_DOMAIN_ERROR)


@app.post("/v1/auth/check-availability")
@app.post("/api/v1/auth/check-availability")
def check_registration_availability(data: RegistrationAvailabilitySchema, db: Session = Depends(get_db)):
    ensure_registration_available(db, data.email, data.store_url)
    return {"status": "success", "available": True}


@app.post("/v1/auth/register")
@app.post("/api/v1/auth/register")
def register_customer(data: CustomerRegistrationSchema, db: Session = Depends(get_db)):
    email_error = REGISTRATION_EMAIL_ERROR
    domain_error = REGISTRATION_DOMAIN_ERROR
    store_domain = data.store_url  # normalized by the schema validator
    ensure_registration_available(db, data.email, store_domain)

    try:
        access_token = issue_customer_token(data.email)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    customer = CustomerAccountModel(
        name=data.name,
        email=data.email,
        password_hash=hash_customer_password(data.password),
        store_domain=store_domain,
    )
    db.add(customer)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        # Concurrent request won the race; report whichever constraint now conflicts.
        if db.query(CustomerAccountModel).filter(CustomerAccountModel.email == data.email).first():
            raise HTTPException(status_code=400, detail=email_error) from exc
        raise HTTPException(status_code=400, detail=domain_error) from exc

    welcome_email_sent = False
    try:
        send_welcome_email(data.name, data.email, get_account_email_settings())
        welcome_email_sent = True
    except RuntimeError as exc:
        logger.warning("Could not send customer welcome email: %s", exc)

    return {
        "status": "success",
        "message": "Account created successfully.",
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": CUSTOMER_TOKEN_EXPIRE_MINUTES * 60,
        "role": "customer",
        "user": {"email": data.email, "store_name": data.name, "store_domain": store_domain},
        "welcome_email_sent": welcome_email_sent,
        "email_dispatched": welcome_email_sent,
    }


@app.post("/api/v1/auth/signup")
def register_merchant(data: MerchantSignupSchema, db: Session = Depends(get_db)):
    store_domain = data.store_url
    ensure_registration_available(db, data.email, store_domain)

    customer = CustomerAccountModel(
        name=data.store_name,
        email=data.email,
        password_hash=hash_customer_password(data.password),
        store_domain=store_domain,
    )
    store = StoreModel(
        store_url=store_domain,
        owner_email=data.email,
        active_skus=0,
    )
    db.add_all([customer, store])
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if db.query(CustomerAccountModel).filter(CustomerAccountModel.email == data.email).first():
            raise HTTPException(status_code=400, detail=REGISTRATION_EMAIL_ERROR) from exc
        if (
            db.query(CustomerAccountModel)
            .filter(CustomerAccountModel.store_domain == store_domain)
            .first()
            or db.query(StoreModel).filter(StoreModel.store_url == store_domain).first()
        ):
            raise HTTPException(status_code=400, detail=REGISTRATION_DOMAIN_ERROR) from exc
        logger.exception("Could not persist merchant signup.")
        raise HTTPException(status_code=500, detail="Merchant signup could not be completed.") from exc

    return {
        "message": "Merchant account successfully created!",
        "store_name": data.store_name,
        "email": data.email,
        "role": "customer",
    }


@app.post("/v1/auth/token")
@app.post("/api/v1/auth/token")
def create_auth_token(data: CustomerLoginSchema, db: Session = Depends(get_db)):
    customer = (
        db.query(CustomerAccountModel)
        .filter(CustomerAccountModel.email == data.email)
        .first()
    )
    if customer:
        if not verify_customer_password(data.password, customer.password_hash):
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        try:
            access_token = issue_customer_token(customer.email)
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {
            "status": "success",
            "message": "Sign in successful.",
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": CUSTOMER_TOKEN_EXPIRE_MINUTES * 60,
            "role": "customer",
        }

    return {
        "status": "success",
        "message": "Sign in successful.",
        "access_token": issue_admin_token(
            AdminLoginSchema(email=data.email, password=data.password)
        ),
        "token_type": "bearer",
        "expires_in": TOKEN_EXPIRE_MINUTES * 60,
        "role": "admin",
    }


@app.post("/v1/auth/reset-password")
@app.post("/api/v1/auth/reset-password")
def request_customer_password_reset(
    data: PasswordResetRequestSchema,
    db: Session = Depends(get_db),
):
    try:
        email_settings = get_password_reset_settings()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    customer = (
        db.query(CustomerAccountModel)
        .filter(CustomerAccountModel.email == data.email)
        .first()
    )
    if not customer:
        return {
            "status": "success",
            "message": "If an account exists for this email, password recovery instructions have been sent."
        }

    raw_token, token_hash = create_password_reset_token()
    now = datetime.now(timezone.utc)
    db.query(PasswordResetModel).filter(
        PasswordResetModel.email == customer.email,
        PasswordResetModel.used_at.is_(None),
    ).update({PasswordResetModel.used_at: now}, synchronize_session=False)
    db.add(
        PasswordResetModel(
            token_hash=token_hash,
            email=customer.email,
            expires_at=now + timedelta(minutes=PASSWORD_RESET_EXPIRE_MINUTES),
        )
    )
    db.commit()

    try:
        send_password_reset_email(customer.email, raw_token, email_settings)
    except RuntimeError as exc:
        db.query(PasswordResetModel).filter(
            PasswordResetModel.token_hash == token_hash
        ).update({PasswordResetModel.used_at: datetime.now(timezone.utc)})
        db.commit()
        raise HTTPException(
            status_code=503,
            detail="Password recovery email could not be sent. Please try again later.",
        ) from exc

    return {
        "status": "success",
        "message": "If an account exists for this email, password recovery instructions have been sent."
    }


@app.post("/api/v1/auth/reset-password/confirm")
def confirm_customer_password_reset(
    data: PasswordResetConfirmSchema,
    db: Session = Depends(get_db),
):
    token_hash = hashlib.sha256(data.token.encode("utf-8")).hexdigest()
    reset = (
        db.query(PasswordResetModel)
        .filter(
            PasswordResetModel.token_hash == token_hash,
            PasswordResetModel.used_at.is_(None),
        )
        .first()
    )
    now = datetime.now(timezone.utc)
    if not reset:
        raise HTTPException(status_code=400, detail="The password reset link is invalid or expired.")

    expires_at = reset.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        raise HTTPException(status_code=400, detail="The password reset link is invalid or expired.")

    customer = (
        db.query(CustomerAccountModel)
        .filter(CustomerAccountModel.email == reset.email)
        .first()
    )
    if not customer:
        raise HTTPException(status_code=400, detail="The password reset link is invalid or expired.")

    customer.password_hash = hash_customer_password(data.password)
    db.query(PasswordResetModel).filter(
        PasswordResetModel.email == customer.email,
        PasswordResetModel.used_at.is_(None),
    ).update({PasswordResetModel.used_at: now}, synchronize_session=False)
    db.commit()
    return {
        "status": "success",
        "message": "Your password has been reset. You can now sign in.",
    }


@app.get("/api/v1/admin/me")
def read_admin_profile(admin_email: str = Depends(verify_admin_access)):
    return {"email": admin_email, "role": "admin"}


@app.get("/api/v1/admin/notices")
def list_admin_notices(
    admin_email: str = Depends(verify_admin_access),
    db: Session = Depends(get_db),
):
    notices = (
        db.query(NoticeModel)
        .order_by(NoticeModel.created_at.desc())
        .limit(100)
        .all()
    )
    return [
        {
            "notice_id": notice.id,
            "store_id": notice.store_id,
            "target_infringing_url": notice.target_infringing_url,
            "recipient": notice.recipient,
            "sender": notice.sender,
            "similarity_score": round(notice.similarity_score, 2),
            "status": notice.status,
            "created_at": notice.created_at.isoformat(),
            "subject": notice.subject,
            "draft_html": notice.body_html,
        }
        for notice in notices
    ]


class DispatchNotAuthorized(Exception):
    """Raised when an outbound notice lacks explicit confirmation or an enabled automation setting."""


class DispatchConflict(Exception):
    def __init__(self, status: str):
        super().__init__(status)
        self.status = status


SIMILARITY_DISCLAIMER = "Similarity is not a legal determination. Review all evidence before sending."


def _add_notice_audit(db: Session, notice: NoticeModel, *, user: str, event: str, status: str) -> None:
    db.add(
        NoticeAuditLogModel(
            event=event,
            user=user,
            target=notice.target_infringing_url,
            recipient=notice.recipient,
            notice_id=notice.id,
            status=status,
        )
    )


def send_notice_guarded(
    db: Session,
    notice: NoticeModel,
    *,
    api_key: str,
    sender_email: str,
    actor: str,
    confirmed: bool = False,
    automated: bool = False,
) -> tuple[str | None, DmcaDeliveryError | None]:
    """The only code path that sends a legal notice.

    A send needs either an explicit confirmation from a named user or the documented
    AUTO_DISPATCH_DMCA setting. The authorization and the outcome are both written to the audit log.
    Returns (provider_message_id, failure); failure is None when the provider accepted the notice.
    """
    if automated:
        if not auto_dispatch_enabled():
            raise DispatchNotAuthorized("Automatic dispatch is disabled; set AUTO_DISPATCH_DMCA to enable it.")
        authorization_event = "auto_dispatch_authorized"
    else:
        if confirmed is not True or not (actor or "").strip():
            raise DispatchNotAuthorized("Explicit dispatch confirmation from a signed-in user is required.")
        authorization_event = "dispatch_confirmed"

    claimed = (
        db.query(NoticeModel)
        .filter(NoticeModel.id == notice.id, NoticeModel.status == "PENDING")
        .update({NoticeModel.status: "DISPATCHING"}, synchronize_session=False)
    )
    if claimed != 1:
        db.rollback()
        db.refresh(notice)
        raise DispatchConflict(notice.status)
    _add_notice_audit(db, notice, user=actor, event=authorization_event, status="DISPATCHING")
    db.commit()

    provider_message_id = None
    failure: DmcaDeliveryError | None = None
    try:
        provider_message_id = send_dmca_notice(
            api_key=api_key,
            sender_email=sender_email,
            recipient=notice.recipient,
            subject=notice.subject,
            html=notice.body_html,
        )
    except DmcaProviderRejectedError as exc:
        notice.status = "DISPATCH_FAILED"
        failure = exc
    except DmcaDeliveryUnknownError as exc:
        notice.status = "DISPATCH_UNKNOWN"
        failure = exc
    else:
        notice.status = "DISPATCHED"
        notice.dispatched_at = datetime.now(timezone.utc)
        notice.dispatched_by = actor
        notice.provider_message_id = provider_message_id
    _add_notice_audit(db, notice, user=actor, event="dispatch_result", status=notice.status)
    db.commit()
    return provider_message_id, failure


@app.post("/api/v1/admin/dispatch-notice/{notice_id}")
def dispatch_dmca_notice(
    notice_id: str,
    data: DispatchNoticeSchema,
    admin_email: str = Depends(verify_admin_access),
    db: Session = Depends(get_db),
):
    if not data.confirm_dispatch:
        raise HTTPException(status_code=400, detail="Explicit dispatch confirmation is required.")

    notice = db.query(NoticeModel).filter(NoticeModel.id == notice_id).first()
    if not notice:
        raise HTTPException(status_code=404, detail="Notice not found.")
    if notice.similarity_score < 90.0:
        raise HTTPException(
            status_code=409,
            detail="Manual legal review required: match is below the 90% dispatch threshold.",
        )
    try:
        api_key, configured_sender = get_resend_settings()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="Configured sender email is invalid.") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if notice.sender != configured_sender:
        raise HTTPException(
            status_code=409,
            detail="The configured email sender differs from the sender on this notice.",
        )

    try:
        provider_message_id, failure = send_notice_guarded(
            db,
            notice,
            api_key=api_key,
            sender_email=configured_sender,
            actor=admin_email,
            confirmed=data.confirm_dispatch,
        )
    except DispatchNotAuthorized as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except DispatchConflict as exc:
        raise HTTPException(
            status_code=409,
            detail=f"Notice cannot be dispatched from status {exc.status}.",
        ) from exc
    if failure is not None:
        raise HTTPException(status_code=502, detail=str(failure)) from failure

    return {
        "success": True,
        "notice_id": notice.id,
        "status": notice.status,
        "message": f"Notice {notice.id} was accepted by the email provider.",
        "provider_message_id": provider_message_id,
    }


@app.get("/api/v1/metrics/{store_id}")
def get_store_metrics(
    store_id: int,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    store = require_store_access(db, store_id, principal)

    return {
        "store_url": store.store_url,
        "scans_performed": store.scans_performed,
        "webhook_health": "100%",
    }


def auto_dispatch_enabled() -> bool:
    return os.getenv("AUTO_DISPATCH_DMCA", "").strip().lower() in {"1", "true", "yes"}


def auto_dispatch_notice(db: Session, notice_id: str) -> str:
    """Send a PENDING notice without per-notice review, only when AUTO_DISPATCH_DMCA is enabled.

    Returns the resulting status.
    TODO(legal): the automated DMCA workflow must be reviewed by a qualified lawyer before launch.
    """
    if not auto_dispatch_enabled():
        return "PENDING"
    try:
        api_key, configured_sender = get_resend_settings()
    except (RuntimeError, ValueError) as exc:
        logger.warning("Auto-dispatch skipped; email is not configured: %s", exc)
        return "PENDING"

    notice = db.query(NoticeModel).filter(NoticeModel.id == notice_id).first()
    if not notice or notice.sender != configured_sender:
        return "PENDING"

    try:
        _, failure = send_notice_guarded(
            db,
            notice,
            api_key=api_key,
            sender_email=configured_sender,
            actor="auto-dispatch",
            automated=True,
        )
    except DispatchNotAuthorized:
        return "PENDING"
    except DispatchConflict as exc:
        return exc.status
    if failure is not None:
        logger.warning("Auto-dispatch for notice %s ended as %s", notice_id, notice.status)
    return notice.status


@app.post("/api/v1/trigger-scan")
def trigger_automated_scan(authorization: str | None = Header(None)):
    expected = os.getenv("ALPHAGUARD_SCAN_TRIGGER_TOKEN", "")
    if not expected or not hmac.compare_digest(authorization or "", f"Bearer {expected}"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        summary = run_scheduled_scans(
            SessionLocal, StoreModel, NoticeModel, _fetch_public_page, create_dmca_notice_draft, lookup_whois_contact
        )
    except Exception:
        logger.exception("Scheduled scan failed")
        raise HTTPException(status_code=500, detail="Scan failed")
    return {"status": "success", **summary}


@app.post("/api/v1/scan/execute-takedown")
def execute_automated_scan(
    data: ScanRequestSchema,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
):
    store = require_store_access(db, data.store_id, principal)

    try:
        original_hash = compute_image_hash(str(data.original_image_url))
        target_hash = compute_image_hash(str(data.infringing_image_url))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail="Could not retrieve an image.") from exc
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        UnidentifiedImageError,
        OSError,
    ) as exc:
        raise HTTPException(status_code=422, detail="An image URL did not contain a valid image.") from exc

    similarity = compare_hashes(original_hash, target_hash)
    notice_draft = None
    notice_id = None
    if similarity >= 90.0:
        recipient_source = "provided"
        host_abuse_email = data.host_abuse_email
        if not host_abuse_email:
            target_domain = urlsplit(str(data.target_infringing_url)).hostname
            if not target_domain:
                raise HTTPException(
                    status_code=422,
                    detail="A valid target domain is required to look up a WHOIS contact.",
                )
            try:
                host_abuse_email = lookup_whois_contact(target_domain)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            except WhoisLookupError as exc:
                raise HTTPException(
                    status_code=502,
                    detail="WHOIS lookup failed; provide a contact email to create the draft.",
                ) from exc
            if not host_abuse_email:
                raise HTTPException(
                    status_code=422,
                    detail="No email was listed in WHOIS data; provide a recipient to create the draft.",
                )
            recipient_source = "whois"
        try:
            notice_draft = create_dmca_notice_draft(
                host_abuse_email=host_abuse_email,
                target_infringing_url=str(data.target_infringing_url),
                original_asset_url=str(data.original_image_url),
                store_domain=store.store_url,
                recipient_source=recipient_source,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        notice_id = str(uuid.uuid4())
        db.add(
            NoticeModel(
                id=notice_id,
                store_id=store.id,
                similarity_score=similarity,
                target_infringing_url=str(data.target_infringing_url),
                original_asset_url=str(data.original_image_url),
                recipient=notice_draft["recipient"],
                sender=notice_draft["sender"],
                subject=notice_draft["subject"],
                body_html=notice_draft["html"],
                status="PENDING",
            )
        )

    store.scans_performed = (store.scans_performed or 0) + 1
    db.commit()

    notice_status = "PENDING" if notice_id else None
    if notice_id and recipient_source == "provided" and principal.role == "admin" and auto_dispatch_enabled():
        notice_status = auto_dispatch_notice(db, notice_id)

    return {
        "success": True,
        "similarity_match_percentage": round(similarity, 2),
        "takedown_notice_sent": notice_status == "DISPATCHED",
        "notice_status": notice_status,
        "notice_draft": notice_draft,
        "notice_id": notice_id,
        "disclaimer": SIMILARITY_DISCLAIMER,
        "message": (
            _scan_message(notice_draft, notice_status)
        ),
    }


def _scan_message(notice_draft: dict | None, notice_status: str | None) -> str:
    if not notice_draft:
        return "Scan completed; no match met the 90% review threshold."
    if notice_status == "DISPATCHED":
        return "Match found at or above 90%; the DMCA notice was sent automatically."
    if notice_status in {"DISPATCH_FAILED", "DISPATCH_UNKNOWN"}:
        return f"Match found, but automatic dispatch ended as {notice_status}. Review the notice before retrying."
    return "Potential match found. Review the DMCA notice draft before sending."
