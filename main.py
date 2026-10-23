import os
import uuid
import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from ipaddress import ip_address
from urllib.parse import urljoin, urlsplit

import requests
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from auth import (
    TOKEN_EXPIRE_MINUTES,
    AdminLoginSchema,
    issue_admin_token,
    verify_admin_access,
)
from dmca_dispatcher import (
    DmcaDeliveryUnknownError,
    DmcaProviderRejectedError,
    create_dmca_notice_draft,
    get_resend_settings,
    send_dmca_notice,
)
from scanner import _validate_public_url, compare_hashes, compute_image_hash

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


class ScanRequestSchema(BaseModel):
    store_id: int
    target_infringing_url: HttpUrl
    infringing_image_url: HttpUrl
    original_image_url: HttpUrl
    host_abuse_email: str


class DispatchNoticeSchema(BaseModel):
    confirm_dispatch: bool


class DomainInspectionSchema(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


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


def _fetch_public_page(url: str) -> tuple[bytes, str]:
    _validate_public_url(url)
    with requests.Session() as session:
        session.trust_env = False
        with session.get(
            url,
            headers={"User-Agent": "AlphaGuard-Audit-Bot/1.0"},
            timeout=DOMAIN_REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
        ) as response:
            if 300 <= response.status_code < 400:
                raise ValueError("Domain redirects are not followed; inspect the destination directly.")
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
    )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


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


@app.post("/api/v1/auth/token")
def create_admin_token(data: AdminLoginSchema):
    return {
        "access_token": issue_admin_token(data),
        "token_type": "bearer",
        "expires_in": TOKEN_EXPIRE_MINUTES * 60,
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

    claimed = (
        db.query(NoticeModel)
        .filter(NoticeModel.id == notice_id, NoticeModel.status == "PENDING")
        .update({NoticeModel.status: "DISPATCHING"}, synchronize_session=False)
    )
    if claimed != 1:
        db.rollback()
        db.refresh(notice)
        raise HTTPException(
            status_code=409,
            detail=f"Notice cannot be dispatched from status {notice.status}.",
        )
    db.commit()

    try:
        provider_message_id = send_dmca_notice(
            api_key=api_key,
            sender_email=configured_sender,
            recipient=notice.recipient,
            subject=notice.subject,
            html=notice.body_html,
        )
    except DmcaProviderRejectedError as exc:
        notice.status = "DISPATCH_FAILED"
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except DmcaDeliveryUnknownError as exc:
        notice.status = "DISPATCH_UNKNOWN"
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    notice.status = "DISPATCHED"
    notice.dispatched_at = datetime.now(timezone.utc)
    notice.dispatched_by = admin_email
    notice.provider_message_id = provider_message_id
    db.commit()

    return {
        "success": True,
        "notice_id": notice.id,
        "status": notice.status,
        "message": f"Notice {notice.id} was accepted by the email provider.",
        "provider_message_id": provider_message_id,
    }


@app.get("/api/v1/metrics/{store_id}")
def get_store_metrics(store_id: int, db: Session = Depends(get_db)):
    store = db.query(StoreModel).filter(StoreModel.id == store_id).first()
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")

    return {
        "store_url": store.store_url,
        "scans_performed": store.scans_performed,
        "webhook_health": "100%",
    }


@app.post("/api/v1/scan/execute-takedown")
def execute_automated_scan(data: ScanRequestSchema, db: Session = Depends(get_db)):
    store = db.query(StoreModel).filter(StoreModel.id == data.store_id).first()
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")

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
        try:
            notice_draft = create_dmca_notice_draft(
                host_abuse_email=data.host_abuse_email,
                target_infringing_url=str(data.target_infringing_url),
                original_asset_url=str(data.original_image_url),
                store_domain=store.store_url,
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

    return {
        "success": True,
        "similarity_match_percentage": round(similarity, 2),
        "takedown_notice_sent": False,
        "notice_draft": notice_draft,
        "notice_id": notice_id,
        "message": (
            "Potential match found. Review the DMCA notice draft before sending."
            if notice_draft
            else "Scan completed; no match met the 90% review threshold."
        ),
    }
