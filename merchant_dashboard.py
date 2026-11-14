"""AlphaGuard dashboard (Streamlit).

Admins see DMCA notices and per-store scan counts; merchants can register a store
and protect product images. Set ALPHAGUARD_API_URL to point at a deployed API.

Run: streamlit run merchant_dashboard.py
"""

import os

import pandas as pd
import requests
import streamlit as st

API_URL = os.getenv("ALPHAGUARD_API_URL", "http://127.0.0.1:8000").rstrip("/")
DEFAULT_TIMEOUT = (3, 15)
UPLOAD_TIMEOUT = (3, 120)
NOTICE_COLUMNS = [
    "notice_id",
    "created_at",
    "target_infringing_url",
    "similarity_score",
    "status",
    "recipient",
]

st.set_page_config(page_title="AlphaGuard Dashboard", page_icon="🛡️", layout="wide")


def api_request(method: str, path: str, **kwargs) -> requests.Response:
    """Call the API with the session token.

    A timeout passed by the caller overrides the default instead of conflicting with it.
    """
    headers = dict(kwargs.pop("headers", None) or {})
    token = st.session_state.get("token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    return requests.request(method, f"{API_URL}{path}", headers=headers, **kwargs)


def clear_session() -> None:
    st.session_state.pop("token", None)
    st.session_state.pop("role", None)
    st.session_state.pop("protected", None)


def json_or_none(response: requests.Response):
    try:
        return response.json()
    except ValueError:
        return None


def expire_if_unauthorized(response: requests.Response) -> None:
    if response.status_code == 401:
        clear_session()
        st.warning("Your session expired. Please sign in again.")
        st.rerun()


def sign_in(email: str, password: str) -> str | None:
    """Return an error message, or None on success."""
    try:
        response = api_request(
            "POST", "/api/v1/auth/token", json={"email": email, "password": password}
        )
    except requests.RequestException:
        return f"Could not reach the API at {API_URL}."
    body = json_or_none(response)
    if not isinstance(body, dict):
        return f"Unexpected response from the API (HTTP {response.status_code})."
    if response.status_code != 200:
        detail = body.get("detail")
        return detail if isinstance(detail, str) else "Sign-in failed."
    if not body.get("access_token"):
        return "Sign-in failed."
    st.session_state["token"] = body["access_token"]
    st.session_state["role"] = body.get("role", "customer")
    return None


def register_store(email: str, password: str, store_name: str, store_url: str) -> str | None:
    """Return an error message, or None on success."""
    try:
        response = api_request(
            "POST",
            "/api/v1/auth/signup",
            json={
                "email": email,
                "password": password,
                "store_name": store_name,
                "store_url": store_url,
            },
        )
    except requests.RequestException:
        return f"Could not reach the API at {API_URL}."
    if response.status_code == 200:
        return None
    body = json_or_none(response)
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, list):
        return "Please check your details: " + "; ".join(
            str(item.get("msg", "invalid value")) if isinstance(item, dict) else "invalid value"
            for item in detail
        )
    return detail if isinstance(detail, str) else f"Registration failed (HTTP {response.status_code})."


def load_notices() -> list[dict] | None:
    try:
        response = api_request("GET", "/api/v1/admin/notices")
    except requests.RequestException:
        st.error(f"Could not reach the API at {API_URL}.")
        return None
    expire_if_unauthorized(response)
    if response.status_code != 200:
        st.error(f"Could not load notices (HTTP {response.status_code}).")
        return None
    notices = json_or_none(response)
    if not isinstance(notices, list):
        st.error("The API returned an unexpected response.")
        return None
    return notices


def notices_to_frame(notices: list[dict]) -> pd.DataFrame:
    """Build a notice table with every expected column present, even when empty."""
    frame = pd.DataFrame(notices)
    for column in NOTICE_COLUMNS:
        if column not in frame:
            frame[column] = None
    frame["status"] = frame["status"].fillna("UNKNOWN").astype(str)
    if not frame.empty:
        frame["created_at"] = pd.to_datetime(frame["created_at"], errors="coerce")
    return frame


if "token" not in st.session_state:
    st.title("🛡️ AlphaGuard Security Suite - Portal")
    auth_mode = st.radio("Choose Action", ["Log In", "Register Store"], horizontal=True)
    if auth_mode == "Log In":
        with st.form("login"):
            email = st.text_input("Email address")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in")
        if submitted:
            error = sign_in(email.strip(), password)
            if error:
                st.error(error)
            else:
                st.rerun()
    else:
        with st.form("register"):
            st.subheader("Register Your E-Commerce Brand")
            reg_email = st.text_input("Work email")
            reg_password = st.text_input("Choose password (min. 8 characters)", type="password")
            store_name = st.text_input("Store name")
            store_url = st.text_input("Store website URL (e.g. https://example.com)")
            registered = st.form_submit_button("Create Account & Activate Protection")
        if registered:
            error = register_store(
                reg_email.strip(), reg_password, store_name.strip(), store_url.strip()
            )
            if error:
                st.error(error)
            else:
                st.success("Account created successfully! Switch to Log In to continue.")
    st.stop()

is_admin = st.session_state.get("role") == "admin"

st.title("🛡️ AlphaGuard Dashboard")
st.sidebar.header("Navigation")
pages = (
    ["Overview", "Notice Log", "Store Metrics", "Protect Assets"]
    if is_admin
    else ["Protect Assets"]
)
page = st.sidebar.radio("Select View", pages)
if st.sidebar.button("Refresh"):
    st.rerun()
if st.sidebar.button("Sign out"):
    clear_session()
    st.rerun()

if page == "Protect Assets":
    st.subheader("📤 Secure Catalog Asset Upload & Watermarking")
    st.markdown(
        "Upload a product image. The API embeds an invisible watermark and "
        "computes a perceptual hash; download the protected PNG afterwards."
    )
    uploaded_file = st.file_uploader("Upload Product Image", type=["jpg", "jpeg", "png"])
    if uploaded_file is not None:
        st.image(uploaded_file, caption="Preview: Selected Product Asset", width=300)
        if st.button("Protect Asset"):
            st.session_state.pop("protected", None)
            with st.spinner("Applying watermark and generating fingerprint..."):
                try:
                    response = api_request(
                        "POST",
                        "/api/v1/protection/process-image",
                        files={
                            "image_file": (
                                uploaded_file.name,
                                uploaded_file.getvalue(),
                                uploaded_file.type,
                            )
                        },
                        timeout=UPLOAD_TIMEOUT,
                    )
                except requests.RequestException:
                    st.error(f"Could not reach the API at {API_URL}.")
                else:
                    expire_if_unauthorized(response)
                    if response.status_code == 200:
                        st.session_state["protected"] = {
                            "source": uploaded_file.name,
                            "image": response.content,
                            "perceptual_hash": response.headers.get("X-AlphaGuard-Perceptual-Hash"),
                            "payload_id": response.headers.get("X-AlphaGuard-Payload-Id"),
                        }
                    else:
                        body = json_or_none(response)
                        detail = body.get("detail") if isinstance(body, dict) else None
                        st.error(
                            detail
                            if isinstance(detail, str)
                            else f"Protection failed (HTTP {response.status_code})."
                        )
    # Kept in session state so the download button's rerun does not discard the result.
    protected = st.session_state.get("protected")
    if protected and uploaded_file is not None and protected["source"] == uploaded_file.name:
        st.success("Asset protected.")
        st.json(
            {
                "perceptual_hash": protected["perceptual_hash"],
                "payload_id": protected["payload_id"],
            }
        )
        st.download_button(
            "Download protected image",
            protected["image"],
            file_name="alphaguard-watermarked.png",
            mime="image/png",
        )
    st.stop()

if page == "Store Metrics":
    st.subheader("Store scan activity")
    store_id = st.number_input("Store ID", min_value=1, step=1, value=1)
    try:
        response = api_request("GET", f"/api/v1/metrics/{int(store_id)}")
    except requests.RequestException:
        st.error(f"Could not reach the API at {API_URL}.")
    else:
        expire_if_unauthorized(response)
        data = json_or_none(response)
        if response.status_code == 200 and isinstance(data, dict):
            st.metric("Store", data.get("store_url", "-"))
            st.metric("Scans performed", data.get("scans_performed", 0))
        elif response.status_code == 404:
            st.info("No store found with that ID.")
        else:
            st.error(f"Could not load metrics (HTTP {response.status_code}).")
    st.stop()

notices = load_notices()
if notices is None:
    st.stop()

frame = notices_to_frame(notices)

if page == "Overview":
    st.subheader("Notice overview")
    if frame.empty:
        st.info("No notices yet. Notices appear here after a scan finds a match of 90% or higher.")
    else:
        counts = frame["status"].value_counts()
        columns = st.columns(4)
        columns[0].metric("Total notices", len(frame))
        columns[1].metric("Pending review", int(counts.get("PENDING", 0)))
        columns[2].metric("Dispatched", int(counts.get("DISPATCHED", 0)))
        columns[3].metric(
            "Failed or unknown",
            int(counts.get("DISPATCH_FAILED", 0) + counts.get("DISPATCH_UNKNOWN", 0)),
        )
        st.caption("Showing the 100 most recent notices.")
        st.divider()
        st.subheader("Notices created per day")
        per_day = frame.dropna(subset=["created_at"]).groupby(
            frame["created_at"].dt.date
        ).size().rename("Notices")
        st.bar_chart(per_day)
        st.subheader("Notices by status")
        st.bar_chart(counts)

elif page == "Notice Log":
    st.subheader("DMCA notice log")
    if frame.empty:
        st.info("No notices yet.")
    else:
        statuses = sorted(frame["status"].unique())
        chosen = st.multiselect("Status", statuses, default=statuses)
        view = frame[frame["status"].isin(chosen)][NOTICE_COLUMNS].rename(
            columns={
                "notice_id": "Notice ID",
                "created_at": "Created",
                "target_infringing_url": "Infringing URL",
                "similarity_score": "Match %",
                "status": "Status",
                "recipient": "Recipient",
            }
        )
        st.dataframe(view, width="stretch", hide_index=True)
        st.caption(
            "Notices are dispatched from the admin API after review "
            "(or automatically when AUTO_DISPATCH_DMCA is enabled)."
        )