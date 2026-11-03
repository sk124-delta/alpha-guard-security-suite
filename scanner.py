from io import BytesIO
import ipaddress
import os
import socket
from urllib.parse import urlsplit
import warnings

import imagehash
import requests
from PIL import Image
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import NewConnectionError
from urllib3.util import connection as urllib3_connection

MAX_IMAGE_BYTES = 10 * 1024 * 1024
REQUEST_TIMEOUT = (3, 10)
SERPAPI_ENDPOINT = "https://serpapi.com/search"
SERPAPI_TIMEOUT = (5, 30)


def _open_public_socket(conn):
    """Resolve once, require a global address, and connect to that exact IP.

    Connecting to the validated IP (not re-resolving the hostname) defeats DNS rebinding.
    TLS still verifies against the original hostname.
    """
    try:
        infos = socket.getaddrinfo(conn._dns_host, conn.port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise NewConnectionError(conn, f"Could not resolve host: {exc}") from exc
    if not infos or not all(ipaddress.ip_address(i[4][0]).is_global for i in infos):
        raise NewConnectionError(conn, "Host does not resolve to a public address.")
    return urllib3_connection.create_connection(
        (infos[0][4][0], conn.port),
        conn.timeout,
        source_address=conn.source_address,
        socket_options=conn.socket_options,
    )


class _PublicHTTPConnection(HTTPConnection):
    def _new_conn(self):
        return _open_public_socket(self)


class _PublicHTTPSConnection(HTTPSConnection):
    def _new_conn(self):
        return _open_public_socket(self)


class _PublicHTTPPool(HTTPConnectionPool):
    ConnectionCls = _PublicHTTPConnection


class _PublicHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _PublicHTTPSConnection


class _PublicOnlyAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": _PublicHTTPPool,
            "https": _PublicHTTPSPool,
        }


def public_only_session() -> requests.Session:
    """Session that can only connect to publicly routable IPs (SSRF-safe)."""
    session = requests.Session()
    session.trust_env = False
    adapter = _PublicOnlyAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _validate_public_url(image_url: str) -> None:
    parsed_url = urlsplit(image_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname:
        raise ValueError("Image URL must be an absolute HTTP or HTTPS URL.")
    if parsed_url.username or parsed_url.password:
        raise ValueError("Image URLs must not include embedded credentials.")

    try:
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        addresses = socket.getaddrinfo(parsed_url.hostname, port)
    except (OSError, ValueError) as exc:
        raise ValueError("Image URL host could not be resolved.") from exc

    if not addresses:
        raise ValueError("Image URL host did not resolve to an address.")

    for address in addresses:
        ip_address = ipaddress.ip_address(address[4][0])
        if not ip_address.is_global:
            raise ValueError("Image URL must resolve only to publicly routable addresses.")


def compute_image_hash(image_url: str) -> str:
    _validate_public_url(image_url)

    with public_only_session() as session:
        with session.get(
            image_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
        ) as response:
            if 300 <= response.status_code < 400:
                raise ValueError("Image URL redirects are not allowed.")
            response.raise_for_status()

            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    content_length_value = int(content_length)
                except ValueError as exc:
                    raise ValueError("Image response has an invalid Content-Length.") from exc
                if content_length_value > MAX_IMAGE_BYTES:
                    raise ValueError("Image exceeds the maximum allowed size.")

            image_data = bytearray()
            for chunk in response.iter_content(chunk_size=64 * 1024):
                image_data.extend(chunk)
                if len(image_data) > MAX_IMAGE_BYTES:
                    raise ValueError("Image exceeds the maximum allowed size.")

    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(BytesIO(image_data)) as image:
            image.load()
            return str(imagehash.phash(image))


def search_web_for_matches(image_url: str, api_key: str | None = None, max_results: int = 20) -> list[dict]:
    """Reverse-image search (SerpApi Google Lens) for copies of a public image URL.

    The key comes from the SERPAPI_KEY environment variable unless passed explicitly;
    never hardcode it. Returns [{"title", "url", "source"}], skipping entries without a link.
    Raises ValueError for bad input/config and RuntimeError for API or network failures.
    """
    _validate_public_url(image_url)
    key = api_key or os.environ.get("SERPAPI_KEY")
    if not key:
        raise ValueError("Set the SERPAPI_KEY environment variable (or pass api_key).")

    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.get(
                SERPAPI_ENDPOINT,
                params={"engine": "google_lens", "url": image_url, "api_key": key},
                timeout=SERPAPI_TIMEOUT,
            )
    except requests.RequestException as exc:
        # Do not echo the exception text: it can contain the request URL with the API key.
        raise RuntimeError(f"Reverse image search request failed ({type(exc).__name__}).") from None

    if response.status_code != 200:
        raise RuntimeError(f"Reverse image search failed with HTTP {response.status_code}.")
    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError("Reverse image search returned invalid JSON.") from exc
    if data.get("error"):
        raise RuntimeError(f"Reverse image search error: {data['error']}")

    matches = []
    for match in data.get("visual_matches") or []:
        link = match.get("link")
        if not link or urlsplit(link).scheme not in {"http", "https"}:
            continue
        matches.append({"title": match.get("title") or "", "url": link, "source": match.get("source") or ""})
        if len(matches) >= max_results:
            break
    return matches


def compare_hashes(hash1_str: str, hash2_str: str) -> float:
    try:
        hash1 = imagehash.hex_to_hash(hash1_str)
        hash2 = imagehash.hex_to_hash(hash2_str)
    except (TypeError, ValueError) as exc:
        raise ValueError("Image hashes must be valid hexadecimal perceptual hashes.") from exc

    if hash1.hash.size != hash2.hash.size:
        raise ValueError("Image hashes must have the same dimensions.")

    difference = hash1 - hash2
    return max(0.0, (1.0 - difference / hash1.hash.size) * 100.0)
