from io import BytesIO
import ipaddress
import socket
from urllib.parse import urlsplit
import warnings

import imagehash
import requests
from PIL import Image

MAX_IMAGE_BYTES = 10 * 1024 * 1024
REQUEST_TIMEOUT = (3, 10)


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

    with requests.Session() as session:
        session.trust_env = False
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
