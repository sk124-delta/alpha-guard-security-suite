"""AlphaGuard image protection pipeline.

Batch-processes e-commerce product images:
  1. sanitize_prnu_noise            - suppress camera sensor noise (PRNU) and strip metadata
  2. embed_steganographic_watermark - embed an invisible DCT-domain signature
  3. process_store_catalog          - download -> sanitize -> watermark -> record

Dependencies: numpy, opencv-python-headless, Pillow, requests.

Robustness notes (be realistic about what a watermark can do):
  * The watermark lives in mid-frequency 8x8 block-DCT coefficients of the luma channel,
    so it survives moderate JPEG/WebP re-compression (quality >= ~60) and mild noise.
  * It is block-grid based: cropping or resizing breaks the grid alignment. Mild
    rescaling may be recoverable via verify_watermark(..., try_sizes=[(w, h)]), but
    heavy downscaling (e.g. 50%) is NOT survived in testing.
  * PRNU suppression is best-effort denoising; it reduces, not provably removes, the
    sensor fingerprint.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import logging
import os
import shutil
import socket
import tempfile
import warnings
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import cv2
import imagehash
import numpy as np
import requests
from PIL import Image, ImageOps

logger = logging.getLogger("alphaguard.watermarker")

DEFAULT_PAYLOAD_ID = "AlphaGuard-ID-3.4"

# --- Limits ------------------------------------------------------------------
MAX_IMAGE_PIXELS = 50_000_000          # decompression-bomb ceiling (~50 MP)
MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024  # 20 MB per image
MAX_REDIRECTS = 3
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 15
USER_AGENT = "AlphaGuardCatalogBot/1.0"

# Pillow raises DecompressionBombError at 2x this value and warns at 1x; we turn the
# warning into an error too so the limit is strict.
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
warnings.simplefilter("error", Image.DecompressionBombWarning)

# --- Watermark parameters ------------------------------------------------------
WM_BITS = 64            # bits of the payload signature that are embedded
WM_STRENGTH = 18.0      # min DCT coefficient gap (orthonormal DCT scale)
WM_KEY_SEED = 0xA1FA6A  # fixed seed -> deterministic bit-to-block mapping
WM_MIN_BLOCKS_PER_BIT = 8
WM_MATCH_THRESHOLD = 0.85


class ImageProcessingError(Exception):
    """Raised for corrupted, oversized or otherwise unprocessable images."""


class DownloadError(Exception):
    """Raised for network failures or unsafe/invalid download targets."""


# --- Low-level helpers ---------------------------------------------------------

def _load_rgb(image_path: str) -> np.ndarray:
    """Load an image as an RGB uint8 array, applying EXIF orientation.

    Raises ImageProcessingError for corrupt files and decompression bombs.
    """
    try:
        with Image.open(image_path) as img:
            width, height = img.size
            if width * height > MAX_IMAGE_PIXELS:
                raise ImageProcessingError(
                    f"Image too large ({width}x{height} px, limit {MAX_IMAGE_PIXELS} px)"
                )
            img.load()  # force full decode so truncated files fail here
            img = ImageOps.exif_transpose(img)
            if img.mode in ("RGBA", "LA", "P"):
                rgba = img.convert("RGBA")
                background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
                img = Image.alpha_composite(background, rgba)
            return np.asarray(img.convert("RGB"), dtype=np.uint8).copy()
    except ImageProcessingError:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise ImageProcessingError(f"Decompression bomb rejected: {exc}") from exc
    except FileNotFoundError as exc:
        raise ImageProcessingError(f"Image not found: {image_path}") from exc
    except (OSError, ValueError, SyntaxError, Image.UnidentifiedImageError) as exc:
        raise ImageProcessingError(f"Corrupted or unsupported image '{image_path}': {exc}") from exc


def _save_rgb(rgb: np.ndarray, output_path: str) -> None:
    """Save an RGB array. Fresh Image object => EXIF/ICC/metadata are not carried over.

    PNG is lossless (best for the watermark); JPEG/WebP use high quality.
    """
    out_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(out_dir, exist_ok=True)
    ext = os.path.splitext(output_path)[1].lower()
    img = Image.fromarray(rgb, "RGB")
    try:
        if ext in (".jpg", ".jpeg"):
            img.save(output_path, "JPEG", quality=95, subsampling=0, optimize=True)
        elif ext == ".webp":
            img.save(output_path, "WEBP", quality=95)
        else:
            img.save(output_path, "PNG", optimize=True)
    except (OSError, ValueError) as exc:
        raise ImageProcessingError(f"Could not save '{output_path}': {exc}") from exc


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _phash(rgb: np.ndarray) -> str:
    """DCT-based perceptual hash (pHash, hex) for catalog matching and tracking."""
    return str(imagehash.phash(Image.fromarray(rgb, "RGB")))


def _dhash(rgb: np.ndarray, hash_size: int = 8) -> str:
    """64-bit perceptual difference hash (hex). Similar-looking images give close hashes."""
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    small = cv2.resize(gray, (hash_size + 1, hash_size), interpolation=cv2.INTER_AREA)
    bits = (small[:, 1:] > small[:, :-1]).flatten()
    value = 0
    for bit in bits:
        value = (value << 1) | int(bit)
    return f"{value:0{hash_size * hash_size // 4}x}"


# --- 1. PRNU / sensor-noise suppression ------------------------------------------

def _sanitize_array(rgb: np.ndarray) -> np.ndarray:
    """Edge-preserving denoise tuned to remove high-frequency sensor noise.

    Two passes: a bilateral filter (smooths flat regions, keeps edges) followed by a
    light non-local-means pass on the luma channel for residual fine-grain noise.
    """
    smoothed = cv2.bilateralFilter(rgb, d=7, sigmaColor=30, sigmaSpace=5)

    ycrcb = cv2.cvtColor(smoothed, cv2.COLOR_RGB2YCrCb)
    # NLM is expensive; skip it on very large images and rely on the bilateral pass.
    if ycrcb.shape[0] * ycrcb.shape[1] <= 12_000_000:
        ycrcb[:, :, 0] = cv2.fastNlMeansDenoising(
            ycrcb[:, :, 0], None, h=4, templateWindowSize=5, searchWindowSize=15
        )
    return cv2.cvtColor(ycrcb, cv2.COLOR_YCrCb2RGB)


def sanitize_prnu_noise(image_path: str, output_path: str) -> None:
    """Suppress PRNU camera-sensor noise while keeping edges crisp, and strip metadata.

    Raises ImageProcessingError on corrupted/oversized input.
    """
    rgb = _load_rgb(image_path)
    try:
        cleaned = _sanitize_array(rgb)
    except cv2.error as exc:
        raise ImageProcessingError(f"Denoising failed for '{image_path}': {exc}") from exc
    _save_rgb(cleaned, output_path)


# --- 2. Frequency-domain watermark -------------------------------------------------

def _dct_matrix(n: int = 8) -> np.ndarray:
    """Orthonormal DCT-II basis matrix."""
    k = np.arange(n)[:, None]
    i = np.arange(n)[None, :]
    mat = np.cos((2 * i + 1) * k * np.pi / (2 * n)) * np.sqrt(2.0 / n)
    mat[0, :] = np.sqrt(1.0 / n)
    return mat.astype(np.float32)


_D = _dct_matrix()

# Mid-frequency coefficient pair; their difference carries the bit.
_COEF_A = (3, 2)
_COEF_B = (2, 3)


def _payload_bits(payload_id: str) -> np.ndarray:
    """Derive a fixed-size bit signature from the payload string (SHA-256 prefix)."""
    digest = hashlib.sha256(payload_id.encode("utf-8")).digest()[: WM_BITS // 8]
    return np.unpackbits(np.frombuffer(digest, dtype=np.uint8)).astype(np.int8)


def _to_blocks(channel: np.ndarray):
    """Split the channel into 8x8 blocks -> array (bh, bw, 8, 8); also return cropped dims."""
    h, w = channel.shape
    bh, bw = h // 8, w // 8
    cropped = channel[: bh * 8, : bw * 8]
    blocks = cropped.reshape(bh, 8, bw, 8).transpose(0, 2, 1, 3)
    return blocks, bh, bw


def _from_blocks(blocks: np.ndarray) -> np.ndarray:
    bh, bw = blocks.shape[:2]
    return blocks.transpose(0, 2, 1, 3).reshape(bh * 8, bw * 8)


def _bit_map(n_blocks: int) -> np.ndarray:
    """Deterministic, key-seeded assignment of each block to a payload bit index."""
    rng = np.random.default_rng(WM_KEY_SEED)
    return rng.integers(0, WM_BITS, size=n_blocks)


def _embed_array(rgb: np.ndarray, payload_id: str, strength: float = WM_STRENGTH) -> np.ndarray:
    h, w = rgb.shape[:2]
    n_blocks = (h // 8) * (w // 8)
    if n_blocks < WM_BITS * WM_MIN_BLOCKS_PER_BIT:
        raise ImageProcessingError(
            f"Image {w}x{h} too small to carry a robust watermark "
            f"(need >= {WM_BITS * WM_MIN_BLOCKS_PER_BIT} 8x8 blocks)"
        )

    ycrcb = cv2.cvtColor(rgb, cv2.COLOR_RGB2YCrCb)
    luma = ycrcb[:, :, 0].astype(np.float32)

    blocks, bh, bw = _to_blocks(luma)
    coefs = np.matmul(np.matmul(_D, blocks), _D.T)  # forward 2-D DCT per block

    bits = _payload_bits(payload_id)
    block_bits = bits[_bit_map(bh * bw)].reshape(bh, bw)
    sign = np.where(block_bits == 1, 1.0, -1.0).astype(np.float32)

    a = coefs[:, :, _COEF_A[0], _COEF_A[1]]
    b = coefs[:, :, _COEF_B[0], _COEF_B[1]]
    # Force sign(a - b) to encode the bit with a margin of at least `strength`.
    shortfall = np.maximum(0.0, strength - sign * (a - b))
    shift = sign * shortfall / 2.0
    coefs[:, :, _COEF_A[0], _COEF_A[1]] = a + shift
    coefs[:, :, _COEF_B[0], _COEF_B[1]] = b - shift

    marked = np.matmul(np.matmul(_D.T, coefs), _D)  # inverse DCT
    luma_out = luma.copy()
    luma_out[: bh * 8, : bw * 8] = _from_blocks(marked)

    ycrcb[:, :, 0] = np.clip(np.rint(luma_out), 0, 255).astype(np.uint8)
    return cv2.cvtColor(ycrcb, cv2.COLOR_YCrCb2RGB)


def embed_steganographic_watermark(
    image_path: str, output_path: str, payload_id: str = DEFAULT_PAYLOAD_ID
) -> None:
    """Embed an invisible block-DCT watermark derived from `payload_id`.

    Save as PNG to keep it intact; JPEG/WebP outputs at quality 95 also retain it.
    Raises ImageProcessingError for corrupted/oversized/too-small images.
    """
    if not payload_id:
        raise ValueError("payload_id must be a non-empty string")
    rgb = _load_rgb(image_path)
    try:
        marked = _embed_array(rgb, payload_id)
    except cv2.error as exc:
        raise ImageProcessingError(f"Watermarking failed for '{image_path}': {exc}") from exc
    _save_rgb(marked, output_path)


def _extract_match(rgb: np.ndarray, payload_id: str) -> float:
    """Fraction (0..1) of payload bits recovered; ~0.5 means no watermark."""
    h, w = rgb.shape[:2]
    if (h // 8) * (w // 8) < WM_BITS * WM_MIN_BLOCKS_PER_BIT:
        return 0.0
    luma = cv2.cvtColor(rgb, cv2.COLOR_RGB2YCrCb)[:, :, 0].astype(np.float32)
    blocks, bh, bw = _to_blocks(luma)
    coefs = np.matmul(np.matmul(_D, blocks), _D.T)
    diff = (coefs[:, :, _COEF_A[0], _COEF_A[1]] - coefs[:, :, _COEF_B[0], _COEF_B[1]]).ravel()

    votes = np.bincount(_bit_map(bh * bw), weights=diff, minlength=WM_BITS)
    recovered = (votes > 0).astype(np.int8)
    return float(np.mean(recovered == _payload_bits(payload_id)))


def verify_watermark(
    image_path: str,
    payload_id: str = DEFAULT_PAYLOAD_ID,
    try_sizes: list[tuple[int, int]] | None = None,
) -> bool:
    """Check whether an image carries the watermark for `payload_id`.

    `try_sizes` lists (width, height) originals to rescale a suspect (resized) image
    back to before checking.
    """
    rgb = _load_rgb(image_path)
    candidates = [rgb]
    for width, height in try_sizes or []:
        if width > 0 and height > 0 and width * height <= MAX_IMAGE_PIXELS:
            candidates.append(cv2.resize(rgb, (width, height), interpolation=cv2.INTER_CUBIC))
    return any(_extract_match(c, payload_id) >= WM_MATCH_THRESHOLD for c in candidates)


# --- 3. Catalog processing ----------------------------------------------------------

def _is_public_host(hostname: str) -> bool:
    """Reject hosts resolving to private/loopback/link-local addresses (SSRF guard)."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return False
    return bool(infos)


def _download_image(url: str, dest_path: str) -> None:
    """Stream `url` to `dest_path` with scheme/host checks, size cap and timeouts.

    Redirects are followed manually so each hop is re-validated.
    """
    session = requests.Session()
    headers = {"User-Agent": USER_AGENT, "Accept": "image/*"}
    current = url
    try:
        for _ in range(MAX_REDIRECTS + 1):
            parsed = urlparse(current)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise DownloadError(f"Unsupported or invalid URL: {current}")
            if not _is_public_host(parsed.hostname):
                raise DownloadError(f"Refusing non-public host: {parsed.hostname}")

            try:
                resp = session.get(
                    current,
                    headers=headers,
                    stream=True,
                    timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                    allow_redirects=False,
                )
            except requests.Timeout as exc:
                raise DownloadError(f"Timed out fetching {current}") from exc
            except requests.RequestException as exc:
                raise DownloadError(f"Network error fetching {current}: {exc}") from exc

            with resp:
                if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        raise DownloadError(f"Redirect without Location from {current}")
                    current = urljoin(current, location)
                    continue
                if resp.status_code != 200:
                    raise DownloadError(f"HTTP {resp.status_code} for {current}")

                ctype = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
                if ctype and not ctype.startswith("image/"):
                    raise DownloadError(f"Unexpected content type '{ctype}' for {current}")
                declared = resp.headers.get("Content-Length")
                if declared and declared.isdigit() and int(declared) > MAX_DOWNLOAD_BYTES:
                    raise DownloadError(f"Image exceeds {MAX_DOWNLOAD_BYTES} bytes: {current}")

                total = 0
                try:
                    with open(dest_path, "wb") as fh:
                        for chunk in resp.iter_content(chunk_size=64 * 1024):
                            total += len(chunk)
                            if total > MAX_DOWNLOAD_BYTES:
                                raise DownloadError(
                                    f"Image exceeds {MAX_DOWNLOAD_BYTES} bytes: {current}"
                                )
                            fh.write(chunk)
                except requests.RequestException as exc:
                    raise DownloadError(f"Download interrupted for {current}: {exc}") from exc
                if total == 0:
                    raise DownloadError(f"Empty response from {current}")
                return
        raise DownloadError(f"Too many redirects for {url}")
    finally:
        session.close()


def process_store_catalog(
    image_urls: list[str],
    output_dir: str,
    payload_id: str = DEFAULT_PAYLOAD_ID,
) -> list[dict]:
    """Download, sanitize and watermark each catalog image.

    Returns one record per URL (input order). Successful records have status "ok" and the
    new hashes/metadata; failures have status "error" with an `error` message, so one bad
    image never aborts the batch. Output files are PNGs named by the URL hash.
    """
    os.makedirs(output_dir, exist_ok=True)
    records: list[dict] = []

    for url in image_urls:
        record: dict = {"source_url": url, "status": "error", "error": None}
        work_dir = tempfile.mkdtemp(prefix="agwm_")
        try:
            raw_path = os.path.join(work_dir, "download.bin")
            clean_path = os.path.join(work_dir, "clean.png")
            name = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16] + ".png"
            final_path = os.path.join(output_dir, name)

            _download_image(url, raw_path)
            original_sha = _sha256_file(raw_path)

            sanitize_prnu_noise(raw_path, clean_path)
            embed_steganographic_watermark(clean_path, final_path, payload_id)

            final_rgb = _load_rgb(final_path)
            record.update(
                {
                    "status": "ok",
                    "error": None,
                    "local_path": final_path,
                    "original_sha256": original_sha,
                    "processed_sha256": _sha256_file(final_path),
                    "perceptual_hash": _phash(final_rgb),
                    "dhash": _dhash(final_rgb),
                    "width": int(final_rgb.shape[1]),
                    "height": int(final_rgb.shape[0]),
                    "size_bytes": os.path.getsize(final_path),
                    "payload_id": payload_id,
                    "processed_at": datetime.now(timezone.utc).isoformat(),
                }
            )
        except (DownloadError, ImageProcessingError) as exc:
            logger.warning("Skipping %s: %s", url, exc)
            record["error"] = str(exc)
        except Exception as exc:  # keep the batch alive on unexpected failures
            logger.exception("Unexpected failure processing %s", url)
            record["error"] = f"Unexpected error: {exc}"
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)
        records.append(record)

    return records


if __name__ == "__main__":
    import json
    import sys

    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 3:
        print("Usage: python watermarker.py <output_dir> <image_url> [<image_url> ...]")
        sys.exit(1)
    print(json.dumps(process_store_catalog(sys.argv[2:], sys.argv[1]), indent=2))
