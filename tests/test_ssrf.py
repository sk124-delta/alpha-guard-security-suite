import os
import sys
import tempfile
from contextlib import contextmanager

os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(tempfile.gettempdir(), "ag_test_ssrf.db").replace("\\", "/")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-for-pytest-0123456789")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

import main  # noqa: E402
import scanner  # noqa: E402

BLOCKED_HOSTS = [
    ("loopback v4", "127.0.0.1"),
    ("loopback v4 range", "127.1.2.3"),
    ("private 10/8", "10.0.0.5"),
    ("private 172.16/12", "172.16.4.4"),
    ("private 192.168/16", "192.168.1.1"),
    ("link-local", "169.254.1.1"),
    ("aws/gcp metadata", "169.254.169.254"),
    ("alibaba metadata", "100.100.100.200"),
    ("cgnat", "100.64.0.1"),
    ("unspecified", "0.0.0.0"),
    ("ipv6 loopback", "::1"),
    ("ipv6 link-local", "fe80::1"),
    ("ipv6 unique-local", "fd00::1"),
    ("aws ipv6 metadata", "fd00:ec2::254"),
    ("ipv4-mapped loopback", "::ffff:127.0.0.1"),
    ("ipv4-mapped metadata", "::ffff:169.254.169.254"),
]


def _bracket(host):
    return f"[{host}]" if ":" in host else host


@pytest.mark.parametrize("name,host", BLOCKED_HOSTS, ids=[b[0] for b in BLOCKED_HOSTS])
def test_ip_literals_are_blocked(name, host):
    with pytest.raises(ValueError):
        scanner._validate_public_url(f"http://{_bracket(host)}/")


@pytest.mark.parametrize("name,host", BLOCKED_HOSTS, ids=[b[0] for b in BLOCKED_HOSTS])
def test_hostnames_resolving_to_blocked_ranges_are_blocked(monkeypatch, name, host):
    import socket

    monkeypatch.setattr(scanner.socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, 0, 0, "", (host, 80))])
    with pytest.raises(ValueError):
        scanner._validate_public_url("http://rebind.example/")


def test_any_private_answer_blocks_even_with_public_answers(monkeypatch):
    import socket

    answers = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 80)), (socket.AF_INET, 0, 0, "", ("10.0.0.1", 80))]
    monkeypatch.setattr(scanner.socket, "getaddrinfo", lambda *a, **k: answers)
    with pytest.raises(ValueError):
        scanner._validate_public_url("http://mixed.example/")


@pytest.mark.parametrize("url", ["ftp://example.com/", "file:///etc/passwd", "gopher://example.com/", "javascript:alert(1)"])
def test_non_http_schemes_blocked(url):
    with pytest.raises(ValueError):
        scanner._validate_public_url(url)


def test_embedded_credentials_blocked():
    with pytest.raises(ValueError):
        scanner._validate_public_url("http://user:pass@example.com/")
    with pytest.raises(ValueError):
        main._normalize_inspection_url("https://user:pass@example.com")


@pytest.mark.parametrize("value", ["localhost", "http://localhost:8000", "127.0.0.1", "http://169.254.169.254/latest/meta-data", "http://[::1]/", "http://[fd00:ec2::254]/"])
def test_inspection_input_rejects_internal_targets(value):
    with pytest.raises(ValueError):
        main._normalize_inspection_url(value)


def test_inspection_input_rejects_non_http_scheme():
    with pytest.raises(ValueError):
        main._normalize_inspection_url("ftp://example.com")


class _FakeResponse:
    def __init__(self, status=200, headers=None, body=b"<html></html>"):
        self.status_code = status
        self.headers = headers or {}
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=1):
        yield self._body


class _FakeSession:
    def __init__(self, responses, calls):
        self._responses = responses
        self._calls = calls

    def get(self, url, **kwargs):
        assert kwargs["allow_redirects"] is False
        assert kwargs["timeout"] == main.DOMAIN_REQUEST_TIMEOUT
        self._calls.append(url)
        return self._responses[url]


@pytest.fixture()
def fake_web(monkeypatch):
    responses, calls = {}, []

    @contextmanager
    def session():
        yield _FakeSession(responses, calls)

    monkeypatch.setattr(main, "public_only_session", session)

    def validate(url):
        # Mirrors the real validator's decision for the hosts used in these tests.
        if "internal" in url or "169.254" in url:
            raise ValueError("Image URL must resolve only to publicly routable addresses.")

    monkeypatch.setattr(main, "_validate_public_url", validate)
    return responses, calls


def test_redirect_to_internal_address_is_blocked(fake_web):
    responses, calls = fake_web
    responses["https://a.example/"] = _FakeResponse(302, {"Location": "http://169.254.169.254/latest/meta-data"})
    with pytest.raises(ValueError):
        main._fetch_public_page("https://a.example/")
    assert calls == ["https://a.example/"]


def test_redirect_to_internal_hostname_is_blocked(fake_web):
    responses, calls = fake_web
    responses["https://a.example/"] = _FakeResponse(301, {"Location": "https://internal.example/admin"})
    with pytest.raises(ValueError):
        main._fetch_public_page("https://a.example/")
    assert calls == ["https://a.example/"]


def test_safe_redirect_is_followed_and_relative_location_resolved(fake_web):
    responses, calls = fake_web
    responses["https://a.example/"] = _FakeResponse(302, {"Location": "/next"})
    responses["https://a.example/next"] = _FakeResponse(200, {"Content-Type": "text/html"}, b"ok")
    body, content_type = main._fetch_public_page("https://a.example/")
    assert body == b"ok" and content_type == "text/html"
    assert calls == ["https://a.example/", "https://a.example/next"]


def test_redirect_limit_is_enforced(fake_web):
    responses, calls = fake_web
    for i in range(10):
        responses[f"https://a.example/{i}"] = _FakeResponse(302, {"Location": f"/{i + 1}"})
    responses["https://a.example/"] = _FakeResponse(302, {"Location": "/1"})
    with pytest.raises(ValueError, match="too many"):
        main._fetch_public_page("https://a.example/")
    assert len(calls) == main.MAX_DOMAIN_REDIRECTS + 1


def test_exactly_max_redirects_is_allowed(fake_web):
    responses, calls = fake_web
    responses["https://a.example/"] = _FakeResponse(302, {"Location": "/1"})
    responses["https://a.example/1"] = _FakeResponse(302, {"Location": "/2"})
    responses["https://a.example/2"] = _FakeResponse(302, {"Location": "/3"})
    responses["https://a.example/3"] = _FakeResponse(200, {"Content-Type": "text/html"}, b"done")
    assert main._fetch_public_page("https://a.example/")[0] == b"done"


def test_response_size_cap_by_header_and_by_stream(fake_web):
    responses, _ = fake_web
    big = str(main.MAX_DOMAIN_PAGE_BYTES + 1)
    responses["https://a.example/"] = _FakeResponse(200, {"Content-Length": big})
    with pytest.raises(ValueError, match="size limit"):
        main._fetch_public_page("https://a.example/")
    responses["https://b.example/"] = _FakeResponse(200, {}, b"x" * (main.MAX_DOMAIN_PAGE_BYTES + 1))
    with pytest.raises(ValueError, match="size limit"):
        main._fetch_public_page("https://b.example/")


def test_timeout_is_configured():
    assert main.DOMAIN_REQUEST_TIMEOUT == (3, 7)
