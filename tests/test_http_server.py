import asyncio
from types import SimpleNamespace

from baitbox.ratelimit import block_ip, unblock_ip
from baitbox.servers.http_server import honeypot


class FakeRequest:
    method = "GET"
    headers = {"x-forwarded-for": "203.0.113.42"}
    client = SimpleNamespace(host="198.51.100.99")
    url = SimpleNamespace(path="/wp-admin", query="")

    async def body(self):
        return b""


def test_blocked_ip_is_rejected_before_honeypot_response():
    ip = "203.0.113.42"
    block_ip(ip)
    try:
        response = asyncio.run(honeypot(FakeRequest(), "wp-admin"))
    finally:
        unblock_ip(ip)

    assert response.status_code == 403
    assert response.body == b'{"status":"blocked"}'


def test_payload_is_truncated_before_logging(monkeypatch):
    from baitbox.servers import http_server

    class LargeBodyRequest(FakeRequest):
        method = "POST"
        headers = {"content-type": "text/plain"}
        url = SimpleNamespace(path="/upload", query="")

        async def body(self):
            return b"x" * 20

    monkeypatch.setattr(http_server, "settings", SimpleNamespace(http_max_body_bytes=8))
    payload = asyncio.run(http_server._request_payload(LargeBodyRequest()))

    assert payload["body_truncated"] is True
    assert payload["body"] == {"raw_body": "xxxxxxxx"}


def test_ip_validation_normalizes_ipv4_and_rejects_bad_values():
    from baitbox.servers.http_server import _validate_ip

    assert _validate_ip("203.0.113.42") == "203.0.113.42"

    try:
        _validate_ip("not-an-ip")
    except ValueError as exc:
        assert "Invalid IP address" in str(exc)
    else:
        raise AssertionError("invalid IP was accepted")
