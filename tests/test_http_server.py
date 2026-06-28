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
