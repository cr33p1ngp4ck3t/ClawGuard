"""Exercise wire decisions without replacing the gateway's transport function."""
import asyncio
from unittest.mock import patch

import httpx
import pytest

from proxy.client import forward_request


def fetch(handler, **kwargs):
    original_client = httpx.AsyncClient
    def make_client(**options):
        assert options.get("trust_env") is False
        def stream_response(request):
            response = handler(request)
            return httpx.Response(response.status_code, headers=response.headers, stream=httpx.ByteStream(response.content))
        return original_client(**options, transport=httpx.MockTransport(stream_response))
    with patch("proxy.client.httpx.AsyncClient", side_effect=make_client):
        return asyncio.run(forward_request(
            "https://example.com/data", addresses=("93.184.216.34",), **kwargs,
        ))


def test_approved_ip_is_used_with_original_host_and_tls_name():
    def upstream(request):
        assert request.url.host == "93.184.216.34"
        assert request.headers["host"] == "example.com"
        assert request.extensions["sni_hostname"] == "example.com"
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"weather report")
    assert fetch(upstream)[2] == "weather report"


def test_international_hostname_uses_same_ascii_name_for_host_and_tls():
    original_client = httpx.AsyncClient
    def upstream(request):
        assert request.headers["host"] == "xn--fa-hia.de"
        assert request.extensions["sni_hostname"] == "xn--fa-hia.de"
        return httpx.Response(200, headers={"content-type": "text/plain"}, stream=httpx.ByteStream(b"data"))
    with patch("proxy.client.httpx.AsyncClient", side_effect=lambda **options: original_client(
        **options, transport=httpx.MockTransport(upstream),
    )):
        result = asyncio.run(forward_request("https://xn--fa-hia.de/", addresses=("93.184.216.34",)))
    assert result[2] == "data"


@pytest.mark.parametrize("headers", [
    {"Host": "evil.test"}, {"Connection": "keep-alive"}, {"Accept-Encoding": "gzip"},
    {"X-Test": "value\r\nInjected: yes"}, {"Proxy-Authorization": "secret"},
])
def test_request_cannot_override_routing_or_framing(headers):
    with pytest.raises(ValueError):
        fetch(lambda request: pytest.fail("unsafe request reached upstream"), headers=headers)


@pytest.mark.parametrize("response", [
    httpx.Response(302, headers={"location": "https://evil.test/"}),
    httpx.Response(200, headers={"content-encoding": "gzip"}, content=b""),
    httpx.Response(200, headers={"content-type": "application/octet-stream"}, content=b"binary"),
    httpx.Response(200, headers={"content-type": "text/plain"}, content=b"\xff\xfe"),
    httpx.Response(200, headers={"content-type": "text/plain"}, content=b"a" * 1025),
])
def test_unsafe_response_is_never_returned(response):
    with pytest.raises(ValueError):
        fetch(lambda request: response, max_bytes=1024)


def test_missing_checked_address_cannot_connect():
    with pytest.raises(ValueError):
        asyncio.run(forward_request("https://example.com/", addresses=()))


def test_read_request_cannot_smuggle_a_body():
    with pytest.raises(ValueError):
        fetch(lambda request: pytest.fail("read body reached upstream"), body={"action": "delete"})


def test_slow_stream_has_total_deadline():
    class SlowStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"start"
            await asyncio.sleep(1)
            yield b"late"

    original_client = httpx.AsyncClient
    def make_client(**options):
        return original_client(**options, transport=httpx.MockTransport(lambda request: httpx.Response(
            200, headers={"content-type": "text/plain"}, stream=SlowStream(),
        )))
    with patch("proxy.client.httpx.AsyncClient", side_effect=make_client), pytest.raises(TimeoutError):
        asyncio.run(forward_request("https://example.com/", addresses=("93.184.216.34",), timeout=0.02))


def test_head_and_no_content_responses_need_no_content_type():
    assert fetch(lambda request: httpx.Response(200), method="HEAD") == (200, {}, "")
    assert fetch(lambda request: httpx.Response(204)) == (204, {}, "")
