"""Real TLS verifies that address pinning preserves certificate verification."""
import asyncio
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpcore
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from proxy.client import forward_request


@pytest.fixture
def certificate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


@pytest.mark.asyncio
async def test_real_tls_connects_to_checked_ip_and_verifies_original_hostname(certificate, monkeypatch, client):
    cert_path, key_path = certificate
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    names, requests, connections = [], [], []
    context.set_servername_callback(lambda sock, name, ctx: names.append(name))

    async def serve(reader, writer):
        try:
            requests.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 15\r\nConnection: close\r\n\r\nweather report\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    original_connect = httpcore.AnyIOBackend.connect_tcp
    original_ssl = ssl.create_default_context

    async def local_connect(self, host, port, **kwargs):
        connections.append(host)
        assert host == "93.184.216.34"
        return await original_connect(self, "127.0.0.1", port, **kwargs)

    def trust_test_ca(*args, **kwargs):
        return original_ssl(cafile=str(cert_path))

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", local_connect)
    async with server:
        with patch("ssl.create_default_context", side_effect=trust_test_ca):
            status, _, text = await forward_request(f"https://example.com:{port}/research", addresses=("93.184.216.34",))
            assert status == 200
            assert text == "weather report\n"
            import main
            monkeypatch.setitem(main.app_policy.allowed_origins, "test-agent", [f"https://example.com:{port}"])
            gateway = await client.post("/proxy", json={
                "target_url": f"https://example.com:{port}/research", "tool_name": "web_search",
            })
            assert gateway.status_code == 200
            assert gateway.json()["blocked"] is False
            assert gateway.json()["body"] == "weather report\n"
            with pytest.raises(httpx.ConnectError):
                await forward_request(f"https://wrong.example:{port}/", addresses=("93.184.216.34",))
        with pytest.raises(httpx.ConnectError):
            await forward_request(f"https://example.com:{port}/", addresses=("93.184.216.34",))
    assert connections == ["93.184.216.34"] * 4
    assert names[:3] == ["example.com", "example.com", "wrong.example"]
    assert len(requests) == 2
    assert f"Host: example.com:{port}".encode() in requests[0]
