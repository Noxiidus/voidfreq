"""Tests for proxy module."""

from unittest.mock import MagicMock

import pytest

from voidfreq.modules.proxy import InterceptedRequest, ProxyCapture, ProxyModule


@pytest.fixture()
def proxy():
    config = MagicMock()
    opsec = MagicMock()
    return ProxyModule(config, opsec)


class TestProxyCapture:
    def test_empty_capture(self):
        c = ProxyCapture()
        assert c.requests == []
        assert c.credentials == []
        assert c.cookies == []
        assert c.tls_info == []


class TestInterceptedRequest:
    def test_defaults(self):
        r = InterceptedRequest(
            timestamp="2024-01-01T00:00:00",
            client_ip="192.168.1.100",
            method="GET",
            url="http://example.com",
            host="example.com",
        )
        assert r.content_type == ""
        assert r.status_code == 0
        assert r.has_credentials is False

    def test_with_credentials(self):
        r = InterceptedRequest(
            timestamp="2024-01-01T00:00:00",
            client_ip="192.168.1.100",
            method="POST",
            url="http://login.example.com",
            host="login.example.com",
            has_credentials=True,
        )
        assert r.has_credentials is True


class TestProxyExport:
    def test_export_creates_json(self, proxy, tmp_path):
        proxy.capture.requests.append(InterceptedRequest(
            timestamp="2024-01-01T00:00:00",
            client_ip="192.168.1.100",
            method="GET",
            url="http://example.com",
            host="example.com",
        ))

        path = proxy.export(output_dir=str(tmp_path))
        assert path.endswith(".json")

        import json
        with open(path) as f:
            data = json.load(f)
        assert data["stats"]["total_requests"] == 1
        assert data["stats"]["unique_hosts"] == 1
