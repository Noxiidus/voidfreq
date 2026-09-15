"""Tests for captive portal — HTTP server, credential capture, export."""

from __future__ import annotations

import json
import time
import urllib.request

from voidfreq.modules.captive import CaptivePortal, CapturedCredential


class TestCapturedCredential:
    def test_defaults(self):
        cred = CapturedCredential(
            timestamp="2024-01-01 12:00:00",
            source_ip="192.168.1.10",
            username="admin",
            password="pass123",
        )
        assert cred.user_agent == ""
        assert cred.extra_fields == {}

    def test_full_fields(self):
        cred = CapturedCredential(
            timestamp="2024-01-01",
            source_ip="10.0.0.1",
            username="user",
            password="pw",
            user_agent="Mozilla/5.0",
            extra_fields={"email": "test@test.com"},
        )
        assert cred.user_agent == "Mozilla/5.0"
        assert cred.extra_fields["email"] == "test@test.com"


class TestCaptivePortal:
    def test_start_stop(self):
        portal = CaptivePortal(listen_ip="127.0.0.1", port=18923)
        portal.start()
        time.sleep(0.3)

        try:
            resp = urllib.request.urlopen("http://127.0.0.1:18923/")
            html = resp.read().decode()
            assert "<form" in html.lower() or "password" in html.lower() or len(html) > 0
        finally:
            creds = portal.stop()
            assert isinstance(creds, list)

    def test_credential_capture(self):
        portal = CaptivePortal(listen_ip="127.0.0.1", port=18924)
        portal.start()
        time.sleep(0.3)

        try:
            data = b"username=admin&password=letmein"
            req = urllib.request.Request(
                "http://127.0.0.1:18924/",
                data=data,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            urllib.request.urlopen(req)
            time.sleep(0.2)
        finally:
            creds = portal.stop()

        assert len(creds) == 1
        assert creds[0].username == "admin"
        assert creds[0].password == "letmein"
        assert creds[0].source_ip == "127.0.0.1"

    def test_export(self, tmp_path):
        portal = CaptivePortal(listen_ip="127.0.0.1", port=18925)
        portal.credentials.append(CapturedCredential(
            timestamp="2024-01-01 12:00:00",
            source_ip="10.0.0.1",
            username="test",
            password="pw",
        ))
        path = portal.export(output_dir=str(tmp_path))
        assert path.endswith(".json")
        with open(path) as f:
            data = json.loads(f.read())
        assert len(data) == 1
        assert data[0]["username"] == "test"
