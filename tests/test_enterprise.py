"""Tests for 802.1X Enterprise WiFi module."""

from unittest.mock import MagicMock, patch

from voidfreq.core.config import Config, StealthProfile
from voidfreq.core.opsec import OpsecEngine
from voidfreq.modules.enterprise import EapInfo, EnterpriseModule, EnterpriseResult


def _make_module():
    config = Config(
        interface="wlan0",
        stealth=StealthProfile(),
        stealth_level="high",
        raw={},
    )
    opsec = MagicMock(spec=OpsecEngine)
    return EnterpriseModule(config, opsec)


class TestEapInfo:
    def test_defaults(self):
        info = EapInfo(bssid="AA:BB:CC:DD:EE:FF")
        assert info.eap_types == []
        assert info.inner_auth == []
        assert info.cert_cn == ""

    def test_result_defaults(self):
        r = EnterpriseResult(success=False, attack_type="test")
        assert r.credentials == []
        assert r.capture_file is None


class TestEapUserFile:
    def test_peap_user_file(self):
        mod = _make_module()
        content = mod._generate_eap_user_file("PEAP")
        assert "PEAP" in content
        assert "MSCHAPV2" in content

    def test_gtc_user_file(self):
        mod = _make_module()
        content = mod._generate_eap_user_file("GTC")
        assert "GTC" in content

    def test_ttls_user_file(self):
        mod = _make_module()
        content = mod._generate_eap_user_file("EAP-TTLS")
        assert "TTLS" in content


class TestWpeLogParsing:
    def test_parse_mschapv2_creds(self):
        mod = _make_module()
        import os
        import tempfile

        log_content = """
hostapd-wpe started
username: john.doe
challenge: aa:bb:cc:dd:ee:ff:00:11
response: 11:22:33:44:55:66:77:88
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(log_content)
            f.flush()
        try:
            creds = mod._parse_wpe_log(f.name)
            assert len(creds) == 1
            assert creds[0]["username"] == "john.doe"
            assert creds[0]["type"] == "MS-CHAPv2"
            assert "challenge" in creds[0]
            assert "response" in creds[0]
        finally:
            os.unlink(f.name)

    def test_parse_gtc_cleartext(self):
        mod = _make_module()
        import os
        import tempfile

        log_content = """
username: admin@corp.local
GTC password: SuperSecret123
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(log_content)
            f.flush()
        try:
            creds = mod._parse_wpe_log(f.name)
            assert len(creds) == 1
            assert creds[0]["username"] == "admin@corp.local"
            assert creds[0]["password"] == "SuperSecret123"
            assert creds[0]["type"] == "GTC-cleartext"
        finally:
            os.unlink(f.name)

    def test_parse_empty_log(self):
        mod = _make_module()
        creds = mod._parse_wpe_log("/nonexistent/path.log")
        assert creds == []

    def test_parse_no_creds(self):
        mod = _make_module()
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("hostapd-wpe started\nListening on port 1812\n")
            f.flush()
        try:
            creds = mod._parse_wpe_log(f.name)
            assert creds == []
        finally:
            os.unlink(f.name)


class TestDisplayAndDict:
    def test_to_dict(self):
        mod = _make_module()
        info = EapInfo(
            bssid="AA:BB:CC:DD:EE:FF",
            essid="CorpWiFi",
            eap_types=["PEAP", "EAP-TTLS"],
            inner_auth=["MS-CHAPv2"],
        )
        d = mod.to_dict(info)
        assert d["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert "PEAP" in d["eap_types"]

    def test_display_no_crash(self):
        mod = _make_module()
        info = EapInfo(bssid="AA:BB:CC:DD:EE:FF")
        mod._display_eap_info(info)

        info.eap_types = ["PEAP", "GTC"]
        mod._display_eap_info(info)


class TestCheckTool:
    @patch("voidfreq.modules.enterprise.subprocess")
    def test_tool_found(self, mock_sub):
        mock_sub.run.return_value = MagicMock(returncode=0)
        mod = _make_module()
        result = mod._check_tool()
        assert result in ("hostapd-wpe", "hostapd-mana")

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_tool_not_found(self, mock_run):
        mod = _make_module()
        result = mod._check_tool()
        assert result is None


class TestStop:
    def test_stop_no_proc(self):
        mod = _make_module()
        mod.stop()

    def test_stop_with_proc(self):
        mod = _make_module()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mod._proc = mock_proc
        mod.stop()
        mock_proc.terminate.assert_called_once()
        assert mod._proc is None
