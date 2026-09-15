"""Tests for WPS module."""

from unittest.mock import MagicMock, patch

import pytest

from voidfreq.modules.wps import WpsModule, WpsResult, WpsTarget


@pytest.fixture()
def wps():
    config = MagicMock()
    opsec = MagicMock()
    return WpsModule(config, opsec)


class TestWpsScan:
    def test_scan_parses_wash_output(self, wps):
        wash_output = (
            "Wash v1.6.6\n"
            "---\n"
            "BSSID               Ch  dBm  WPS  Lck  ESSID\n"
            "AA:BB:CC:DD:EE:FF   6   -45  1.0  No   TestNetwork\n"
            "11:22:33:44:55:66   1   -60  2.0  Yes  LockedAP\n"
        )
        mock_result = MagicMock(returncode=0, stdout=wash_output)

        with patch("voidfreq.modules.wps.subprocess.run", return_value=mock_result):
            targets = wps.scan_wps("wlan0mon", duration=10)

        assert len(targets) == 2
        assert targets[0].bssid == "AA:BB:CC:DD:EE:FF"
        assert targets[0].channel == 6
        assert targets[0].wps_locked is False
        assert targets[1].wps_locked is True

    def test_scan_wash_not_found(self, wps):
        with patch("voidfreq.modules.wps.subprocess.run", side_effect=FileNotFoundError):
            targets = wps.scan_wps("wlan0mon")
        assert targets == []

    def test_scan_empty_output(self, wps):
        mock_result = MagicMock(returncode=0, stdout="")
        with patch("voidfreq.modules.wps.subprocess.run", return_value=mock_result):
            targets = wps.scan_wps("wlan0mon")
        assert targets == []


class TestPixieDust:
    def test_pixie_reaver_success(self, wps):
        mock_result = MagicMock(
            returncode=0,
            stdout="WPS PIN: '12345670'\nWPA PSK: 'MyPassword123'\n",
            stderr="",
        )
        with patch("voidfreq.modules.wps.subprocess.run", return_value=mock_result):
            result = wps.pixie_dust("wlan0mon", "AA:BB:CC:DD:EE:FF", 6)

        assert result.success is True
        assert result.pin == "12345670"
        assert result.password == "MyPassword123"

    def test_pixie_both_tools_fail(self, wps):
        mock_result = MagicMock(returncode=1, stdout="", stderr="Failed")
        with patch("voidfreq.modules.wps.subprocess.run", return_value=mock_result):
            result = wps.pixie_dust("wlan0mon", "AA:BB:CC:DD:EE:FF", 6)

        assert result.success is False

    def test_pixie_tool_not_found(self, wps):
        with patch("voidfreq.modules.wps.subprocess.run", side_effect=FileNotFoundError):
            result = wps.pixie_dust("wlan0mon", "AA:BB:CC:DD:EE:FF", 6)
        assert result.success is False


class TestWpsDataclasses:
    def test_wps_result_defaults(self):
        r = WpsResult(success=False)
        assert r.pin is None
        assert r.password is None
        assert r.method == ""

    def test_wps_target(self):
        t = WpsTarget(bssid="AA:BB:CC:DD:EE:FF", essid="Test", channel=6)
        assert t.wps_version == ""
        assert t.wps_locked is False
