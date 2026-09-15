"""Integration tests for Evil Twin module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from voidfreq.modules.eviltwin import EvilTwinConfig, EvilTwinModule


def test_evil_twin_config_defaults():
    cfg = EvilTwinConfig(essid="Free", channel=6, interface="wlan0")
    assert cfg.bssid is None
    assert cfg.gateway_ip == "192.168.87.1"
    assert cfg.capture_traffic is True


def test_evil_twin_config_custom():
    cfg = EvilTwinConfig(
        essid="Test", channel=11, interface="wlan1",
        bssid="AA:BB:CC:DD:EE:FF",
        wpa_passphrase="secret",
        gateway_ip="10.0.0.1",
    )
    assert cfg.wpa_passphrase == "secret"
    assert cfg.gateway_ip == "10.0.0.1"


@patch("voidfreq.modules.eviltwin.subprocess.Popen")
@patch("voidfreq.modules.eviltwin.subprocess.run")
def test_hostapd_config_generation(mock_run, mock_popen, tmp_path):
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None
    mock_popen.return_value = mock_proc

    config = MagicMock()
    opsec = MagicMock()
    et = EvilTwinModule(config, opsec)

    twin_cfg = EvilTwinConfig(essid="FreeWiFi", channel=6, interface="wlan0")
    hostapd_conf = et._generate_hostapd_conf(twin_cfg, str(tmp_path))
    with open(hostapd_conf) as f:
        content = f.read()
    assert "ssid=FreeWiFi" in content
    assert "channel=6" in content


@patch("voidfreq.modules.eviltwin.subprocess.Popen")
@patch("voidfreq.modules.eviltwin.subprocess.run")
def test_dnsmasq_config_generation(mock_run, mock_popen, tmp_path):
    config = MagicMock()
    opsec = MagicMock()
    et = EvilTwinModule(config, opsec)

    twin_cfg = EvilTwinConfig(essid="Test", channel=1, interface="wlan0")
    dnsmasq_conf = et._generate_dnsmasq_conf(twin_cfg, str(tmp_path))
    with open(dnsmasq_conf) as f:
        content = f.read()
    assert "interface=wlan0" in content
    assert "dhcp-range=" in content
