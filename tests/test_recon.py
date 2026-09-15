"""Integration tests for recon module — mock subprocess for airodump-ng."""

from __future__ import annotations

from unittest.mock import MagicMock

from voidfreq.modules.recon import AccessPoint, Client, ReconModule

AP_SECTION = """\
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

AA:BB:CC:DD:EE:FF, 2024-01-01 00:00:00, 2024-01-01 00:01:00, 6, 54, WPA2, CCMP, PSK, -50, 100, 0, 0.0.0.0, 8, TestNet,
11:22:33:44:55:66, 2024-01-01 00:00:00, 2024-01-01 00:01:00, 1, 54, OPN, , , -70, 50, 0, 0.0.0.0, 4, Open,"""


def test_parse_ap_section():
    config = MagicMock()
    opsec = MagicMock()
    recon = ReconModule(config, opsec)
    recon._parse_ap_section(AP_SECTION)
    assert len(recon.access_points) == 2
    assert recon.access_points[0].bssid == "AA:BB:CC:DD:EE:FF"
    assert recon.access_points[0].essid == "TestNet"
    assert recon.access_points[0].channel == 6
    assert recon.access_points[0].power == -50
    assert recon.access_points[1].encryption == "OPN"
    assert recon.access_points[1].essid == "Open"


def test_parse_empty_csv():
    config = MagicMock()
    opsec = MagicMock()
    recon = ReconModule(config, opsec)
    recon._parse_ap_section("")
    assert len(recon.access_points) == 0


def test_parse_malformed_csv():
    config = MagicMock()
    opsec = MagicMock()
    recon = ReconModule(config, opsec)
    recon._parse_ap_section("header\nsubheader\nshort,line")
    assert len(recon.access_points) == 0


def test_access_point_dataclass():
    ap = AccessPoint(bssid="AA:BB:CC:DD:EE:FF", channel=6, power=-50,
                     encryption="WPA2", essid="Test")
    assert ap.encryption == "WPA2"
    assert ap.essid == "Test"
    assert ap.wps is False
    assert ap.clients == []


def test_client_dataclass():
    c = Client(mac="11:22:33:44:55:66", ap_bssid="AA:BB:CC:DD:EE:FF", power=-40)
    assert c.vendor == ""


def test_parse_client_section():
    config = MagicMock()
    opsec = MagicMock()
    recon = ReconModule(config, opsec)
    section = (
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
        "\n"
        "AA:11:22:33:44:55, 2024-01-01, 2024-01-01, -40, 200, AA:BB:CC:DD:EE:FF, TestNet"
    )
    recon._parse_client_section(section)
    assert len(recon.clients) == 1
    assert recon.clients[0].mac == "AA:11:22:33:44:55"
