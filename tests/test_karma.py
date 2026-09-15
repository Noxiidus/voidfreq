"""Tests for karma module."""

import os
from unittest.mock import MagicMock

import pytest

from voidfreq.modules.karma import KarmaConfig, KarmaModule, ProbeRequest


@pytest.fixture()
def karma():
    config = MagicMock()
    opsec = MagicMock()
    return KarmaModule(config, opsec)


class TestKarmaConfig:
    def test_defaults(self):
        kc = KarmaConfig(interface="wlan0mon")
        assert kc.channel == 1
        assert kc.gateway_ip == "192.168.99.1"
        assert kc.mana_loud is True
        assert kc.capture_traffic is True
        assert kc.captive_portal is False


class TestProbeRequest:
    def test_probe_request(self):
        p = ProbeRequest(timestamp="12:00:00", client_mac="AA:BB:CC:DD:EE:FF", ssid="FreeWiFi")
        assert p.ssid == "FreeWiFi"


class TestHostapdConfig:
    def test_generates_mana_config(self, karma, tmp_path):
        kc = KarmaConfig(interface="wlan0mon", channel=6, mana_loud=True)
        path = karma._generate_hostapd_mana(kc, str(tmp_path))
        assert os.path.exists(path)

        with open(path) as f:
            content = f.read()
        assert "interface=wlan0mon" in content
        assert "channel=6" in content
        assert "enable_mana=1" in content
        assert "mana_loud=1" in content

    def test_generates_config_no_loud(self, karma, tmp_path):
        kc = KarmaConfig(interface="wlan0mon", mana_loud=False)
        path = karma._generate_hostapd_mana(kc, str(tmp_path))

        with open(path) as f:
            content = f.read()
        assert "mana_loud=1" not in content


class TestDnsmasqConfig:
    def test_generates_dnsmasq_config(self, karma, tmp_path):
        kc = KarmaConfig(interface="wlan0mon", gateway_ip="10.0.0.1", dns_server="1.1.1.1")
        path = karma._generate_dnsmasq(kc, str(tmp_path))
        assert os.path.exists(path)

        with open(path) as f:
            content = f.read()
        assert "interface=wlan0mon" in content
        assert "dhcp-option=3,10.0.0.1" in content
        assert "server=1.1.1.1" in content

    def test_captive_portal_redirect(self, karma, tmp_path):
        kc = KarmaConfig(interface="wlan0mon", captive_portal=True, gateway_ip="10.0.0.1")
        path = karma._generate_dnsmasq(kc, str(tmp_path))

        with open(path) as f:
            content = f.read()
        assert "address=/#/10.0.0.1" in content


class TestExport:
    def test_export_creates_json(self, karma, tmp_path):
        karma.probes.append(ProbeRequest("12:00:00", "AA:BB:CC:DD:EE:FF", "TestNet"))
        karma.probes.append(ProbeRequest("12:00:01", "11:22:33:44:55:66", "FreeWiFi"))

        path = karma.export(output_dir=str(tmp_path))
        assert path.endswith(".json")

        import json
        with open(path) as f:
            data = json.load(f)
        assert data["stats"]["total_probes"] == 2
        assert data["stats"]["unique_clients"] == 2
        assert data["stats"]["unique_ssids"] == 2
