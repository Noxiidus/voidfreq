"""Tests for Bluetooth recon module."""

from unittest.mock import MagicMock, patch

from voidfreq.core.config import Config, StealthProfile
from voidfreq.core.opsec import OpsecEngine
from voidfreq.modules.bluetooth import BluetoothModule, BtDevice, BtScanResult


def _make_module():
    config = Config(
        interface="wlan0",
        stealth=StealthProfile(),
        stealth_level="high",
        raw={},
    )
    opsec = MagicMock(spec=OpsecEngine)
    return BluetoothModule(config, opsec)


class TestBtDevice:
    def test_defaults(self):
        dev = BtDevice(address="AA:BB:CC:DD:EE:FF")
        assert dev.name == ""
        assert dev.device_type == "unknown"
        assert dev.rssi == 0
        assert dev.services == []
        assert dev.vulnerabilities == []

    def test_scan_result_defaults(self):
        result = BtScanResult()
        assert result.devices == []
        assert result.duration == 0.0


class TestVulnerabilityCheck:
    def test_known_oui(self):
        mod = _make_module()
        dev = BtDevice(address="A4:C1:38:12:34:56", name="ESP32-test")
        mod._check_vulnerabilities(dev)
        assert len(dev.vulnerabilities) == 1
        assert "ESP32" in dev.vulnerabilities[0]

    def test_unknown_oui(self):
        mod = _make_module()
        dev = BtDevice(address="FF:FF:FF:00:00:00")
        mod._check_vulnerabilities(dev)
        assert dev.vulnerabilities == []


class TestRssiDistance:
    def test_close_range(self):
        mod = _make_module()
        dist = mod._rssi_to_distance(-30)
        assert dist < 1.0

    def test_medium_range(self):
        mod = _make_module()
        dist = mod._rssi_to_distance(-70)
        assert 1.0 < dist < 30.0

    def test_far_range(self):
        mod = _make_module()
        dist = mod._rssi_to_distance(-95)
        assert dist > 10.0

    def test_positive_rssi(self):
        mod = _make_module()
        assert mod._rssi_to_distance(0) == 0.0


class TestUuidName:
    def test_known_uuid(self):
        mod = _make_module()
        assert mod._uuid_name("0000180f-0000-1000-8000-00805f9b34fb") == "Battery Service"

    def test_unknown_uuid(self):
        mod = _make_module()
        assert mod._uuid_name("deadbeef-1234-5678-abcd-ef0123456789") == ""


class TestBleScan:
    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_ble_scan_no_hcitool(self, mock_run):
        mod = _make_module()
        result = mod.scan_ble(duration=5)
        assert result.devices == []

    @patch("voidfreq.modules.bluetooth.subprocess")
    def test_ble_scan_hcitool_output(self, mock_sub):
        mock_sub.run.side_effect = [
            MagicMock(returncode=0),  # hciconfig up
            MagicMock(
                stdout="AA:BB:CC:DD:EE:FF TestDevice\n11:22:33:44:55:66 AnotherDev\n",
                returncode=0,
            ),
        ]
        mock_sub.TimeoutExpired = type("TE", (Exception,), {})
        mod = _make_module()
        result = mod.scan_ble(duration=5)
        assert len(result.devices) == 2
        assert result.devices[0].address == "AA:BB:CC:DD:EE:FF"
        assert result.devices[0].name == "TestDevice"


class TestClassicScan:
    @patch("voidfreq.modules.bluetooth.subprocess")
    def test_classic_scan_parse(self, mock_sub):
        mock_sub.run.return_value = MagicMock(
            stdout="Scanning ...\n\tAA:BB:CC:DD:EE:FF\tMyPhone\n\t11:22:33:44:55:66\tMyLaptop\n",
            returncode=0,
        )
        mock_sub.TimeoutExpired = type("TE", (Exception,), {})
        mod = _make_module()
        result = mod.scan_classic(duration=5)
        assert len(result.devices) == 2
        assert result.devices[0].name == "MyPhone"


class TestToDict:
    def test_to_dict(self):
        mod = _make_module()
        result = BtScanResult(
            devices=[BtDevice(address="AA:BB:CC:DD:EE:FF", name="Test", device_type="ble")],
            duration=10.0,
            interface="hci0",
        )
        d = mod.to_dict(result)
        assert d["device_count"] == 1
        assert d["devices"][0]["address"] == "AA:BB:CC:DD:EE:FF"
        assert d["interface"] == "hci0"


class TestDisplayScan:
    def test_display_empty(self):
        mod = _make_module()
        result = BtScanResult()
        mod._display_scan(result)

    def test_display_with_vulns(self):
        mod = _make_module()
        dev = BtDevice(
            address="A4:C1:38:12:34:56",
            name="VulnDevice",
            vulnerabilities=["ESP32 (common in IoT, often no auth)"],
        )
        result = BtScanResult(devices=[dev], duration=10.0)
        mod._display_scan(result)
