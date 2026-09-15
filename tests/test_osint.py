"""Tests for OSINT module."""

from unittest.mock import MagicMock, patch

import pytest

from voidfreq.modules.osint import OsintModule, OsintReport, VendorInfo, WigleResult


@pytest.fixture()
def osint():
    return OsintModule(wigle_api_key=None)


@pytest.fixture()
def osint_with_key():
    return OsintModule(wigle_api_key="dGVzdDp0ZXN0")


class TestVendorLookup:
    def test_vendor_found(self, osint):
        mock_lookup_cls = MagicMock()
        mock_lookup_cls.return_value.lookup.return_value = "TP-Link Technologies"

        with patch.dict("sys.modules", {"mac_vendor_lookup": MagicMock(MacLookup=mock_lookup_cls)}):
            result = osint._lookup_vendor("AA:BB:CC:DD:EE:FF")

        assert result is not None
        assert result.vendor == "TP-Link Technologies"
        assert result.mac_prefix == "AA:BB:CC"

    def test_vendor_lookup_fails(self, osint):
        with patch.dict("sys.modules", {"mac_vendor_lookup": None}):
            result = osint._lookup_vendor("AA:BB:CC:DD:EE:FF")
        assert result is not None
        assert result.vendor == "Unknown"


class TestKnownVulns:
    def test_tplink_vulns(self, osint):
        vendor = VendorInfo(mac_prefix="AA:BB:CC", vendor="TP-Link Technologies")
        vulns = osint._check_known_vulns(vendor, "")
        assert len(vulns) > 0
        assert any("admin:admin" in v for v in vulns)

    def test_default_essid_pattern(self, osint):
        vendor = VendorInfo(mac_prefix="AA:BB:CC", vendor="Unknown")
        vulns = osint._check_known_vulns(vendor, "NETGEAR-5G")
        assert any("Netgear default" in v for v in vulns)

    def test_no_vulns_for_unknown(self, osint):
        vendor = VendorInfo(mac_prefix="AA:BB:CC", vendor="UnknownBrand")
        vulns = osint._check_known_vulns(vendor, "UniqueSSID")
        assert len(vulns) == 0

    def test_no_vendor(self, osint):
        vulns = osint._check_known_vulns(None, "test")
        assert vulns == []


class TestInvestigate:
    def test_investigate_without_wigle(self, osint):
        with patch.object(osint, "_lookup_vendor") as mock_vendor:
            mock_vendor.return_value = VendorInfo(
                mac_prefix="AA:BB:CC", vendor="ASUS",
            )
            report = osint.investigate("AA:BB:CC:DD:EE:FF", essid="ASUS_5G")

        assert report.target_bssid == "AA:BB:CC:DD:EE:FF"
        assert report.vendor.vendor == "ASUS"
        assert report.wigle is None
        assert len(report.known_vulns) > 0


class TestExport:
    def test_export_creates_file(self, osint, tmp_path):
        report = OsintReport(
            target_bssid="AA:BB:CC:DD:EE:FF",
            vendor=VendorInfo(mac_prefix="AA:BB:CC", vendor="Test"),
            known_vulns=["vuln1"],
        )
        path = osint.export(report, output_dir=str(tmp_path))
        assert path.endswith(".json")

        import json
        with open(path) as f:
            data = json.load(f)
        assert data["target"] == "AA:BB:CC:DD:EE:FF"
        assert data["known_vulns"] == ["vuln1"]


class TestDataclasses:
    def test_wigle_result_defaults(self):
        r = WigleResult(bssid="AA:BB:CC:DD:EE:FF")
        assert r.ssid == ""
        assert r.latitude == 0.0

    def test_osint_report_defaults(self):
        r = OsintReport(target_bssid="AA:BB:CC:DD:EE:FF")
        assert r.wigle is None
        assert r.vendor is None
        assert r.known_vulns == []
