"""Tests for report generation — markdown and JSON output."""

from __future__ import annotations

import json
import os

from voidfreq.utils.report import generate_report


class TestReportMarkdown:
    def test_empty_report(self, tmp_path):
        generate_report(output_dir=str(tmp_path), fmt="markdown")
        md_files = list(tmp_path.glob("*.md"))
        assert len(md_files) == 1
        content = md_files[0].read_text(encoding="utf-8")
        assert "VoidFreq" in content

    def test_scan_data(self, tmp_path):
        scan = {
            "access_points": [
                {
                    "bssid": "AA:BB:CC:DD:EE:FF",
                    "essid": "TestNet",
                    "channel": 6,
                    "power": -50,
                    "encryption": "WPA2",
                    "clients": ["11:22:33:44:55:66"],
                },
            ],
        }
        generate_report(scan_data=scan, output_dir=str(tmp_path), fmt="markdown")
        md_files = list(tmp_path.glob("*.md"))
        content = md_files[0].read_text(encoding="utf-8")
        assert "AA:BB:CC:DD:EE:FF" in content
        assert "TestNet" in content
        assert "Reconnaissance" in content

    def test_capture_data(self, tmp_path):
        capture = {"strategy": "PMKID", "success": True, "file": "/tmp/cap.pcapng"}
        generate_report(capture_data=capture, output_dir=str(tmp_path), fmt="markdown")
        content = list(tmp_path.glob("*.md"))[0].read_text(encoding="utf-8")
        assert "PMKID" in content
        assert "Capture" in content

    def test_crack_data_with_password(self, tmp_path):
        crack = {"method": "hashcat", "success": True, "password": "secret123"}
        generate_report(crack_data=crack, output_dir=str(tmp_path), fmt="markdown")
        content = list(tmp_path.glob("*.md"))[0].read_text(encoding="utf-8")
        assert "secret123" in content
        assert "Cracking" in content

    def test_traffic_data(self, tmp_path):
        traffic = {
            "stats": {
                "total_dns": 42,
                "total_sni": 10,
                "total_http": 5,
                "unique_domains": 8,
                "total_credentials": 1,
            },
            "dns_queries": [{"domain": "example.com"}],
            "sni_domains": [{"domain": "secure.example.com"}],
        }
        generate_report(traffic_data=traffic, output_dir=str(tmp_path), fmt="markdown")
        content = list(tmp_path.glob("*.md"))[0].read_text(encoding="utf-8")
        assert "example.com" in content
        assert "Traffic" in content

    def test_alerts_data(self, tmp_path):
        alerts = {
            "alerts": [
                {"severity": "CRITICAL", "type": "Deauth", "message": "Flood detected"},
                {"severity": "WARNING", "type": "ARP", "message": "Anomaly"},
            ],
        }
        generate_report(alerts_data=alerts, output_dir=str(tmp_path), fmt="markdown")
        content = list(tmp_path.glob("*.md"))[0].read_text(encoding="utf-8")
        assert "Flood detected" in content
        assert "Blue Team" in content


class TestReportJSON:
    def test_json_output(self, tmp_path):
        scan = {"access_points": []}
        generate_report(scan_data=scan, output_dir=str(tmp_path), fmt="json")
        json_files = list(tmp_path.glob("*.json"))
        assert len(json_files) == 1
        data = json.loads(json_files[0].read_text())
        assert data["tool"] == "VoidFreq"
        assert "version" in data
        assert "timestamp" in data
        assert data["reconnaissance"] == scan

    def test_both_formats(self, tmp_path):
        generate_report(output_dir=str(tmp_path), fmt="both")
        assert len(list(tmp_path.glob("*.md"))) == 1
        assert len(list(tmp_path.glob("*.json"))) == 1

    def test_json_all_sections_null(self, tmp_path):
        generate_report(output_dir=str(tmp_path), fmt="json")
        data = json.loads(list(tmp_path.glob("*.json"))[0].read_text())
        assert data["reconnaissance"] is None
        assert data["capture"] is None
        assert data["cracking"] is None
        assert data["traffic"] is None
        assert data["alerts"] is None

    def test_output_dir_created(self, tmp_path):
        nested = str(tmp_path / "deep" / "nested")
        generate_report(output_dir=nested, fmt="markdown")
        assert os.path.isdir(nested)
