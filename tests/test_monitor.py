"""Tests for monitor module — rogue AP and Evil Twin detection."""

from unittest.mock import MagicMock

import pytest

from voidfreq.modules.monitor import Alert, MonitorModule


@pytest.fixture()
def monitor():
    config = MagicMock()
    return MonitorModule(config)


class TestAlerts:
    def test_add_alert(self, monitor):
        monitor._add_alert("CRITICAL", "TEST", "test message", source="src")
        assert len(monitor.alerts) == 1
        assert monitor.alerts[0].severity == "CRITICAL"
        assert monitor.alerts[0].alert_type == "TEST"
        assert monitor.alerts[0].source == "src"

    def test_alert_dataclass(self):
        a = Alert(
            timestamp="12:00:00",
            severity="WARNING",
            alert_type="ROGUE_AP",
            message="test",
        )
        assert a.source == ""


class TestExportAlerts:
    def test_export_creates_json(self, monitor, tmp_path):
        monitor._add_alert("WARNING", "TEST", "msg1")
        monitor._add_alert("CRITICAL", "TEST2", "msg2")

        path = monitor.export_alerts(output_dir=str(tmp_path))
        assert path.endswith(".json")

        import json
        with open(path) as f:
            data = json.load(f)
        assert data["stats"]["total_alerts"] == 2
        assert data["stats"]["critical"] == 1
        assert data["stats"]["warnings"] == 1


class TestStop:
    def test_stop_returns_alerts(self, monitor):
        monitor._running = True
        monitor._add_alert("INFO", "TEST", "msg")
        alerts = monitor.stop()
        assert len(alerts) == 1
        assert not monitor._running
