"""Integration tests for MITM module — mock subprocess for arpspoof/tshark."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from voidfreq.modules.mitm import CapturedTraffic, MitmModule


@patch("voidfreq.modules.mitm.subprocess.Popen")
@patch("voidfreq.modules.mitm.subprocess.run")
def test_start_stop(mock_run, mock_popen):
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None
    mock_proc.stdout = MagicMock()
    mock_proc.stdout.readline.return_value = ""
    mock_popen.return_value = mock_proc

    config = MagicMock()
    config.mitm_fullduplex = True
    config.mitm_capture = ["dns"]
    opsec = MagicMock()
    mitm = MitmModule(config, opsec)

    mitm.start("wlan0", "192.168.1.5", "192.168.1.1")
    assert mitm._running is True

    traffic = mitm.stop()
    assert isinstance(traffic, CapturedTraffic)
    assert mitm._running is False


def test_captured_traffic_defaults():
    traffic = CapturedTraffic()
    assert traffic.dns_queries == []
    assert traffic.sni_domains == []
    assert traffic.http_requests == []


@patch("voidfreq.modules.mitm.subprocess.Popen")
@patch("voidfreq.modules.mitm.subprocess.run")
def test_ttl_spoof_enabled(mock_run, mock_popen):
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None
    mock_proc.stdout = MagicMock()
    mock_proc.stdout.readline.return_value = ""
    mock_popen.return_value = mock_proc
    mock_run.return_value = MagicMock(returncode=0)

    config = MagicMock()
    config.mitm_fullduplex = False
    config.mitm_capture = []
    opsec = MagicMock()
    mitm = MitmModule(config, opsec)

    mitm.start("wlan0", "192.168.1.5", "192.168.1.1", ttl_spoof=True)
    assert mitm._ttl_rule is not None

    mitm.stop()
    assert mitm._ttl_rule is None


def test_export(tmp_path):
    config = MagicMock()
    config.mitm_fullduplex = False
    config.mitm_capture = []
    opsec = MagicMock()
    mitm = MitmModule(config, opsec)

    mitm.traffic.dns_queries.append({"domain": "example.com", "client": "10.0.0.1"})
    mitm.traffic.sni_domains.append({"domain": "secure.com"})

    path = mitm.export(output_dir=str(tmp_path))
    assert path.endswith(".json")
    with open(path) as f:
        data = json.loads(f.read())
    assert data["stats"]["total_dns"] == 1
    assert data["stats"]["total_sni"] == 1
