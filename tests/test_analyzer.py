"""Integration tests for pcap analyzer — mock tshark subprocess calls."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from voidfreq.modules.analyzer import PcapAnalysis, PcapAnalyzer


def test_analysis_dataclass():
    analysis = PcapAnalysis(filename="test.pcap")
    assert analysis.total_packets == 0
    assert analysis.dns_queries == []
    assert analysis.protocols == {}


@patch("voidfreq.modules.analyzer.subprocess.run")
def test_analyze_missing_file(mock_run):
    analyzer = PcapAnalyzer()
    result = analyzer.analyze("/nonexistent/file.pcap")
    assert result.filename == "/nonexistent/file.pcap"
    assert result.total_packets == 0
    mock_run.assert_not_called()


@patch("voidfreq.modules.analyzer.os.path.exists", return_value=True)
@patch("voidfreq.modules.analyzer.subprocess.run")
def test_analyze_runs_tshark(mock_run, mock_exists):
    mock_run.return_value = MagicMock(returncode=0, stdout="")
    analyzer = PcapAnalyzer()
    result = analyzer.analyze("/tmp/test.pcap")
    assert result.filename == "/tmp/test.pcap"
    assert mock_run.call_count > 0


def test_export(tmp_path):
    analyzer = PcapAnalyzer()
    analyzer.analysis = PcapAnalysis(
        filename="test.pcap",
        total_packets=100,
        dns_queries=["example.com"],
    )
    path = analyzer.export(output_dir=str(tmp_path))
    assert path.endswith(".json")
    with open(path) as f:
        data = json.loads(f.read())
    assert data["filename"] == "test.pcap"
    assert data["total_packets"] == 100
