"""Integration tests for DNS spoof module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from voidfreq.modules.dnsspoof import DnsSpoofModule, SpoofedQuery, SpoofRule


def test_spoof_rule_defaults():
    rule = SpoofRule(domain="example.com", redirect_ip="10.0.0.1")
    assert rule.wildcard is False


def test_spoof_rule_wildcard():
    rule = SpoofRule(domain="*.evil.com", redirect_ip="10.0.0.1", wildcard=True)
    assert rule.wildcard is True


def test_spoofed_query():
    q = SpoofedQuery(
        timestamp="12:00:00", source_ip="192.168.1.5",
        domain="example.com", redirected_to="10.0.0.1",
    )
    assert q.domain == "example.com"
    assert q.source_ip == "192.168.1.5"


def test_add_rules():
    config = MagicMock()
    opsec = MagicMock()
    ds = DnsSpoofModule(config, opsec)
    ds.add_rule("example.com", "10.0.0.1")
    ds.add_rule("*.evil.com", "10.0.0.2", wildcard=True)
    assert len(ds.rules) == 2
    assert ds.rules[0].domain == "example.com"
    assert ds.rules[1].wildcard is True


def test_start_no_rules():
    config = MagicMock()
    opsec = MagicMock()
    ds = DnsSpoofModule(config, opsec)
    result = ds.start("wlan0")
    assert result is False


@patch("voidfreq.modules.dnsspoof.subprocess.Popen")
@patch("voidfreq.modules.dnsspoof.subprocess.run")
def test_start_with_rules(mock_run, mock_popen, tmp_path):
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None
    mock_proc.stdout = MagicMock()
    mock_proc.stdout.readline.return_value = ""
    mock_popen.return_value = mock_proc

    config = MagicMock()
    opsec = MagicMock()
    ds = DnsSpoofModule(config, opsec)
    ds.add_rule("example.com", "10.0.0.1")

    def fake_build():
        hosts = str(tmp_path / "hosts")
        with open(hosts, "w") as f:
            f.write("10.0.0.1 example.com\n")
        return hosts, None

    with patch.object(ds, "_build_config_files", fake_build):
        result = ds.start("wlan0")
    assert result is True
    assert ds._running is True

    queries = ds.stop()
    assert isinstance(queries, list)
