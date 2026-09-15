"""Integration tests for scanner module — mock subprocess for nmap."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from voidfreq.modules.scanner import ScannerModule

NMAP_HOST_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Cisco"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.100" addrtype="ipv4"/>
  </host>
</nmaprun>
"""

NMAP_PORT_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@patch("voidfreq.modules.scanner.subprocess.run")
def test_discover_hosts(mock_run):
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=NMAP_HOST_XML, stderr="",
    )
    config = MagicMock()
    config.stealth.scan_timing = "normal"
    config.stealth.fingerprint_spoof = False
    opsec = MagicMock()
    scanner = ScannerModule(config, opsec)

    hosts = scanner.discover_hosts("192.168.1.0/24")
    assert len(hosts) == 2
    assert hosts[0].ip == "192.168.1.1"


@patch("voidfreq.modules.scanner.subprocess.run")
def test_scan_ports(mock_run):
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=NMAP_PORT_XML, stderr="",
    )
    config = MagicMock()
    config.stealth.scan_timing = "normal"
    config.stealth.fingerprint_spoof = False
    opsec = MagicMock()
    scanner = ScannerModule(config, opsec)

    host = scanner.scan_ports("192.168.1.1")
    assert host is not None
    assert host.ip == "192.168.1.1"
    open_ports = [p for p in host.ports if p.state == "open"]
    assert len(open_ports) == 2


@patch("voidfreq.modules.scanner.subprocess.run")
def test_discover_hosts_failure(mock_run):
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=2, stdout="", stderr="nmap failed",
    )
    config = MagicMock()
    config.stealth.scan_timing = "normal"
    config.stealth.fingerprint_spoof = False
    opsec = MagicMock()
    scanner = ScannerModule(config, opsec)

    hosts = scanner.discover_hosts("10.0.0.0/24")
    assert hosts == []


@patch("voidfreq.modules.scanner.subprocess.run")
def test_stealth_scan_options(mock_run):
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=NMAP_HOST_XML, stderr="",
    )
    config = MagicMock()
    config.stealth.scan_timing = "paranoid"
    config.stealth.fingerprint_spoof = True
    opsec = MagicMock()
    scanner = ScannerModule(config, opsec)

    scanner.discover_hosts("192.168.1.0/24")
    called_cmd = mock_run.call_args[0][0]
    assert "-T1" in called_cmd
    assert "--data-length" in called_cmd
