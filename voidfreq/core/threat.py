"""Threat detector — detect IDS/WIDS presence and trigger kill switch."""

from __future__ import annotations

import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from rich.console import Console

from .config import Config
from .logger import get_logger

console = Console()
log = get_logger("threat")


@dataclass
class ThreatIndicator:
    timestamp: str
    threat_type: str
    confidence: str  # low | medium | high
    details: str


class ThreatDetector:
    """Detects defensive systems on the network that could expose the attacker."""

    KNOWN_IDS_PORTS = {
        3000: "Snort/Suricata web UI",
        2812: "Monit",
        9090: "Kismet",
        8834: "Nessus",
        3790: "Metasploit Pro",
        8080: "Security Onion / various IDS",
        514: "Syslog (centralized logging)",
        1514: "OSSEC",
        1515: "OSSEC auth",
        55000: "Wazuh API",
    }

    KNOWN_IDS_MACS = {
        "00:0C:DB": "Cisco Aironet (WIDS)",
        "00:40:96": "Cisco (enterprise AP)",
        "F0:9F:C2": "Ubiquiti (UniFi)",
        "18:E8:29": "Ubiquiti",
        "78:8A:20": "Ubiquiti",
        "24:5A:4C": "Ubiquiti",
        "B4:FB:E4": "Ubiquiti",
        "68:D7:9A": "Ubiquiti",
        "44:D9:E7": "Ubiquiti",
        "FC:EC:DA": "Ubiquiti",
        "AC:8B:A9": "Ubiquiti",
        "80:2A:A8": "Ubiquiti",
    }

    WIDS_SIGNATURES = [
        "kismet",
        "airwatch",
        "arpwatch",
        "snort",
        "suricata",
        "wids",
    ]

    def __init__(self, config: Config) -> None:
        self.config = config
        self.indicators: list[ThreatIndicator] = []
        self._running = False
        self._killswitch_callback: Callable[[], None] | None = None

    def set_killswitch(self, callback: Callable[[], None]) -> None:
        self._killswitch_callback = callback

    def scan_once(self, interface: str, gateway_ip: str) -> list[ThreatIndicator]:
        self.indicators = []

        self._check_ids_ports(gateway_ip)
        self._check_enterprise_aps(interface)
        self._check_arp_monitoring(gateway_ip)
        self._check_running_processes()

        if self.indicators:
            self._display_threats()

        return self.indicators

    def start_continuous(self, interface: str, gateway_ip: str) -> None:
        self._running = True

        t = threading.Thread(
            target=self._continuous_monitor,
            args=(interface, gateway_ip),
            daemon=True,
        )
        t.start()

    def stop(self) -> None:
        self._running = False

    def _add_indicator(self, threat_type: str, confidence: str, details: str) -> None:
        indicator = ThreatIndicator(
            timestamp=time.strftime("%H:%M:%S"),
            threat_type=threat_type,
            confidence=confidence,
            details=details,
        )
        self.indicators.append(indicator)
        log.warning("Threat: [%s] %s — %s", confidence.upper(), threat_type, details)

        color = {"high": "red bold", "medium": "yellow", "low": "dim"}.get(confidence, "white")
        console.print(f"[{color}]THREAT: [{confidence.upper()}] {threat_type} — {details}[/{color}]")

        if confidence == "high" and self.config.stealth.auto_killswitch:
            console.print("[red bold]KILL SWITCH TRIGGERED![/red bold]")
            if self._killswitch_callback:
                self._killswitch_callback()

    def _check_ids_ports(self, gateway_ip: str) -> None:
        ports = ",".join(str(p) for p in self.KNOWN_IDS_PORTS)
        try:
            result = subprocess.run(
                ["nmap", "-sT", "-p", ports, "--open", "-T4", gateway_ip, "-oX", "-"],
                capture_output=True, text=True, timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return

        if result.returncode != 0:
            return

        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(result.stdout)
            for port_el in root.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") == "open":
                    port_num = int(port_el.get("portid", 0))
                    if port_num in self.KNOWN_IDS_PORTS:
                        self._add_indicator(
                            "IDS_PORT_OPEN",
                            "medium",
                            f"Port {port_num} open on gateway — likely {self.KNOWN_IDS_PORTS[port_num]}",
                        )
        except ET.ParseError:
            pass

    def _check_enterprise_aps(self, interface: str) -> None:
        try:
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return

        for line in result.stdout.split("\n"):
            for prefix, vendor in self.KNOWN_IDS_MACS.items():
                if prefix.lower() in line.lower():
                    self._add_indicator(
                        "ENTERPRISE_AP",
                        "medium",
                        f"Enterprise AP detected ({vendor}) — may have WIDS capabilities",
                    )

    def _check_arp_monitoring(self, gateway_ip: str) -> None:
        try:
            result1 = subprocess.run(
                ["arping", "-c", "3", "-I", self.config.interface, gateway_ip],
                capture_output=True, text=True, timeout=10,
            )

            time.sleep(2)

            result2 = subprocess.run(
                ["arping", "-c", "3", "-I", self.config.interface, gateway_ip],
                capture_output=True, text=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return

        if "Received 0" in (result1.stdout + result2.stdout):
            self._add_indicator(
                "ARP_FILTERED",
                "low",
                "ARP responses may be filtered — possible arpwatch or static ARP",
            )

    def _check_running_processes(self) -> None:
        try:
            result = subprocess.run(
                ["ps", "aux"], capture_output=True, text=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return

        for sig in self.WIDS_SIGNATURES:
            if sig in result.stdout.lower():
                self._add_indicator(
                    "IDS_PROCESS",
                    "high",
                    f"IDS/WIDS process detected locally: {sig}",
                )

    def _continuous_monitor(self, interface: str, gateway_ip: str) -> None:
        while self._running:
            self.scan_once(interface, gateway_ip)
            time.sleep(30)

    def _display_threats(self) -> None:
        from rich.table import Table
        table = Table(title="Threat Indicators", show_lines=True)
        table.add_column("Time", style="dim")
        table.add_column("Confidence", width=10)
        table.add_column("Type", style="cyan")
        table.add_column("Details")

        for ind in self.indicators:
            colors = {"high": "red", "medium": "yellow", "low": "dim"}
            table.add_row(
                ind.timestamp,
                f"[{colors.get(ind.confidence, 'white')}]{ind.confidence.upper()}[/{colors.get(ind.confidence, 'white')}]",
                ind.threat_type,
                ind.details,
            )

        console.print(table)

    @property
    def risk_level(self) -> str:
        if any(i.confidence == "high" for i in self.indicators):
            return "HIGH"
        if any(i.confidence == "medium" for i in self.indicators):
            return "MEDIUM"
        if self.indicators:
            return "LOW"
        return "CLEAR"
