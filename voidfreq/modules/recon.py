"""Recon module — passive WiFi network and client discovery."""

from __future__ import annotations

import csv
import os
import random
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

from rich.console import Console
from rich.table import Table

from ..core.config import Config
from ..core.opsec import OpsecEngine

console = Console()


@dataclass
class AccessPoint:
    bssid: str
    channel: int
    power: int
    encryption: str
    essid: str
    wps: bool = False
    clients: list[Client] = field(default_factory=list)


@dataclass
class Client:
    mac: str
    ap_bssid: str
    power: int
    vendor: str = ""


class ReconModule:
    def __init__(self, config: Config, opsec: OpsecEngine) -> None:
        self.config = config
        self.opsec = opsec
        self.access_points: list[AccessPoint] = []
        self.clients: list[Client] = []

    def scan(self, interface: str, duration: int = 30) -> list[AccessPoint]:
        console.print(f"[cyan]Scanning for {duration}s on {interface}...[/cyan]")
        self.opsec.pre_operation()

        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = os.path.join(tmpdir, "voidfreq")

            proc = subprocess.Popen(
                ["sudo", "airodump-ng",
                 "--write", prefix,
                 "--output-format", "csv",
                 "--band", "abg",
                 interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            time.sleep(duration)
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=5)

            csv_file = f"{prefix}-01.csv"
            if os.path.exists(csv_file):
                self._parse_airodump_csv(csv_file)

        self._resolve_vendors()
        self._display_results()
        return self.access_points

    def _parse_airodump_csv(self, path: str) -> None:
        with open(path, encoding="utf-8", errors="ignore") as f:
            content = f.read()

        sections = content.split("\r\n\r\n") if "\r\n\r\n" in content else content.split("\n\n")

        if len(sections) >= 1:
            self._parse_ap_section(sections[0])
        if len(sections) >= 2:
            self._parse_client_section(sections[1])

    def _parse_ap_section(self, section: str) -> None:
        lines = section.strip().split("\n")
        if len(lines) < 2:
            return

        for line in lines[2:]:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 14:
                continue
            try:
                ap = AccessPoint(
                    bssid=parts[0],
                    channel=int(parts[3]) if parts[3].strip() else 0,
                    power=int(parts[8]) if parts[8].strip().lstrip("-").isdigit() else -100,
                    encryption=parts[5],
                    essid=parts[13] if len(parts) > 13 else "",
                )
                self.access_points.append(ap)
            except (ValueError, IndexError):
                continue

    def _parse_client_section(self, section: str) -> None:
        lines = section.strip().split("\n")
        if len(lines) < 2:
            return

        for line in lines[2:]:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 6:
                continue
            try:
                client = Client(
                    mac=parts[0],
                    ap_bssid=parts[5] if len(parts) > 5 else "",
                    power=int(parts[3]) if parts[3].strip().lstrip("-").isdigit() else -100,
                )
                self.clients.append(client)
                for ap in self.access_points:
                    if ap.bssid == client.ap_bssid:
                        ap.clients.append(client)
            except (ValueError, IndexError):
                continue

    def _resolve_vendors(self) -> None:
        try:
            from mac_vendor_lookup import MacLookup
            lookup = MacLookup()
            for client in self.clients:
                try:
                    client.vendor = lookup.lookup(client.mac)
                except Exception:
                    client.vendor = "Unknown"
        except ImportError:
            pass

    def _display_results(self) -> None:
        table = Table(title="Access Points", show_lines=True)
        table.add_column("BSSID", style="cyan")
        table.add_column("ESSID", style="green")
        table.add_column("CH", justify="center")
        table.add_column("PWR", justify="center")
        table.add_column("ENC", style="yellow")
        table.add_column("Clients", justify="center")

        for ap in sorted(self.access_points, key=lambda a: a.power, reverse=True):
            table.add_row(
                ap.bssid,
                ap.essid or "[hidden]",
                str(ap.channel),
                str(ap.power),
                ap.encryption,
                str(len(ap.clients)),
            )

        console.print(table)

        if self.clients:
            ct = Table(title="Clients", show_lines=True)
            ct.add_column("MAC", style="cyan")
            ct.add_column("AP", style="green")
            ct.add_column("PWR", justify="center")
            ct.add_column("Vendor", style="dim")

            for c in self.clients:
                ct.add_row(c.mac, c.ap_bssid, str(c.power), c.vendor)

            console.print(ct)

        console.print(
            f"\n[bold]Found {len(self.access_points)} APs, "
            f"{len(self.clients)} clients[/bold]"
        )

    def to_dict(self) -> dict:
        return {
            "access_points": [
                {
                    "bssid": ap.bssid,
                    "essid": ap.essid,
                    "channel": ap.channel,
                    "power": ap.power,
                    "encryption": ap.encryption,
                    "clients": [
                        {"mac": c.mac, "power": c.power, "vendor": c.vendor}
                        for c in ap.clients
                    ],
                }
                for ap in self.access_points
            ],
        }
