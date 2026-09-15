"""Monitor module — blue team detection for ARP spoofing, deauth, rogue APs."""

from __future__ import annotations

import subprocess
import threading
import time
from collections import defaultdict
from dataclasses import dataclass

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.config import Config

console = Console()


@dataclass
class Alert:
    timestamp: str
    severity: str  # INFO, WARNING, CRITICAL
    alert_type: str
    message: str
    source: str = ""


class MonitorModule:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.alerts: list[Alert] = []
        self.arp_table: dict[str, str] = {}  # IP -> MAC
        self.known_devices: set[str] = set()
        self._running = False
        self._threads: list[threading.Thread] = []

    def start(self, interface: str) -> None:
        self._running = True

        monitors = [
            ("ARP anomaly", self._monitor_arp, interface),
            ("Deauth flood", self._monitor_deauth, interface),
            ("New devices", self._monitor_new_devices, interface),
            ("Rogue AP", self._monitor_rogue_ap, interface),
        ]

        for name, func, iface in monitors:
            t = threading.Thread(target=func, args=(iface,), daemon=True, name=name)
            t.start()
            self._threads.append(t)
            console.print(f"[dim]Monitor started: {name}[/dim]")

        console.print("[green]Blue team monitoring active[/green]")

    def stop(self) -> list[Alert]:
        self._running = False
        return self.alerts

    def _add_alert(
        self, severity: str, alert_type: str, message: str, source: str = "",
    ) -> None:
        alert = Alert(
            timestamp=time.strftime("%H:%M:%S"),
            severity=severity,
            alert_type=alert_type,
            message=message,
            source=source,
        )
        self.alerts.append(alert)

        colors = {"INFO": "blue", "WARNING": "yellow", "CRITICAL": "red bold"}
        color = colors.get(severity, "white")
        console.print(f"[{color}]⚠ [{severity}] {alert_type}: {message}[/{color}]")

    def _monitor_arp(self, interface: str) -> None:
        while self._running:
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True,
            )

            current_table: dict[str, list[str]] = defaultdict(list)
            for line in result.stdout.split("\n"):
                parts = line.split()
                if len(parts) >= 4 and ":" in parts[3]:
                    ip = parts[1].strip("()")
                    mac = parts[3]
                    current_table[mac].append(ip)

            for mac, ips in current_table.items():
                if len(ips) > 1:
                    self._add_alert(
                        "CRITICAL",
                        "ARP_SPOOF",
                        f"MAC {mac} claims multiple IPs: {', '.join(ips)} "
                        f"— possible ARP spoofing!",
                        source=mac,
                    )

            for ip in set(
                ip for ips in current_table.values() for ip in ips
            ):
                mac_for_ip = [
                    mac for mac, ips in current_table.items() if ip in ips
                ]
                if ip in self.arp_table and self.arp_table[ip] not in mac_for_ip:
                    self._add_alert(
                        "CRITICAL",
                        "ARP_CHANGE",
                        f"IP {ip} changed MAC: {self.arp_table[ip]} → {mac_for_ip[0]}",
                        source=ip,
                    )

            for mac, ips in current_table.items():
                for ip in ips:
                    self.arp_table[ip] = mac

            time.sleep(5)

    def _monitor_deauth(self, interface: str) -> None:
        proc = subprocess.Popen(
            ["sudo", "tshark",
             "-i", interface,
             "-Y", "wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a",
             "-T", "fields",
             "-e", "wlan.sa",
             "-e", "wlan.da",
             "-l"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        deauth_counts: dict[str, int] = defaultdict(int)
        window_start = time.time()

        while self._running and proc.poll() is None:
            line = proc.stdout.readline().strip()
            if not line:
                continue

            parts = line.split("\t")
            source = parts[0] if parts else "unknown"
            deauth_counts[source] += 1

            if time.time() - window_start > 10:
                for src, count in deauth_counts.items():
                    if count > 5:
                        self._add_alert(
                            "CRITICAL",
                            "DEAUTH_FLOOD",
                            f"{count} deauth frames from {src} in 10s — attack in progress!",
                            source=src,
                        )
                deauth_counts.clear()
                window_start = time.time()

        proc.terminate()

    def _monitor_new_devices(self, interface: str) -> None:
        while self._running:
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True,
            )

            for line in result.stdout.split("\n"):
                parts = line.split()
                if len(parts) >= 4 and ":" in parts[3]:
                    mac = parts[3]
                    ip = parts[1].strip("()")
                    if mac not in self.known_devices:
                        self.known_devices.add(mac)
                        if len(self.known_devices) > 1:
                            self._add_alert(
                                "WARNING",
                                "NEW_DEVICE",
                                f"New device joined: {mac} ({ip})",
                                source=mac,
                            )

            time.sleep(10)

    def _monitor_rogue_ap(self, interface: str) -> None:
        """Detect rogue APs: duplicate SSIDs on different BSSIDs, and Evil Twin (same SSID+channel, different BSSID)."""
        proc = subprocess.Popen(
            ["sudo", "tshark",
             "-i", interface,
             "-Y", "wlan.fc.type_subtype == 0x08",
             "-T", "fields",
             "-e", "wlan.sa",
             "-e", "wlan.ssid",
             "-e", "wlan_radio.channel",
             "-l"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        ssid_bssids: dict[str, set[str]] = defaultdict(set)
        ssid_channel_bssids: dict[tuple[str, str], set[str]] = defaultdict(set)

        while self._running and proc.poll() is None:
            line = proc.stdout.readline().strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue

            bssid = parts[0]
            ssid = parts[1]
            channel = parts[2] if len(parts) > 2 else ""

            if not ssid or ssid == "\\x00":
                continue

            prev_count = len(ssid_bssids[ssid])
            ssid_bssids[ssid].add(bssid)

            if len(ssid_bssids[ssid]) > 1 and prev_count < len(ssid_bssids[ssid]):
                self._add_alert(
                    "WARNING",
                    "ROGUE_AP",
                    f'SSID "{ssid}" seen on {len(ssid_bssids[ssid])} BSSIDs — possible rogue AP: '
                    f'{", ".join(ssid_bssids[ssid])}',
                    source=bssid,
                )

            if channel:
                key = (ssid, channel)
                prev_ch_count = len(ssid_channel_bssids[key])
                ssid_channel_bssids[key].add(bssid)

                if len(ssid_channel_bssids[key]) > 1 and prev_ch_count < len(ssid_channel_bssids[key]):
                    self._add_alert(
                        "CRITICAL",
                        "EVIL_TWIN",
                        f'SSID "{ssid}" on channel {channel} from multiple BSSIDs — '
                        f'Evil Twin attack likely: {", ".join(ssid_channel_bssids[key])}',
                        source=bssid,
                    )

        proc.terminate()

    def live_dashboard(self) -> None:
        def build_panel() -> Panel:
            table = Table(show_header=True, expand=True)
            table.add_column("Time", style="dim", width=10)
            table.add_column("Sev", width=10)
            table.add_column("Type", width=16)
            table.add_column("Message", style="white")

            for alert in self.alerts[-25:]:
                colors = {"INFO": "blue", "WARNING": "yellow", "CRITICAL": "red"}
                sev_text = Text(alert.severity, style=colors.get(alert.severity, "white"))
                table.add_row(
                    alert.timestamp, sev_text, alert.alert_type, alert.message,
                )

            stats = (
                f"Devices: {len(self.known_devices)} | "
                f"Alerts: {len(self.alerts)} | "
                f"Critical: {sum(1 for a in self.alerts if a.severity == 'CRITICAL')}"
            )

            return Panel(
                table,
                title="[bold]VoidFreq Monitor — Blue Team Dashboard[/bold]",
                subtitle=stats,
                border_style="blue",
            )

        with Live(build_panel(), refresh_per_second=1, console=console) as live:
            while self._running:
                time.sleep(1)
                live.update(build_panel())

    def export_alerts(self, output_dir: str = "./reports") -> str:
        import json
        import os

        os.makedirs(output_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(output_dir, f"monitor_alerts_{ts}.json")

        data = {
            "alerts": [
                {
                    "timestamp": a.timestamp,
                    "severity": a.severity,
                    "type": a.alert_type,
                    "message": a.message,
                    "source": a.source,
                }
                for a in self.alerts
            ],
            "known_devices": list(self.known_devices),
            "stats": {
                "total_alerts": len(self.alerts),
                "critical": sum(1 for a in self.alerts if a.severity == "CRITICAL"),
                "warnings": sum(1 for a in self.alerts if a.severity == "WARNING"),
            },
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        return path
