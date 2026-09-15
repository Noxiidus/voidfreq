"""Wireless interface management — monitor mode, channel control."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from rich.console import Console

console = Console()


@dataclass
class InterfaceInfo:
    name: str
    mode: str
    mac: str
    driver: str | None = None
    monitor_name: str | None = None


class InterfaceManager:
    def __init__(self, interface: str = "wlan0") -> None:
        self.interface = interface
        self.monitor_interface: str | None = None

    def _run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def get_info(self) -> InterfaceInfo | None:
        result = self._run(["iwconfig", self.interface], check=False)
        if result.returncode != 0:
            return None

        mode = "unknown"
        if "Mode:Monitor" in result.stdout:
            mode = "monitor"
        elif "Mode:Managed" in result.stdout:
            mode = "managed"

        mac = ""
        ip_result = self._run(["ip", "link", "show", self.interface], check=False)
        if ip_result.returncode == 0:
            for part in ip_result.stdout.split():
                if ":" in part and len(part) == 17 and part[2] == ":":
                    mac = part
                    break

        return InterfaceInfo(name=self.interface, mode=mode, mac=mac)

    def enable_monitor_mode(self) -> str | None:
        console.print(f"[cyan]Enabling monitor mode on {self.interface}...[/cyan]")

        self._run(["sudo", "airmon-ng", "check", "kill"], check=False)
        result = self._run(["sudo", "airmon-ng", "start", self.interface], check=False)

        if result.returncode != 0:
            console.print(f"[red]Failed to enable monitor mode: {result.stderr}[/red]")
            return None

        for candidate in [f"{self.interface}mon", self.interface]:
            check = self._run(["iwconfig", candidate], check=False)
            if check.returncode == 0 and "Monitor" in check.stdout:
                self.monitor_interface = candidate
                console.print(f"[green]Monitor mode active: {candidate}[/green]")
                return candidate

        console.print("[red]Monitor mode interface not found[/red]")
        return None

    def disable_monitor_mode(self) -> bool:
        iface = self.monitor_interface or f"{self.interface}mon"
        console.print(f"[cyan]Disabling monitor mode on {iface}...[/cyan]")

        result = self._run(["sudo", "airmon-ng", "stop", iface], check=False)
        if result.returncode == 0:
            self.monitor_interface = None
            self._run(["sudo", "systemctl", "restart", "NetworkManager"], check=False)
            console.print("[green]Monitor mode disabled, NetworkManager restarted[/green]")
            return True

        console.print(f"[red]Failed to disable monitor mode: {result.stderr}[/red]")
        return False

    def set_channel(self, channel: int) -> bool:
        iface = self.monitor_interface or self.interface
        result = self._run(
            ["sudo", "iwconfig", iface, "channel", str(channel)],
            check=False,
        )
        return result.returncode == 0

    def set_tx_power(self, dbm: int) -> bool:
        iface = self.monitor_interface or self.interface
        result = self._run(
            ["sudo", "iwconfig", iface, "txpower", f"{dbm}dBm"],
            check=False,
        )
        return result.returncode == 0
