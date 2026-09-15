"""OPSEC Engine — stealth layer that runs beneath every operation."""

from __future__ import annotations

import random
import subprocess
import time
from dataclasses import dataclass, field

from rich.console import Console

from .config import Config

console = Console()

COMMON_VENDORS = [
    "00:1A:2B",  # Ayecom
    "3C:5A:B4",  # Google
    "AC:37:43",  # HTC
    "F0:D5:BF",  # Apple
    "DC:A6:32",  # Raspberry Pi
    "B8:27:EB",  # Raspberry Pi (older)
    "00:0C:29",  # VMware
    "48:D7:05",  # Samsung
    "FC:F5:C4",  # Samsung
    "98:01:A7",  # Apple
]

WINDOWS_HOSTNAMES = [
    "DESKTOP-{}", "LAPTOP-{}", "WIN-{}", "WORKSTATION-{}",
]
ANDROID_HOSTNAMES = [
    "android-{}", "Galaxy-S{}", "Pixel-{}", "OnePlus-{}",
]


def _random_hex(n: int) -> str:
    return "".join(f"{random.randint(0, 255):02x}" for _ in range(n))


def _random_hostname() -> str:
    pool = WINDOWS_HOSTNAMES + ANDROID_HOSTNAMES
    template = random.choice(pool)
    suffix = _random_hex(4).upper()
    return template.format(suffix)


@dataclass
class OpsecState:
    """Tracks original values for cleanup."""
    original_mac: str | None = None
    original_hostname: str | None = None
    current_mac: str | None = None
    interface: str = "wlan0"
    modifications: list[str] = field(default_factory=list)


class OpsecEngine:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.profile = config.stealth
        self.state = OpsecState(interface=config.interface)

    def _run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def save_original_state(self) -> None:
        result = self._run(["ip", "link", "show", self.state.interface], check=False)
        if result.returncode == 0:
            for part in result.stdout.split():
                if ":" in part and len(part) == 17:
                    self.state.original_mac = part
                    break

        result = self._run(["hostname"], check=False)
        if result.returncode == 0:
            self.state.original_hostname = result.stdout.strip()

    def rotate_mac(self) -> str | None:
        if not self.profile.mac_rotation:
            return None

        vendor = random.choice(COMMON_VENDORS)
        device_part = _random_hex(3)
        new_mac = f"{vendor}:{device_part[0:2]}:{device_part[2:4]}:{device_part[4:6]}"

        console.print(f"[dim]OPSEC: MAC rotation → {new_mac}[/dim]")

        self._run(["sudo", "ip", "link", "set", self.state.interface, "down"], check=False)
        result = self._run(
            ["sudo", "ip", "link", "set", self.state.interface, "address", new_mac],
            check=False,
        )
        self._run(["sudo", "ip", "link", "set", self.state.interface, "up"], check=False)

        if result.returncode == 0:
            self.state.current_mac = new_mac
            self.state.modifications.append(f"mac:{new_mac}")
            return new_mac
        else:
            console.print(f"[red]OPSEC: MAC rotation failed: {result.stderr.strip()}[/red]")
            return None

    def spoof_hostname(self) -> str | None:
        new_hostname = _random_hostname()
        console.print(f"[dim]OPSEC: hostname → {new_hostname}[/dim]")

        result = self._run(["sudo", "hostnamectl", "set-hostname", new_hostname], check=False)
        if result.returncode == 0:
            self.state.modifications.append(f"hostname:{new_hostname}")
            return new_hostname
        return None

    def jitter(self, base_delay: float = 1.0) -> None:
        if not self.profile.timing_jitter:
            return
        delay = base_delay + random.uniform(0, base_delay * 0.5)
        time.sleep(delay)

    def pre_operation(self) -> None:
        """Run before every major operation."""
        self.save_original_state()

        if self.profile.mac_rotation:
            self.rotate_mac()

        if self.profile.timing_jitter:
            self.jitter(0.5)

    def cleanup(self) -> None:
        """Restore everything to original state."""
        console.print("[yellow]OPSEC: cleaning up...[/yellow]")

        if self.state.original_mac:
            self._run(["sudo", "ip", "link", "set", self.state.interface, "down"], check=False)
            self._run(
                ["sudo", "ip", "link", "set", self.state.interface,
                 "address", self.state.original_mac],
                check=False,
            )
            self._run(["sudo", "ip", "link", "set", self.state.interface, "up"], check=False)
            console.print(f"[dim]OPSEC: MAC restored → {self.state.original_mac}[/dim]")

        if self.state.original_hostname:
            self._run(
                ["sudo", "hostnamectl", "set-hostname", self.state.original_hostname],
                check=False,
            )
            console.print(f"[dim]OPSEC: hostname restored → {self.state.original_hostname}[/dim]")

        self._run(["sudo", "ip", "route", "flush", "cache"], check=False)

        console.print("[green]OPSEC: cleanup complete[/green]")

    def status(self) -> dict:
        return {
            "interface": self.state.interface,
            "stealth_level": self.config.stealth_level,
            "original_mac": self.state.original_mac,
            "current_mac": self.state.current_mac,
            "mac_rotation": self.profile.mac_rotation,
            "timing_jitter": self.profile.timing_jitter,
            "fingerprint_spoof": self.profile.fingerprint_spoof,
            "threat_detection": self.profile.threat_detection,
            "killswitch": self.profile.auto_killswitch,
            "modifications": self.state.modifications,
        }
