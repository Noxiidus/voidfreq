"""Dependency checker — verifies all required external tools are installed."""

from __future__ import annotations

import shutil

from rich.console import Console
from rich.table import Table

console = Console()

REQUIRED = {
    "aircrack-ng": "WiFi cracking (aircrack-ng suite)",
    "airodump-ng": "WiFi scanning (aircrack-ng suite)",
    "aireplay-ng": "Packet injection (aircrack-ng suite)",
    "airmon-ng": "Monitor mode (aircrack-ng suite)",
}

OPTIONAL = {
    "hcxdumptool": "PMKID capture (silent attack)",
    "hcxpcapngtool": "PCAP to hashcat conversion",
    "hashcat": "GPU-accelerated cracking",
    "bettercap": "MITM framework",
    "tshark": "Packet analysis (Wireshark CLI)",
    "nmap": "Network scanning + vulnerability detection",
    "arpspoof": "ARP spoofing (dsniff suite)",
    "macchanger": "MAC address spoofing",
    "mitmproxy": "HTTPS interception proxy",
    "hostapd": "Evil Twin rogue AP",
    "dnsmasq": "DHCP/DNS for Evil Twin + DNS spoofing",
    "tcpdump": "Traffic capture",
    "arping": "ARP probing (threat detection)",
}


def check_dependencies() -> tuple[list[str], list[str]]:
    missing_required: list[str] = []
    missing_optional: list[str] = []

    table = Table(title="Dependency Check", show_lines=True)
    table.add_column("Tool", style="cyan")
    table.add_column("Status", width=10)
    table.add_column("Purpose", style="dim")
    table.add_column("Required")

    for tool, desc in REQUIRED.items():
        found = shutil.which(tool) is not None
        if not found:
            missing_required.append(tool)
        table.add_row(
            tool,
            "[green]OK[/green]" if found else "[red]MISSING[/red]",
            desc,
            "[bold]YES[/bold]",
        )

    for tool, desc in OPTIONAL.items():
        found = shutil.which(tool) is not None
        if not found:
            missing_optional.append(tool)
        table.add_row(
            tool,
            "[green]OK[/green]" if found else "[yellow]MISSING[/yellow]",
            desc,
            "no",
        )

    console.print(table)

    if missing_required:
        console.print(
            f"\n[red bold]Missing required tools: {', '.join(missing_required)}[/red bold]"
        )
        console.print("[yellow]Install with: sudo apt install aircrack-ng[/yellow]")
    elif missing_optional:
        console.print(
            f"\n[yellow]Missing optional tools: {', '.join(missing_optional)}[/yellow]"
        )
        console.print("[dim]Some features will be unavailable[/dim]")
    else:
        console.print("\n[green bold]All dependencies satisfied![/green bold]")

    return missing_required, missing_optional


def check_root() -> bool:
    import os
    if os.geteuid() != 0:
        console.print("[red]VoidFreq requires root privileges. Run with sudo.[/red]")
        return False
    return True


def check_interface(interface: str) -> bool:
    import subprocess
    result = subprocess.run(
        ["iwconfig", interface], capture_output=True, text=True,
    )
    if result.returncode != 0:
        console.print(f"[red]Interface {interface} not found or not wireless[/red]")
        return False
    return True
