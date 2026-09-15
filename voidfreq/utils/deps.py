"""Dependency checker and doctor mode — system readiness diagnostics."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys

from rich.console import Console
from rich.panel import Panel
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

VERSION_FLAGS = {
    "aircrack-ng": ["--version"],
    "hashcat": ["--version"],
    "tshark": ["--version"],
    "nmap": ["--version"],
    "hostapd": ["-v"],
    "dnsmasq": ["--version"],
    "tcpdump": ["--version"],
    "hcxdumptool": ["--version"],
    "macchanger": ["--version"],
    "mitmproxy": ["--version"],
}

TOOL_FEATURES = {
    "recon": ["airodump-ng"],
    "attack": ["aireplay-ng", "aircrack-ng"],
    "attack (PMKID)": ["hcxdumptool", "hcxpcapngtool"],
    "attack (GPU)": ["hashcat"],
    "scan": ["nmap"],
    "mitm": ["arpspoof", "tshark"],
    "eviltwin": ["hostapd", "dnsmasq"],
    "monitor": ["tshark"],
    "dns_spoof": ["dnsmasq"],
    "packets (Scapy)": [],
    "wordlist": [],
    "analyze": ["tshark", "aircrack-ng"],
    "threat": ["nmap", "arping"],
}


def _get_version(tool: str) -> str | None:
    flags = VERSION_FLAGS.get(tool)
    if not flags:
        return None
    try:
        result = subprocess.run(
            [tool] + flags,
            capture_output=True, text=True, timeout=5,
        )
        output = (result.stdout + result.stderr).strip()
        match = re.search(r"(\d+\.\d+[\w.\-]*)", output)
        return match.group(1) if match else output[:40]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


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


def doctor() -> dict:
    """Full system diagnostic — tool versions, interfaces, kernel modules, feature map."""
    from .. import __version__

    results: dict = {
        "passed": 0,
        "warnings": 0,
        "errors": 0,
    }

    # --- System info ---
    console.rule("[bold cyan]System Information[/bold cyan]")
    sys_table = Table(show_header=False, box=None, padding=(0, 2))
    sys_table.add_column("Key", style="bold")
    sys_table.add_column("Value")

    sys_table.add_row("VoidFreq", __version__)
    sys_table.add_row("Python", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    sys_table.add_row("Platform", platform.platform())
    sys_table.add_row("Arch", platform.machine())
    sys_table.add_row("UID", str(os.getuid()))

    if os.getuid() == 0:
        sys_table.add_row("Root", "[green]yes[/green]")
        results["passed"] += 1
    else:
        sys_table.add_row("Root", "[yellow]no — most commands require sudo[/yellow]")
        results["warnings"] += 1

    console.print(sys_table)

    # --- Tool versions ---
    console.rule("[bold cyan]Tool Versions[/bold cyan]")
    tool_table = Table(show_lines=True)
    tool_table.add_column("Tool", style="cyan")
    tool_table.add_column("Path")
    tool_table.add_column("Version")
    tool_table.add_column("Status")

    all_tools = {**REQUIRED, **OPTIONAL}
    for tool, _desc in all_tools.items():
        path = shutil.which(tool)
        version = _get_version(tool) if path else None
        required = tool in REQUIRED

        if path:
            tool_table.add_row(
                tool,
                path,
                version or "[dim]—[/dim]",
                "[green]OK[/green]",
            )
            results["passed"] += 1
        elif required:
            tool_table.add_row(
                tool,
                "[red]not found[/red]",
                "—",
                "[red]MISSING (required)[/red]",
            )
            results["errors"] += 1
        else:
            tool_table.add_row(
                tool,
                "[yellow]not found[/yellow]",
                "—",
                "[yellow]optional[/yellow]",
            )
            results["warnings"] += 1

    console.print(tool_table)

    # --- WiFi interfaces ---
    console.rule("[bold cyan]WiFi Interfaces[/bold cyan]")
    _doctor_interfaces(results)

    # --- Kernel modules ---
    console.rule("[bold cyan]Kernel Modules[/bold cyan]")
    _doctor_kernel(results)

    # --- Python packages ---
    console.rule("[bold cyan]Python Packages[/bold cyan]")
    _doctor_python(results)

    # --- Feature availability ---
    console.rule("[bold cyan]Feature Availability[/bold cyan]")
    feat_table = Table(show_lines=True)
    feat_table.add_column("Feature", style="cyan")
    feat_table.add_column("Required tools")
    feat_table.add_column("Status")

    for feature, tools in TOOL_FEATURES.items():
        if not tools:
            feat_table.add_row(feature, "[dim]built-in[/dim]", "[green]available[/green]")
            results["passed"] += 1
            continue

        missing = [t for t in tools if shutil.which(t) is None]
        if not missing:
            feat_table.add_row(
                feature,
                ", ".join(tools),
                "[green]available[/green]",
            )
            results["passed"] += 1
        else:
            feat_table.add_row(
                feature,
                ", ".join(tools),
                f"[yellow]missing: {', '.join(missing)}[/yellow]",
            )
            results["warnings"] += 1

    console.print(feat_table)

    # --- Config check ---
    console.rule("[bold cyan]Configuration[/bold cyan]")
    _doctor_config(results)

    # --- Summary ---
    console.rule("[bold cyan]Summary[/bold cyan]")
    p = results["passed"]
    w = results["warnings"]
    e = results["errors"]

    if e == 0 and w == 0:
        console.print(Panel(
            f"[green bold]All checks passed ({p} OK)[/green bold]\n"
            "[dim]System is ready for operations.[/dim]",
            border_style="green",
        ))
    elif e == 0:
        console.print(Panel(
            f"[yellow bold]{p} passed, {w} warnings[/yellow bold]\n"
            "[dim]System is operational with reduced capability.[/dim]",
            border_style="yellow",
        ))
    else:
        console.print(Panel(
            f"[red bold]{e} errors, {w} warnings, {p} passed[/red bold]\n"
            "[dim]Fix errors before running operations.[/dim]",
            border_style="red",
        ))

    return results


def _doctor_interfaces(results: dict) -> None:
    ifaces = []

    iw_path = shutil.which("iw")
    iwconfig_path = shutil.which("iwconfig")

    if iw_path:
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True,
        )
        current_iface = None
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("Interface"):
                current_iface = line.split()[-1]
            elif current_iface and "type" in line:
                mode = line.split()[-1]
                ifaces.append((current_iface, mode))
                current_iface = None
    elif iwconfig_path:
        result = subprocess.run(
            ["iwconfig"], capture_output=True, text=True,
        )
        for line in result.stdout.split("\n"):
            match = re.match(r"^(\w+)\s+.*Mode:(\w+)", line)
            if match:
                ifaces.append((match.group(1), match.group(2).lower()))

    if ifaces:
        table = Table(show_lines=True)
        table.add_column("Interface", style="cyan")
        table.add_column("Mode")
        table.add_column("Monitor capable")

        for name, mode in ifaces:
            monitor_cap = _check_monitor_capable(name)
            table.add_row(
                name,
                mode,
                "[green]yes[/green]" if monitor_cap else "[yellow]unknown[/yellow]",
            )
            results["passed"] += 1

        console.print(table)
    else:
        console.print("[yellow]No wireless interfaces detected[/yellow]")
        console.print("[dim]Plug in a WiFi adapter (Atheros AR9271 or Realtek RTL8812AU recommended)[/dim]")
        results["warnings"] += 1


def _check_monitor_capable(interface: str) -> bool:
    if not shutil.which("iw"):
        return False
    result = subprocess.run(
        ["iw", "phy"], capture_output=True, text=True,
    )
    return "monitor" in result.stdout.lower()


def _doctor_kernel(results: dict) -> None:
    if platform.system() != "Linux":
        console.print("[dim]Kernel module check skipped (not Linux)[/dim]")
        return

    modules_to_check = [
        ("cfg80211", "WiFi configuration framework"),
        ("mac80211", "WiFi MAC layer"),
        ("ath9k_htc", "Atheros AR9271 driver"),
        ("88XXau", "Realtek RTL8812AU driver"),
        ("rtl8812au", "Realtek RTL8812AU driver (alt)"),
    ]

    result = subprocess.run(["lsmod"], capture_output=True, text=True)
    loaded = result.stdout.lower()

    table = Table(show_lines=True)
    table.add_column("Module", style="cyan")
    table.add_column("Purpose", style="dim")
    table.add_column("Status")

    for mod, desc in modules_to_check:
        if mod.lower() in loaded:
            table.add_row(mod, desc, "[green]loaded[/green]")
            results["passed"] += 1
        else:
            table.add_row(mod, desc, "[dim]not loaded[/dim]")

    console.print(table)


def _doctor_python(results: dict) -> None:
    packages = {
        "scapy": "scapy",
        "rich": "rich",
        "yaml": "pyyaml",
        "netifaces": "netifaces",
        "mac_vendor_lookup": "mac-vendor-lookup",
        "nmap": "python-nmap",
        "requests": "requests",
    }

    table = Table(show_lines=True)
    table.add_column("Package", style="cyan")
    table.add_column("Import", style="dim")
    table.add_column("Version")
    table.add_column("Status")

    for import_name, pip_name in packages.items():
        try:
            mod = __import__(import_name)
            version = getattr(mod, "__version__", getattr(mod, "VERSION", "—"))
            table.add_row(pip_name, import_name, str(version), "[green]OK[/green]")
            results["passed"] += 1
        except ImportError:
            table.add_row(pip_name, import_name, "—", "[red]MISSING[/red]")
            results["errors"] += 1

    console.print(table)


def _doctor_config(results: dict) -> None:
    from ..core.config import ConfigError, load_config

    config_paths = ["config.yaml", "config.yml", os.path.expanduser("~/.voidfreq/config.yaml")]
    found_config = None

    for path in config_paths:
        if os.path.exists(path):
            found_config = path
            break

    if found_config:
        try:
            config = load_config(found_config)
            console.print(f"[green]Config loaded: {found_config}[/green]")
            console.print(f"  Interface: {config.interface}")
            console.print(f"  Stealth: {config.stealth_level}")
            console.print(f"  Wordlist: {config.wordlist}")

            if os.path.exists(config.wordlist):
                console.print("  Wordlist file: [green]exists[/green]")
                results["passed"] += 1
            else:
                console.print("  Wordlist file: [yellow]not found — cracking will need a wordlist path[/yellow]")
                results["warnings"] += 1

            results["passed"] += 1
        except ConfigError as e:
            console.print(f"[red]Config error in {found_config}: {e}[/red]")
            results["errors"] += 1
    else:
        console.print("[dim]No config file found — defaults will be used[/dim]")
        results["passed"] += 1


def check_root() -> bool:
    if os.geteuid() != 0:
        console.print("[red]VoidFreq requires root privileges. Run with sudo.[/red]")
        return False
    return True


def check_interface(interface: str) -> bool:
    result = subprocess.run(
        ["iwconfig", interface], capture_output=True, text=True,
    )
    if result.returncode != 0:
        console.print(f"[red]Interface {interface} not found or not wireless[/red]")
        return False
    return True
