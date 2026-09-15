"""VoidFreq CLI — main entry point."""

from __future__ import annotations

import argparse
import signal
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from . import __version__
from .core.config import load_config, Config
from .core.interface import InterfaceManager
from .core.opsec import OpsecEngine
from .modules.recon import ReconModule
from .modules.attack import AttackModule
from .modules.mitm import MitmModule
from .modules.monitor import MonitorModule
from .utils.deps import check_dependencies, check_root, check_interface
from .utils.report import generate_report

console = Console()

BANNER = r"""
 ██╗   ██╗ ██████╗ ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗
 ██║   ██║██╔═══██╗██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗
 ██║   ██║██║   ██║██║██║  ██║█████╗  ██████╔╝█████╗  ██║   ██║
 ╚██╗ ██╔╝██║   ██║██║██║  ██║██╔══╝  ██╔══██╗██╔══╝  ██║▄▄ ██║
  ╚████╔╝ ╚██████╔╝██║██████╔╝██║     ██║  ██║███████╗╚██████╔╝
   ╚═══╝   ╚═════╝ ╚═╝╚═════╝ ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚══▀▀═╝
"""


def print_banner() -> None:
    console.print(Panel(
        Text(BANNER, style="bold red") +
        Text(f"\n  WiFi Red/Blue Team Framework v{__version__}", style="dim"),
        border_style="red",
        subtitle="[dim]github.com/Noxiidus/voidfreq[/dim]",
    ))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="voidfreq",
        description="WiFi Red/Blue Team Framework",
    )
    parser.add_argument("-V", "--version", action="version", version=f"voidfreq {__version__}")
    parser.add_argument("-c", "--config", default="config.yaml", help="Config file path")
    parser.add_argument("-i", "--interface", help="WiFi interface override")
    parser.add_argument("-s", "--stealth", choices=["low", "medium", "high", "ghost"],
                        help="Stealth level override")

    sub = parser.add_subparsers(dest="command")

    # recon
    recon = sub.add_parser("recon", help="Passive WiFi reconnaissance")
    recon.add_argument("-d", "--duration", type=int, default=30, help="Scan duration (seconds)")

    # attack
    attack = sub.add_parser("attack", help="WPA handshake/PMKID capture + crack")
    attack.add_argument("-t", "--target", required=True, help="Target AP BSSID")
    attack.add_argument("-ch", "--channel", type=int, required=True, help="Target channel")
    attack.add_argument("--client", help="Target client MAC (for deauth)")
    attack.add_argument("--no-crack", action="store_true", help="Capture only, skip cracking")
    attack.add_argument("-o", "--output", default="./captures", help="Output directory")

    # mitm
    mitm = sub.add_parser("mitm", help="Man-in-the-Middle attack")
    mitm.add_argument("-t", "--target", required=True, help="Target IP")
    mitm.add_argument("-g", "--gateway", required=True, help="Gateway IP")
    mitm.add_argument("--dashboard", action="store_true", help="Show live dashboard")

    # monitor
    monitor = sub.add_parser("monitor", help="Blue team network monitoring")
    monitor.add_argument("--dashboard", action="store_true", help="Show live dashboard")

    # auto
    auto = sub.add_parser("auto", help="Full automated attack chain")
    auto.add_argument("-t", "--target", required=True, help="Target AP BSSID")
    auto.add_argument("-ch", "--channel", type=int, required=True, help="Target channel")
    auto.add_argument("--client", help="Target client MAC")

    # opsec
    opsec = sub.add_parser("opsec", help="OPSEC status and cleanup")
    opsec.add_argument("--status", action="store_true", help="Show OPSEC status")
    opsec.add_argument("--cleanup", action="store_true", help="Restore original state")

    # check
    sub.add_parser("check", help="Check dependencies and system readiness")

    return parser


def cmd_recon(config: Config, args: argparse.Namespace) -> None:
    opsec = OpsecEngine(config)
    iface_mgr = InterfaceManager(config.interface)

    monitor_iface = iface_mgr.enable_monitor_mode()
    if not monitor_iface:
        return

    try:
        recon = ReconModule(config, opsec)
        recon.scan(monitor_iface, duration=args.duration)
    finally:
        iface_mgr.disable_monitor_mode()
        opsec.cleanup()


def cmd_attack(config: Config, args: argparse.Namespace) -> None:
    opsec = OpsecEngine(config)
    iface_mgr = InterfaceManager(config.interface)

    monitor_iface = iface_mgr.enable_monitor_mode()
    if not monitor_iface:
        return

    try:
        attack = AttackModule(config, opsec)
        capture = attack.capture(
            monitor_iface, args.target, args.channel,
            client_mac=args.client, output_dir=args.output,
        )

        if capture.success and not args.no_crack:
            result = attack.crack(capture)
            if result.success:
                console.print(f"\n[green bold]Password: {result.password}[/green bold]")
            else:
                console.print(f"\n[yellow]{result.message}[/yellow]")
    finally:
        iface_mgr.disable_monitor_mode()
        opsec.cleanup()


def cmd_mitm(config: Config, args: argparse.Namespace) -> None:
    opsec = OpsecEngine(config)
    mitm = MitmModule(config, opsec)

    def signal_handler(sig, frame):
        traffic = mitm.stop()
        mitm.export()
        opsec.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    mitm.start(config.interface, args.target, args.gateway)

    if args.dashboard:
        mitm.live_dashboard()
    else:
        console.print("[dim]Press Ctrl+C to stop...[/dim]")
        signal.pause()


def cmd_monitor(config: Config, args: argparse.Namespace) -> None:
    monitor = MonitorModule(config)

    def signal_handler(sig, frame):
        alerts = monitor.stop()
        monitor.export_alerts()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    monitor.start(config.interface)

    if args.dashboard:
        monitor.live_dashboard()
    else:
        console.print("[dim]Press Ctrl+C to stop...[/dim]")
        signal.pause()


def cmd_auto(config: Config, args: argparse.Namespace) -> None:
    console.print("[bold cyan]Starting automated attack chain...[/bold cyan]")

    opsec = OpsecEngine(config)
    iface_mgr = InterfaceManager(config.interface)

    monitor_iface = iface_mgr.enable_monitor_mode()
    if not monitor_iface:
        return

    scan_data = None
    capture_data = None
    crack_data = None

    try:
        # Phase 1: Recon
        console.rule("[bold]Phase 1: Reconnaissance[/bold]")
        recon = ReconModule(config, opsec)
        recon.scan(monitor_iface, duration=15)
        scan_data = recon.to_dict()

        # Phase 2: Capture
        console.rule("[bold]Phase 2: Capture[/bold]")
        attack = AttackModule(config, opsec)
        capture = attack.capture(
            monitor_iface, args.target, args.channel,
            client_mac=args.client,
        )
        capture_data = {
            "success": capture.success,
            "strategy": capture.strategy.value,
            "file": capture.capture_file,
        }

        # Phase 3: Crack
        if capture.success:
            console.rule("[bold]Phase 3: Cracking[/bold]")
            result = attack.crack(capture)
            crack_data = {
                "success": result.success,
                "password": result.password,
                "method": result.method,
            }

            if result.success:
                console.print(f"\n[green bold]Password found: {result.password}[/green bold]")

        # Report
        console.rule("[bold]Report[/bold]")
        generate_report(
            scan_data=scan_data,
            capture_data=capture_data,
            crack_data=crack_data,
            fmt=config.report_format,
            output_dir=config.report_dir,
        )

    finally:
        iface_mgr.disable_monitor_mode()
        opsec.cleanup()


def cmd_opsec(config: Config, args: argparse.Namespace) -> None:
    opsec = OpsecEngine(config)

    if args.cleanup:
        opsec.save_original_state()
        opsec.cleanup()
    else:
        status = opsec.status()
        from rich.table import Table
        table = Table(title="OPSEC Status")
        table.add_column("Setting", style="cyan")
        table.add_column("Value")

        for key, value in status.items():
            table.add_row(key, str(value))

        console.print(table)


def cmd_check(config: Config, args: argparse.Namespace) -> None:
    check_dependencies()


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    print_banner()

    config = load_config(args.config)

    if args.interface:
        config.interface = args.interface
    if args.stealth:
        config.stealth_level = args.stealth
        profiles = config.raw.get("voidfreq", {}).get("stealth_profiles", {})
        profile_data = profiles.get(args.stealth, {})
        from .core.config import StealthProfile
        config.stealth = StealthProfile(**{
            k: v for k, v in profile_data.items()
            if k in StealthProfile.__dataclass_fields__
        })

    commands = {
        "recon": cmd_recon,
        "attack": cmd_attack,
        "mitm": cmd_mitm,
        "monitor": cmd_monitor,
        "auto": cmd_auto,
        "opsec": cmd_opsec,
        "check": cmd_check,
    }

    if args.command in commands:
        if args.command not in ("check", "opsec"):
            if not check_root():
                sys.exit(1)
        commands[args.command](config, args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
