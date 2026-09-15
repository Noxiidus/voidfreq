"""VoidFreq CLI — main entry point."""

from __future__ import annotations

import argparse
import signal
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from . import __version__
from .core.config import load_config, Config, StealthProfile
from .core.interface import InterfaceManager
from .core.opsec import OpsecEngine
from .core.session import SessionManager, Phase
from .core.threat import ThreatDetector
from .modules.recon import ReconModule
from .modules.attack import AttackModule
from .modules.mitm import MitmModule
from .modules.monitor import MonitorModule
from .modules.scanner import ScannerModule
from .modules.eviltwin import EvilTwinModule, EvilTwinConfig
from .modules.dnsspoof import DnsSpoofModule
from .modules.captive import CaptivePortal
from .modules.wordlist import WordlistGenerator, WordlistConfig
from .modules.analyzer import PcapAnalyzer
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

    # scan (network scanner)
    scan = sub.add_parser("scan", help="Network host/port scanning")
    scan.add_argument("-t", "--target", help="Target IP or subnet (e.g. 192.168.1.0/24)")
    scan.add_argument("-p", "--ports", default="1-1000", help="Port range (default: 1-1000)")
    scan.add_argument("--discover", action="store_true", help="Host discovery only")
    scan.add_argument("--vuln", action="store_true", help="Vulnerability scan")
    scan.add_argument("--os", action="store_true", help="OS detection")

    # mitm
    mitm = sub.add_parser("mitm", help="Man-in-the-Middle attack")
    mitm.add_argument("-t", "--target", required=True, help="Target IP")
    mitm.add_argument("-g", "--gateway", required=True, help="Gateway IP")
    mitm.add_argument("--dashboard", action="store_true", help="Show live dashboard")
    mitm.add_argument("--dns-spoof", nargs=2, action="append", metavar=("DOMAIN", "IP"),
                       help="DNS spoof rule (can repeat)")

    # eviltwin
    et = sub.add_parser("eviltwin", help="Evil Twin rogue AP attack")
    et.add_argument("-e", "--essid", required=True, help="SSID to clone")
    et.add_argument("-ch", "--channel", type=int, required=True, help="Channel")
    et.add_argument("--wpa", help="WPA2 passphrase (omit for open)")
    et.add_argument("--captive", action="store_true", help="Enable captive portal")

    # monitor
    monitor = sub.add_parser("monitor", help="Blue team network monitoring")
    monitor.add_argument("--dashboard", action="store_true", help="Show live dashboard")

    # threat
    threat = sub.add_parser("threat", help="Scan for IDS/WIDS presence")
    threat.add_argument("-g", "--gateway", required=True, help="Gateway IP to scan")

    # auto
    auto = sub.add_parser("auto", help="Full automated attack chain")
    auto.add_argument("-t", "--target", required=True, help="Target AP BSSID")
    auto.add_argument("-ch", "--channel", type=int, required=True, help="Target channel")
    auto.add_argument("--client", help="Target client MAC")
    auto.add_argument("--session", help="Session name (enables save/resume)")
    auto.add_argument("--resume", help="Resume session by ID")

    # session
    session = sub.add_parser("session", help="Manage pentest sessions")
    session.add_argument("--list", action="store_true", help="List saved sessions")
    session.add_argument("--show", help="Show session details by ID")
    session.add_argument("--delete", help="Delete session by ID")
    session.add_argument("--export", help="Export session report by ID")

    # wordlist
    wl = sub.add_parser("wordlist", help="Generate targeted wordlist from ESSID")
    wl.add_argument("-e", "--essid", required=True, help="Target ESSID")
    wl.add_argument("-o", "--output", help="Output file path")
    wl.add_argument("--no-leet", action="store_true", help="Skip leet speak variants")
    wl.add_argument("--no-years", action="store_true", help="Skip year variants")
    wl.add_argument("--words", nargs="+", help="Extra custom words to include")
    wl.add_argument("--min-len", type=int, default=8, help="Minimum password length")
    wl.add_argument("--max-len", type=int, default=63, help="Maximum password length")

    # analyze
    az = sub.add_parser("analyze", help="Analyze a pcap capture file offline")
    az.add_argument("file", help="Path to .pcap/.pcapng file")
    az.add_argument("--export", action="store_true", help="Export analysis to JSON")

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


def cmd_scan(config: Config, args: argparse.Namespace) -> None:
    opsec = OpsecEngine(config)
    scanner = ScannerModule(config, opsec)

    if not args.target:
        console.print("[red]Target required: -t <IP or subnet>[/red]")
        return

    if args.discover:
        scanner.discover_hosts(args.target)
    elif args.vuln:
        scanner.quick_vuln_scan(args.target)
    else:
        scanner.scan_ports(
            args.target, ports=args.ports,
            os_detection=args.os,
        )


def cmd_mitm(config: Config, args: argparse.Namespace) -> None:
    opsec = OpsecEngine(config)
    mitm = MitmModule(config, opsec)
    dns_spoof = None

    if args.dns_spoof:
        dns_spoof = DnsSpoofModule(config, opsec)
        for domain, ip in args.dns_spoof:
            dns_spoof.add_rule(domain, ip)

    def signal_handler(sig, frame):
        mitm.stop()
        mitm.export()
        if dns_spoof:
            dns_spoof.stop()
        opsec.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    mitm.start(config.interface, args.target, args.gateway)

    if dns_spoof:
        dns_spoof.start(config.interface)

    if args.dashboard:
        mitm.live_dashboard()
    else:
        console.print("[dim]Press Ctrl+C to stop...[/dim]")
        signal.pause()


def cmd_eviltwin(config: Config, args: argparse.Namespace) -> None:
    opsec = OpsecEngine(config)
    et = EvilTwinModule(config, opsec)
    portal = None

    twin_config = EvilTwinConfig(
        essid=args.essid,
        channel=args.channel,
        interface=config.interface,
        encryption="wpa2" if args.wpa else "open",
        wpa_passphrase=args.wpa,
        captive_portal=args.captive,
    )

    def signal_handler(sig, frame):
        if portal:
            portal.export()
            portal.stop()
        et.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    if et.start(twin_config):
        if args.captive:
            portal = CaptivePortal(listen_ip=twin_config.gateway_ip)
            portal.start()

        console.print("[dim]Press Ctrl+C to stop...[/dim]")
        signal.pause()


def cmd_monitor(config: Config, args: argparse.Namespace) -> None:
    monitor = MonitorModule(config)

    def signal_handler(sig, frame):
        monitor.stop()
        monitor.export_alerts()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    monitor.start(config.interface)

    if args.dashboard:
        monitor.live_dashboard()
    else:
        console.print("[dim]Press Ctrl+C to stop...[/dim]")
        signal.pause()


def cmd_threat(config: Config, args: argparse.Namespace) -> None:
    detector = ThreatDetector(config)
    indicators = detector.scan_once(config.interface, args.gateway)

    if not indicators:
        console.print("[green bold]No threats detected — environment appears clean[/green bold]")
    else:
        console.print(f"\n[bold]Risk level: {detector.risk_level}[/bold]")


def cmd_auto(config: Config, args: argparse.Namespace) -> None:
    console.print("[bold cyan]Starting automated attack chain...[/bold cyan]")

    opsec = OpsecEngine(config)
    iface_mgr = InterfaceManager(config.interface)
    session_mgr = SessionManager()
    session = None

    if args.resume:
        session = session_mgr.load(args.resume)
        if not session:
            return
        console.print(f"[green]Resuming from phase: {session.phase}[/green]")
    elif args.session:
        session = session_mgr.create(
            name=args.session,
            target_bssid=args.target,
            target_channel=args.channel,
            stealth_level=config.stealth_level,
        )

    # Threat check first
    console.rule("[bold]Phase 0: Threat Assessment[/bold]")
    detector = ThreatDetector(config)

    def killswitch():
        console.print("[red bold]KILL SWITCH — aborting all operations[/red bold]")
        iface_mgr.disable_monitor_mode()
        opsec.cleanup()
        sys.exit(1)

    detector.set_killswitch(killswitch)

    monitor_iface = iface_mgr.enable_monitor_mode()
    if not monitor_iface:
        return

    scan_data = None
    capture_data = None
    crack_data = None
    network_data = None

    skip_to = session.phase if session else Phase.INIT.value

    try:
        # Phase 1: Recon
        if skip_to in (Phase.INIT.value, Phase.RECON.value):
            console.rule("[bold]Phase 1: Reconnaissance[/bold]")
            recon = ReconModule(config, opsec)
            recon.scan(monitor_iface, duration=15)
            scan_data = recon.to_dict()

            if session:
                session_mgr.update_phase(session, Phase.RECON, recon_data=scan_data)

        # Phase 2: Capture
        if skip_to in (Phase.INIT.value, Phase.RECON.value, Phase.CAPTURE.value):
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

            if session:
                session_mgr.update_phase(
                    session, Phase.CAPTURE,
                    captured_file=capture.capture_file,
                    capture_strategy=capture.strategy.value,
                )

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

                if session:
                    session_mgr.update_phase(
                        session, Phase.CRACK,
                        cracked_password=result.password,
                        crack_method=result.method,
                    )

        # Phase 4: Network scan (if we cracked the password)
        if crack_data and crack_data.get("success"):
            iface_mgr.disable_monitor_mode()

            console.rule("[bold]Phase 4: Network Enumeration[/bold]")
            scanner = ScannerModule(config, opsec)
            gateway = _detect_gateway()
            if gateway:
                subnet = ".".join(gateway.split(".")[:3]) + ".0/24"
                scanner.discover_hosts(subnet)
                network_data = scanner.to_dict()

                if session:
                    session_mgr.update_phase(
                        session, Phase.ACCESS,
                        network_hosts=network_data.get("hosts"),
                    )

        # Report
        console.rule("[bold]Report[/bold]")
        report_path = generate_report(
            scan_data=scan_data,
            capture_data=capture_data,
            crack_data=crack_data,
            fmt=config.report_format,
            output_dir=config.report_dir,
        )
        console.print(f"[green]Report saved: {report_path}[/green]")

        if session:
            session_mgr.update_phase(session, Phase.COMPLETE)
            session_mgr.display(session)

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — saving state...[/yellow]")
        if session:
            session_mgr.save(session)
            console.print(f"[green]Session saved: {session.id}[/green]")
            console.print(f"[dim]Resume with: voidfreq auto --resume {session.id}[/dim]")
    finally:
        iface_mgr.disable_monitor_mode()
        opsec.cleanup()


def _detect_gateway() -> str | None:
    import subprocess
    result = subprocess.run(
        ["ip", "route", "show", "default"],
        capture_output=True, text=True,
    )
    parts = result.stdout.split()
    if "via" in parts:
        idx = parts.index("via")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def cmd_session(config: Config, args: argparse.Namespace) -> None:
    mgr = SessionManager()

    if args.list:
        mgr.list_sessions()
    elif args.show:
        session = mgr.load(args.show)
        if session:
            mgr.display(session)
    elif args.delete:
        mgr.delete(args.delete)
    elif args.export:
        session = mgr.load(args.export)
        if session:
            path = mgr.export_report(session)
            console.print(f"[green]Report exported: {path}[/green]")
    else:
        mgr.list_sessions()


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


def cmd_wordlist(config: Config, args: argparse.Namespace) -> None:
    wl_config = WordlistConfig(
        essid=args.essid,
        include_leet=not args.no_leet,
        include_years=not args.no_years,
        min_length=args.min_len,
        max_length=args.max_len,
        custom_words=args.words,
    )
    gen = WordlistGenerator(wl_config)
    gen.generate()
    path = gen.save(args.output)
    console.print(f"\n[dim]Use with: voidfreq attack -t <BSSID> -ch <CH> -w {path}[/dim]")


def cmd_analyze(config: Config, args: argparse.Namespace) -> None:
    analyzer = PcapAnalyzer()
    analyzer.analyze(args.file)
    if args.export:
        analyzer.export()


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
        config.stealth = StealthProfile(**{
            k: v for k, v in profile_data.items()
            if k in StealthProfile.__dataclass_fields__
        })

    commands = {
        "recon": cmd_recon,
        "attack": cmd_attack,
        "scan": cmd_scan,
        "mitm": cmd_mitm,
        "eviltwin": cmd_eviltwin,
        "monitor": cmd_monitor,
        "threat": cmd_threat,
        "auto": cmd_auto,
        "session": cmd_session,
        "wordlist": cmd_wordlist,
        "analyze": cmd_analyze,
        "opsec": cmd_opsec,
        "check": cmd_check,
    }

    no_root_commands = ("check", "opsec", "session", "wordlist", "analyze")

    if args.command in commands:
        if args.command not in no_root_commands:
            if not check_root():
                sys.exit(1)
        commands[args.command](config, args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
