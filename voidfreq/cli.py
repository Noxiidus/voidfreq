"""VoidFreq CLI — main entry point."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from . import __version__
from .core.alerts import AlertManager
from .core.config import Config, StealthProfile, load_config
from .core.interface import InterfaceManager
from .core.opsec import OpsecEngine
from .core.plugins import PluginManager
from .core.session import Phase, SessionManager
from .core.threat import ThreatDetector
from .modules.analyzer import PcapAnalyzer
from .modules.attack import AttackModule
from .modules.bluetooth import BluetoothModule
from .modules.captive import CaptivePortal
from .modules.dnsspoof import DnsSpoofModule
from .modules.enterprise import EnterpriseModule
from .modules.eviltwin import EvilTwinConfig, EvilTwinModule
from .modules.karma import KarmaConfig, KarmaModule
from .modules.mitm import MitmModule
from .modules.monitor import MonitorModule
from .modules.osint import OsintModule
from .modules.packets import detect_pmf
from .modules.proxy import ProxyModule
from .modules.recon import ReconModule
from .modules.scanner import ScannerModule
from .modules.wordlist import WordlistConfig, WordlistGenerator
from .modules.wpa3 import Wpa3Module
from .modules.wps import WpsModule
from .utils.deps import check_dependencies, check_root, doctor
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
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  voidfreq recon -d 60                              # Scan for 60 seconds
  voidfreq attack -t AA:BB:CC:DD:EE:FF -ch 6       # Capture + crack
  voidfreq scan -t 192.168.1.0/24 --discover        # Host discovery
  voidfreq mitm -t 192.168.1.5 -g 192.168.1.1       # ARP spoof MITM
  voidfreq wps pixie -t AA:BB:CC:DD:EE:FF -ch 6     # WPS Pixie Dust
  voidfreq proxy --dashboard                         # HTTPS proxy
  voidfreq karma -ch 6 --captive                     # Karma with portal
  voidfreq osint -t AA:BB:CC:DD:EE:FF -e TestNet    # Passive OSINT
  voidfreq monitor --dashboard                       # Blue team monitor
  voidfreq attack -t ... -ch 6 --wpa3-check --evasion # WPA3-aware + IDS evasion
  voidfreq wpa3 detect -t AA:BB:CC:DD:EE:FF          # WPA3/SAE detection
  voidfreq wpa3 downgrade -t AA:BB:CC:DD:EE:FF -ch 6 # Transition mode downgrade
  voidfreq enterprise detect -t AA:BB:CC:DD:EE:FF    # EAP type detection
  voidfreq enterprise wpe -e CorpWiFi -ch 6           # Enterprise evil twin
  voidfreq bt ble -d 30                               # BLE device scan
  voidfreq bt classic                                 # Bluetooth Classic scan
  voidfreq bt gatt AA:BB:CC:DD:EE:FF                  # GATT service enumeration
  voidfreq plugin list                                # List installed plugins
  voidfreq tui                                        # Interactive full-screen TUI
  voidfreq -v attack -t ... -ch 6 --pmf-check        # Verbose + PMF check
  voidfreq doctor                                    # System diagnostic
""",
    )
    parser.add_argument("-V", "--version", action="version", version=f"voidfreq {__version__}")
    parser.add_argument("-c", "--config", default="config.yaml", help="Config file path")
    parser.add_argument("-i", "--interface", help="WiFi interface override")
    parser.add_argument("-s", "--stealth", choices=["low", "medium", "high", "ghost"],
                        help="Stealth level override")
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="store_true",
                           help="Verbose console output (DEBUG level)")
    verbosity.add_argument("-q", "--quiet", action="store_true",
                           help="Quiet mode — only warnings and errors on console")

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
    attack.add_argument("--pmf-check", action="store_true",
                        help="Check PMF before attack to auto-select strategy")
    attack.add_argument("--wpa3-check", action="store_true",
                        help="Check WPA3/SAE before attack to auto-select strategy")
    attack.add_argument("--evasion", action="store_true",
                        help="Use IDS-evasive deauth (randomized reasons, disassoc, rate limiting)")
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
    mitm.add_argument("--ttl-spoof", action="store_true",
                       help="Normalize TTL to hide MITM hop")

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

    # doctor
    sub.add_parser("doctor", help="Full system diagnostic — tools, versions, interfaces, config")

    # wps
    wps = sub.add_parser("wps", help="WPS attacks — Pixie Dust, PIN brute-force")
    wps_sub = wps.add_subparsers(dest="wps_action")

    wps_scan = wps_sub.add_parser("scan", help="Scan for WPS-enabled APs")
    wps_scan.add_argument("-d", "--duration", type=int, default=30, help="Scan duration (seconds)")

    wps_pixie = wps_sub.add_parser("pixie", help="Pixie Dust attack on WPS AP")
    wps_pixie.add_argument("-t", "--target", required=True, help="Target AP BSSID")
    wps_pixie.add_argument("-ch", "--channel", type=int, required=True, help="Target channel")
    wps_pixie.add_argument("--timeout", type=int, default=300, help="Timeout in seconds")

    wps_brute = wps_sub.add_parser("brute", help="WPS PIN brute-force")
    wps_brute.add_argument("-t", "--target", required=True, help="Target AP BSSID")
    wps_brute.add_argument("-ch", "--channel", type=int, required=True, help="Target channel")
    wps_brute.add_argument("--timeout", type=int, default=3600, help="Timeout in seconds")

    # proxy
    proxy = sub.add_parser("proxy", help="HTTPS interception proxy via mitmproxy")
    proxy.add_argument("-p", "--port", type=int, default=8080, help="Proxy listen port")
    proxy.add_argument("--no-transparent", action="store_true", help="Disable transparent mode")
    proxy.add_argument("--dashboard", action="store_true", help="Show live dashboard")

    # karma
    karma = sub.add_parser("karma", help="Karma/MANA rogue AP — respond to all probe requests")
    karma.add_argument("-ch", "--channel", type=int, default=1, help="Channel")
    karma.add_argument("--gateway", default="192.168.99.1", help="Gateway IP for karma AP")
    karma.add_argument("--loud", action="store_true", default=True, help="MANA loud mode (default)")
    karma.add_argument("--no-loud", action="store_true", help="Disable MANA loud mode")
    karma.add_argument("--captive", action="store_true", help="Enable captive portal redirect")
    karma.add_argument("--dashboard", action="store_true", help="Show live probe dashboard")

    # osint
    osint = sub.add_parser("osint", help="Passive OSINT — vendor lookup, WiGLE, known vulns")
    osint.add_argument("-t", "--target", required=True, help="Target AP BSSID")
    osint.add_argument("-e", "--essid", default="", help="Target ESSID (improves results)")
    osint.add_argument("--wigle-key", help="WiGLE API key (or set WIGLE_API_KEY env)")
    osint.add_argument("--export", action="store_true", help="Export report to JSON")

    # pmf
    pmf = sub.add_parser("pmf", help="Detect 802.11w Protected Management Frames")
    pmf.add_argument("-t", "--target", required=True, help="Target AP BSSID")
    pmf.add_argument("-d", "--duration", type=int, default=30, help="Sniff duration (seconds)")

    # wpa3
    wpa3 = sub.add_parser("wpa3", help="WPA3/SAE attacks — detect, downgrade, timing, group")
    wpa3_sub = wpa3.add_subparsers(dest="wpa3_action")

    wpa3_detect = wpa3_sub.add_parser("detect", help="Detect WPA3/SAE capabilities")
    wpa3_detect.add_argument("-t", "--target", required=True, help="Target AP BSSID")
    wpa3_detect.add_argument("-d", "--duration", type=int, default=30, help="Sniff duration")

    wpa3_downgrade = wpa3_sub.add_parser("downgrade", help="WPA3 transition mode downgrade")
    wpa3_downgrade.add_argument("-t", "--target", required=True, help="Target AP BSSID")
    wpa3_downgrade.add_argument("-ch", "--channel", type=int, required=True, help="Target channel")
    wpa3_downgrade.add_argument("--client", help="Target client MAC")
    wpa3_downgrade.add_argument("-o", "--output", default="./captures", help="Output directory")

    wpa3_timing = wpa3_sub.add_parser("timing", help="SAE commit timing side-channel (CVE-2019-9494)")
    wpa3_timing.add_argument("-t", "--target", required=True, help="Target AP BSSID")
    wpa3_timing.add_argument("-ch", "--channel", type=int, required=True, help="Target channel")
    wpa3_timing.add_argument("-d", "--duration", type=int, default=60, help="Capture duration")
    wpa3_timing.add_argument("-o", "--output", default="./captures", help="Output directory")

    wpa3_group = wpa3_sub.add_parser("group", help="SAE group downgrade test (CVE-2019-9496)")
    wpa3_group.add_argument("-t", "--target", required=True, help="Target AP BSSID")
    wpa3_group.add_argument("-ch", "--channel", type=int, required=True, help="Target channel")

    # enterprise
    ent = sub.add_parser("enterprise", help="802.1X Enterprise WiFi attacks")
    ent_sub = ent.add_subparsers(dest="ent_action")

    ent_detect = ent_sub.add_parser("detect", help="Detect EAP types on enterprise AP")
    ent_detect.add_argument("-t", "--target", required=True, help="Target AP BSSID")
    ent_detect.add_argument("-d", "--duration", type=int, default=30, help="Sniff duration")

    ent_wpe = ent_sub.add_parser("wpe", help="Enterprise evil twin via hostapd-wpe")
    ent_wpe.add_argument("-e", "--essid", required=True, help="SSID to impersonate")
    ent_wpe.add_argument("-ch", "--channel", type=int, required=True, help="Channel")
    ent_wpe.add_argument("--eap", choices=["PEAP", "EAP-TTLS", "GTC"], default="PEAP",
                         help="EAP type to offer")
    ent_wpe.add_argument("-d", "--duration", type=int, default=300, help="Capture duration")
    ent_wpe.add_argument("-o", "--output", default="./captures", help="Output directory")

    ent_gtc = ent_sub.add_parser("gtc", help="GTC downgrade — capture cleartext passwords")
    ent_gtc.add_argument("-e", "--essid", required=True, help="SSID to impersonate")
    ent_gtc.add_argument("-ch", "--channel", type=int, required=True, help="Channel")
    ent_gtc.add_argument("-d", "--duration", type=int, default=300, help="Capture duration")
    ent_gtc.add_argument("-o", "--output", default="./captures", help="Output directory")

    # bluetooth
    bt = sub.add_parser("bt", help="Bluetooth recon — BLE scanning, Classic scan, GATT enumeration")
    bt_sub = bt.add_subparsers(dest="bt_action")

    bt_ble = bt_sub.add_parser("ble", help="Scan for BLE devices")
    bt_ble.add_argument("-d", "--duration", type=int, default=15, help="Scan duration (seconds)")
    bt_ble.add_argument("--hci", default="hci0", help="HCI interface (default: hci0)")

    bt_classic = bt_sub.add_parser("classic", help="Scan for Bluetooth Classic devices")
    bt_classic.add_argument("-d", "--duration", type=int, default=15, help="Scan duration (seconds)")
    bt_classic.add_argument("--hci", default="hci0", help="HCI interface (default: hci0)")

    bt_gatt = bt_sub.add_parser("gatt", help="Enumerate GATT services on a BLE device")
    bt_gatt.add_argument("address", help="BLE device address (AA:BB:CC:DD:EE:FF)")
    bt_gatt.add_argument("--hci", default="hci0", help="HCI interface (default: hci0)")

    bt_prox = bt_sub.add_parser("proximity", help="Track BLE device signal strength over time")
    bt_prox.add_argument("address", help="Device address to track")
    bt_prox.add_argument("-d", "--duration", type=int, default=60, help="Track duration (seconds)")
    bt_prox.add_argument("--hci", default="hci0", help="HCI interface (default: hci0)")

    # plugin
    plug = sub.add_parser("plugin", help="Plugin management")
    plug_sub = plug.add_subparsers(dest="plugin_action")

    plug_sub.add_parser("list", help="List installed plugins")

    plug_run = plug_sub.add_parser("run", help="Run a plugin command")
    plug_run.add_argument("plugin_name", help="Plugin name")
    plug_run.add_argument("plugin_command", help="Command to run")
    plug_run.add_argument("plugin_args", nargs="*", help="Arguments for the command")

    # tui
    sub.add_parser("tui", help="Interactive full-screen terminal UI")

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
        pmf_info = None
        wpa3_info = None

        if args.pmf_check:
            console.print("[cyan]Running PMF pre-check...[/cyan]")
            pmf_info = detect_pmf(monitor_iface, args.target, duration=10)

        if args.wpa3_check:
            console.print("[cyan]Running WPA3/SAE pre-check...[/cyan]")
            wpa3_mod = Wpa3Module(config, opsec)
            wpa3_result = wpa3_mod.detect_wpa3(monitor_iface, args.target, duration=10)
            wpa3_info = wpa3_mod.to_dict(wpa3_result)

        attack = AttackModule(config, opsec)
        capture = attack.capture(
            monitor_iface, args.target, args.channel,
            client_mac=args.client, output_dir=args.output,
            pmf_info=pmf_info, wpa3_info=wpa3_info,
            evasion=args.evasion,
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

    stop_event = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())

    mitm.start(config.interface, args.target, args.gateway, ttl_spoof=args.ttl_spoof)

    if dns_spoof:
        dns_spoof.start(config.interface)

    try:
        if args.dashboard:
            mitm.live_dashboard()
        else:
            console.print("[dim]Press Ctrl+C to stop...[/dim]")
            stop_event.wait()
    finally:
        mitm.stop()
        mitm.export()
        if dns_spoof:
            dns_spoof.stop()
        opsec.cleanup()


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

    stop_event = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())

    if et.start(twin_config):
        if args.captive:
            portal = CaptivePortal(listen_ip=twin_config.gateway_ip)
            portal.start()

        try:
            console.print("[dim]Press Ctrl+C to stop...[/dim]")
            stop_event.wait()
        finally:
            if portal:
                portal.export()
                portal.stop()
            et.stop()


def cmd_monitor(config: Config, args: argparse.Namespace) -> None:
    alert_mgr = AlertManager.from_config(config.raw)
    monitor = MonitorModule(config, alert_manager=alert_mgr)

    stop_event = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())

    monitor.start(config.interface)

    try:
        if args.dashboard:
            monitor.live_dashboard()
        else:
            console.print("[dim]Press Ctrl+C to stop...[/dim]")
            stop_event.wait()
    finally:
        monitor.stop()
        monitor.export_alerts()


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


def cmd_doctor(config: Config, args: argparse.Namespace) -> None:
    doctor()


def cmd_wps(config: Config, args: argparse.Namespace) -> None:
    opsec = OpsecEngine(config)
    iface_mgr = InterfaceManager(config.interface)

    monitor_iface = iface_mgr.enable_monitor_mode()
    if not monitor_iface:
        return

    try:
        wps = WpsModule(config, opsec)

        if args.wps_action == "scan":
            wps.scan_wps(monitor_iface, duration=args.duration)
        elif args.wps_action == "pixie":
            result = wps.pixie_dust(
                monitor_iface, args.target, args.channel, timeout=args.timeout,
            )
            if result.success:
                console.print(f"\n[green bold]PIN: {result.pin}[/green bold]")
                if result.password:
                    console.print(f"[green bold]Password: {result.password}[/green bold]")
            else:
                console.print(f"\n[yellow]{result.message}[/yellow]")
        elif args.wps_action == "brute":
            result = wps.brute_force(
                monitor_iface, args.target, args.channel, timeout=args.timeout,
            )
            if result.success:
                console.print(f"\n[green bold]PIN: {result.pin}[/green bold]")
                if result.password:
                    console.print(f"[green bold]Password: {result.password}[/green bold]")
            else:
                console.print(f"\n[yellow]{result.message}[/yellow]")
        else:
            console.print("[yellow]Usage: voidfreq wps {scan|pixie|brute}[/yellow]")
    finally:
        iface_mgr.disable_monitor_mode()
        opsec.cleanup()


def cmd_proxy(config: Config, args: argparse.Namespace) -> None:
    opsec = OpsecEngine(config)
    proxy = ProxyModule(config, opsec)

    transparent = not args.no_transparent

    if not proxy.start(config.interface, listen_port=args.port, transparent=transparent):
        return

    stop_event = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())

    try:
        if args.dashboard:
            proxy.live_dashboard()
        else:
            console.print("[dim]Press Ctrl+C to stop...[/dim]")
            stop_event.wait()
    finally:
        proxy.stop()
        proxy.export()
        opsec.cleanup()


def cmd_karma(config: Config, args: argparse.Namespace) -> None:
    opsec = OpsecEngine(config)
    karma = KarmaModule(config, opsec)

    karma_config = KarmaConfig(
        interface=config.interface,
        channel=args.channel,
        gateway_ip=args.gateway,
        mana_loud=not args.no_loud,
        captive_portal=args.captive,
    )

    if not karma.start(karma_config):
        return

    stop_event = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())

    try:
        if args.dashboard:
            karma.live_dashboard()
        else:
            console.print("[dim]Press Ctrl+C to stop...[/dim]")
            stop_event.wait()
    finally:
        karma.stop()
        karma.export()


def cmd_osint(config: Config, args: argparse.Namespace) -> None:
    import os as _os
    wigle_key = args.wigle_key or _os.environ.get("WIGLE_API_KEY")
    osint = OsintModule(wigle_api_key=wigle_key)
    report = osint.investigate(args.target, essid=args.essid)

    if args.export:
        osint.export(report)


def cmd_pmf(config: Config, args: argparse.Namespace) -> None:
    iface_mgr = InterfaceManager(config.interface)

    monitor_iface = iface_mgr.enable_monitor_mode()
    if not monitor_iface:
        return

    try:
        result = detect_pmf(monitor_iface, args.target, duration=args.duration)
        if result.get("pmf_required"):
            console.print("\n[red bold]Conclusion: Deauth attacks WILL NOT WORK on this AP[/red bold]")
            console.print("[dim]Use PMKID or passive capture strategies instead[/dim]")
        elif result.get("pmf_capable"):
            console.print("\n[yellow]Conclusion: Deauth may partially work — PMF clients are protected[/yellow]")
        else:
            console.print("\n[green]Conclusion: AP has no PMF — all attack strategies available[/green]")
    finally:
        iface_mgr.disable_monitor_mode()


def cmd_wpa3(config: Config, args: argparse.Namespace) -> None:
    opsec = OpsecEngine(config)
    iface_mgr = InterfaceManager(config.interface)

    monitor_iface = iface_mgr.enable_monitor_mode()
    if not monitor_iface:
        return

    try:
        wpa3 = Wpa3Module(config, opsec)

        if args.wpa3_action == "detect":
            wpa3.detect_wpa3(monitor_iface, args.target, duration=args.duration)
        elif args.wpa3_action == "downgrade":
            result = wpa3.transition_downgrade(
                monitor_iface, args.target, args.channel,
                client_mac=getattr(args, "client", None),
                output_dir=args.output,
            )
            if result.success:
                console.print(f"\n[green bold]Downgrade capture: {result.capture_file}[/green bold]")
            else:
                console.print(f"\n[yellow]{result.message}[/yellow]")
        elif args.wpa3_action == "timing":
            result = wpa3.sae_timing_attack(
                monitor_iface, args.target, args.channel,
                duration=args.duration, output_dir=args.output,
            )
            if result.details:
                console.print(f"[dim]Avg: {result.details.get('avg_response_ms', '?')}ms, "
                              f"StdDev: {result.details.get('std_dev_ms', '?')}ms[/dim]")
        elif args.wpa3_action == "group":
            wpa3.sae_group_downgrade(
                monitor_iface, args.target, args.channel,
            )
        else:
            console.print("[yellow]Usage: voidfreq wpa3 {detect|downgrade|timing|group}[/yellow]")
    finally:
        iface_mgr.disable_monitor_mode()
        opsec.cleanup()


def cmd_enterprise(config: Config, args: argparse.Namespace) -> None:
    opsec = OpsecEngine(config)
    iface_mgr = InterfaceManager(config.interface)

    if args.ent_action == "detect":
        monitor_iface = iface_mgr.enable_monitor_mode()
        if not monitor_iface:
            return
        try:
            ent = EnterpriseModule(config, opsec)
            ent.detect_eap(monitor_iface, args.target, duration=args.duration)
        finally:
            iface_mgr.disable_monitor_mode()
            opsec.cleanup()

    elif args.ent_action == "wpe":
        try:
            ent = EnterpriseModule(config, opsec)
            result = ent.evil_twin_wpe(
                config.interface, args.essid, args.channel,
                eap_type=args.eap, duration=args.duration,
                output_dir=args.output,
            )
            if result.success:
                console.print(f"\n[green bold]Captured {len(result.credentials)} credential(s)[/green bold]")
                for cred in result.credentials:
                    console.print(f"  [green]{cred.get('username', '?')} — {cred.get('type', '?')}[/green]")
            else:
                console.print(f"\n[yellow]{result.message}[/yellow]")
        finally:
            opsec.cleanup()

    elif args.ent_action == "gtc":
        try:
            ent = EnterpriseModule(config, opsec)
            result = ent.gtc_downgrade(
                config.interface, args.essid, args.channel,
                duration=args.duration, output_dir=args.output,
            )
            if result.success:
                console.print(f"\n[green bold]GTC cleartext capture: {len(result.credentials)} credential(s)[/green bold]")
                for cred in result.credentials:
                    console.print(f"  [green]{cred.get('username', '?')}: {cred.get('password', '?')}[/green]")
            else:
                console.print(f"\n[yellow]{result.message}[/yellow]")
        finally:
            opsec.cleanup()

    else:
        console.print("[yellow]Usage: voidfreq enterprise {detect|wpe|gtc}[/yellow]")


def cmd_bt(config: Config, args: argparse.Namespace) -> None:
    opsec = OpsecEngine(config)
    bt = BluetoothModule(config, opsec)

    hci = getattr(args, "hci", "hci0")

    if args.bt_action == "ble":
        bt.scan_ble(duration=args.duration, interface=hci)
    elif args.bt_action == "classic":
        bt.scan_classic(duration=args.duration, interface=hci)
    elif args.bt_action == "gatt":
        bt.enumerate_gatt(args.address, interface=hci)
    elif args.bt_action == "proximity":
        bt.proximity_track(args.address, duration=args.duration, interface=hci)
    else:
        console.print("[yellow]Usage: voidfreq bt {ble|classic|gatt|proximity}[/yellow]")


def cmd_plugin(config: Config, args: argparse.Namespace) -> None:
    mgr = PluginManager()

    if args.plugin_action == "list":
        mgr.load_all()
        mgr.list_plugins()
    elif args.plugin_action == "run":
        mgr.load_all()
        if not mgr.run_command(args.plugin_name, args.plugin_command, args.plugin_args):
            console.print(f"[red]Plugin '{args.plugin_name}' not found[/red]")
    else:
        mgr.list_plugins()


def cmd_tui(config: Config, args: argparse.Namespace) -> None:
    from .tui import run_tui
    run_tui(config)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    print_banner()

    if args.verbose:
        from .core.logger import set_console_level
        set_console_level(logging.DEBUG)
    elif args.quiet:
        from .core.logger import set_console_level
        set_console_level(logging.WARNING)

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
        "doctor": cmd_doctor,
        "wps": cmd_wps,
        "proxy": cmd_proxy,
        "karma": cmd_karma,
        "osint": cmd_osint,
        "pmf": cmd_pmf,
        "wpa3": cmd_wpa3,
        "enterprise": cmd_enterprise,
        "bt": cmd_bt,
        "plugin": cmd_plugin,
        "tui": cmd_tui,
    }

    no_root_commands = ("check", "doctor", "opsec", "session", "wordlist", "analyze", "osint", "plugin", "tui")

    if args.command in commands:
        if args.command not in no_root_commands and not check_root():
            sys.exit(1)
        commands[args.command](config, args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
