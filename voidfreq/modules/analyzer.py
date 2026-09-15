"""Pcap analyzer — offline capture file analysis."""

from __future__ import annotations

import json
import os
import subprocess
import time
from collections import Counter
from dataclasses import dataclass, field

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@dataclass
class PcapAnalysis:
    filename: str
    total_packets: int = 0
    duration_seconds: float = 0
    protocols: dict[str, int] = field(default_factory=dict)
    dns_queries: list[dict] = field(default_factory=list)
    sni_domains: list[str] = field(default_factory=list)
    http_requests: list[dict] = field(default_factory=list)
    credentials: list[dict] = field(default_factory=list)
    unique_ips: set[str] = field(default_factory=set)
    unique_macs: set[str] = field(default_factory=set)
    top_talkers: dict[str, int] = field(default_factory=dict)
    handshakes: list[dict] = field(default_factory=list)
    deauth_frames: int = 0
    beacon_ssids: set[str] = field(default_factory=set)


class PcapAnalyzer:
    def __init__(self) -> None:
        self.analysis: PcapAnalysis | None = None

    def analyze(self, pcap_path: str) -> PcapAnalysis:
        if not os.path.exists(pcap_path):
            console.print(f"[red]File not found: {pcap_path}[/red]")
            return PcapAnalysis(filename=pcap_path)

        console.print(f"[cyan]Analyzing {pcap_path}...[/cyan]")
        self.analysis = PcapAnalysis(filename=pcap_path)

        self._get_stats(pcap_path)
        self._extract_dns(pcap_path)
        self._extract_sni(pcap_path)
        self._extract_http(pcap_path)
        self._extract_credentials(pcap_path)
        self._check_handshakes(pcap_path)
        self._count_deauths(pcap_path)
        self._extract_beacons(pcap_path)
        self._get_top_talkers(pcap_path)

        self._display_results()
        return self.analysis

    def _run_tshark(self, args: list[str]) -> str:
        result = subprocess.run(
            ["tshark"] + args,
            capture_output=True, text=True, timeout=120,
        )
        return result.stdout if result.returncode == 0 else ""

    def _get_stats(self, path: str) -> None:
        output = self._run_tshark(["-r", path, "-qz", "io,stat,0"])
        for line in output.split("\n"):
            if "Packets" in line:
                parts = line.split()
                for p in parts:
                    if p.isdigit():
                        self.analysis.total_packets = int(p)
                        break

        output = self._run_tshark([
            "-r", path, "-T", "fields",
            "-e", "frame.protocols",
        ])
        proto_counter: Counter = Counter()
        for line in output.strip().split("\n"):
            if line:
                for proto in line.split(":"):
                    proto_counter[proto] += 1
        self.analysis.protocols = dict(proto_counter.most_common(20))

        output = self._run_tshark([
            "-r", path, "-T", "fields",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "eth.src", "-e", "eth.dst",
        ])
        for line in output.strip().split("\n"):
            parts = line.split("\t")
            if len(parts) >= 2:
                if parts[0]:
                    self.analysis.unique_ips.add(parts[0])
                if parts[1]:
                    self.analysis.unique_ips.add(parts[1])
            if len(parts) >= 4:
                if parts[2]:
                    self.analysis.unique_macs.add(parts[2])
                if parts[3]:
                    self.analysis.unique_macs.add(parts[3])

    def _extract_dns(self, path: str) -> None:
        output = self._run_tshark([
            "-r", path,
            "-Y", "dns.flags.response == 0",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "dns.qry.name",
        ])
        seen = set()
        for line in output.strip().split("\n"):
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1] and parts[1] not in seen:
                seen.add(parts[1])
                self.analysis.dns_queries.append({
                    "source": parts[0],
                    "domain": parts[1],
                })

    def _extract_sni(self, path: str) -> None:
        output = self._run_tshark([
            "-r", path,
            "-Y", "tls.handshake.extensions_server_name",
            "-T", "fields",
            "-e", "tls.handshake.extensions_server_name",
        ])
        domains = set()
        for line in output.strip().split("\n"):
            if line.strip():
                domains.add(line.strip())
        self.analysis.sni_domains = sorted(domains)

    def _extract_http(self, path: str) -> None:
        output = self._run_tshark([
            "-r", path,
            "-Y", "http.request",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "http.request.method",
            "-e", "http.host",
            "-e", "http.request.uri",
        ])
        for line in output.strip().split("\n"):
            parts = line.split("\t")
            if len(parts) >= 4:
                self.analysis.http_requests.append({
                    "source": parts[0],
                    "method": parts[1],
                    "host": parts[2],
                    "uri": parts[3],
                })

    def _extract_credentials(self, path: str) -> None:
        output = self._run_tshark([
            "-r", path,
            "-Y", "http.request.method == POST",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "http.host",
            "-e", "urlencoded-form.key",
            "-e", "urlencoded-form.value",
        ])
        cred_keywords = {"user", "pass", "login", "email", "pwd", "username", "password"}
        for line in output.strip().split("\n"):
            parts = line.split("\t")
            if len(parts) >= 4:
                keys = parts[2].lower() if parts[2] else ""
                if any(k in keys for k in cred_keywords):
                    self.analysis.credentials.append({
                        "source": parts[0],
                        "host": parts[1],
                        "fields": parts[2],
                        "values": parts[3],
                    })

    def _check_handshakes(self, path: str) -> None:
        result = subprocess.run(
            ["aircrack-ng", path],
            capture_output=True, text=True, timeout=30,
        )
        for line in result.stdout.split("\n"):
            if "handshake" in line.lower() and "WPA" in line:
                parts = line.split()
                bssid = parts[0] if parts else "unknown"
                self.analysis.handshakes.append({
                    "bssid": bssid,
                    "info": line.strip(),
                })

    def _count_deauths(self, path: str) -> None:
        output = self._run_tshark([
            "-r", path,
            "-Y", "wlan.fc.type_subtype == 0x0c",
            "-T", "fields",
            "-e", "frame.number",
        ])
        self.analysis.deauth_frames = len([line for line in output.strip().split("\n") if line.strip()])

    def _extract_beacons(self, path: str) -> None:
        output = self._run_tshark([
            "-r", path,
            "-Y", "wlan.fc.type_subtype == 0x08",
            "-T", "fields",
            "-e", "wlan.ssid",
        ])
        for line in output.strip().split("\n"):
            if line.strip():
                self.analysis.beacon_ssids.add(line.strip())

    def _get_top_talkers(self, path: str) -> None:
        output = self._run_tshark([
            "-r", path, "-T", "fields", "-e", "ip.src",
        ])
        counter: Counter = Counter()
        for line in output.strip().split("\n"):
            if line.strip():
                counter[line.strip()] += 1
        self.analysis.top_talkers = dict(counter.most_common(10))

    def _display_results(self) -> None:
        a = self.analysis

        stats_lines = [
            f"[bold]File:[/bold] {a.filename}",
            f"[bold]Total packets:[/bold] {a.total_packets}",
            f"[bold]Unique IPs:[/bold] {len(a.unique_ips)}",
            f"[bold]Unique MACs:[/bold] {len(a.unique_macs)}",
            f"[bold]DNS queries:[/bold] {len(a.dns_queries)} ({len(set(d['domain'] for d in a.dns_queries))} unique domains)",
            f"[bold]SNI domains:[/bold] {len(a.sni_domains)}",
            f"[bold]HTTP requests:[/bold] {len(a.http_requests)}",
            f"[bold]Credentials:[/bold] {len(a.credentials)}",
            f"[bold]Handshakes:[/bold] {len(a.handshakes)}",
            f"[bold]Deauth frames:[/bold] {a.deauth_frames}",
            f"[bold]Beacon SSIDs:[/bold] {len(a.beacon_ssids)}",
        ]
        console.print(Panel("\n".join(stats_lines), title="Capture Analysis", border_style="cyan"))

        if a.sni_domains:
            table = Table(title="Visited Domains (SNI)")
            table.add_column("Domain", style="green")
            for d in a.sni_domains[:30]:
                table.add_row(d)
            console.print(table)

        if a.top_talkers:
            table = Table(title="Top Talkers")
            table.add_column("IP", style="cyan")
            table.add_column("Packets", justify="right")
            for ip, count in a.top_talkers.items():
                table.add_row(ip, str(count))
            console.print(table)

        if a.credentials:
            table = Table(title="Captured Credentials", border_style="red")
            table.add_column("Source", style="cyan")
            table.add_column("Host", style="yellow")
            table.add_column("Fields")
            table.add_column("Values", style="red")
            for c in a.credentials:
                table.add_row(c["source"], c["host"], c["fields"], c["values"])
            console.print(table)

        if a.handshakes:
            for hs in a.handshakes:
                console.print(f"[green bold]Handshake found: {hs['info']}[/green bold]")

    def export(self, output_dir: str = "./reports") -> str:
        if not self.analysis:
            return ""

        os.makedirs(output_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(output_dir, f"pcap_analysis_{ts}.json")

        data = {
            "filename": self.analysis.filename,
            "total_packets": self.analysis.total_packets,
            "unique_ips": sorted(self.analysis.unique_ips),
            "unique_macs": sorted(self.analysis.unique_macs),
            "protocols": self.analysis.protocols,
            "dns_queries": self.analysis.dns_queries,
            "sni_domains": self.analysis.sni_domains,
            "http_requests": self.analysis.http_requests,
            "credentials": self.analysis.credentials,
            "handshakes": self.analysis.handshakes,
            "deauth_frames": self.analysis.deauth_frames,
            "beacon_ssids": sorted(self.analysis.beacon_ssids),
            "top_talkers": self.analysis.top_talkers,
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]Analysis exported to {path}[/green]")
        return path
