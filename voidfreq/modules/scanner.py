"""Network scanner — nmap-based host/port/service enumeration."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from ..core.config import Config
from ..core.opsec import OpsecEngine

console = Console()

TIMING_MAP = {
    "aggressive": "-T4",
    "normal": "-T3",
    "paranoid": "-T1",
    "stealth": "-T0",
}


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str
    version: str = ""
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    os_guess: str = ""
    state: str = "up"
    ports: list[Port] = field(default_factory=list)


class ScannerModule:
    def __init__(self, config: Config, opsec: OpsecEngine) -> None:
        self.config = config
        self.opsec = opsec
        self.hosts: list[Host] = []

    def discover_hosts(self, subnet: str) -> list[Host]:
        console.print(f"[cyan]Host discovery on {subnet}...[/cyan]")
        self.opsec.pre_operation()

        timing = TIMING_MAP.get(self.config.stealth.scan_timing, "-T3")
        cmd = ["sudo", "nmap", "-sn", timing, "-oX", "-", subnet]

        if self.config.stealth.fingerprint_spoof:
            cmd.extend(["--data-length", "24"])

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            console.print(f"[red]Host discovery failed: {result.stderr}[/red]")
            return []

        self.hosts = self._parse_nmap_xml(result.stdout)
        self._display_hosts()
        return self.hosts

    def scan_ports(
        self, target: str,
        ports: str = "1-1000",
        service_detection: bool = True,
        os_detection: bool = False,
        vuln_scan: bool = False,
    ) -> Host | None:
        console.print(f"[cyan]Port scanning {target} (ports {ports})...[/cyan]")
        self.opsec.pre_operation()

        timing = TIMING_MAP.get(self.config.stealth.scan_timing, "-T3")
        cmd = ["sudo", "nmap", timing, "-p", ports, "-oX", "-"]

        if service_detection:
            cmd.append("-sV")
        if os_detection:
            cmd.append("-O")

        scan_type = "-sS"
        if self.config.stealth.scan_timing in ("paranoid", "stealth"):
            if self.config.stealth.fingerprint_spoof:
                cmd.extend(["-f", "--data-length", "24"])
            cmd.extend(["-D", "RND:3"])

        cmd.extend([scan_type, target])

        if vuln_scan:
            cmd.extend(["--script", "vuln"])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode not in (0, 1):
            console.print(f"[red]Port scan failed: {result.stderr}[/red]")
            return None

        hosts = self._parse_nmap_xml(result.stdout)
        if hosts:
            host = hosts[0]
            self._display_port_scan(host)
            return host

        console.print("[yellow]No results from scan[/yellow]")
        return None

    def quick_vuln_scan(self, target: str) -> Host | None:
        console.print(f"[cyan]Vulnerability scan on {target}...[/cyan]")
        return self.scan_ports(
            target,
            ports="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443",
            service_detection=True,
            vuln_scan=True,
        )

    def _parse_nmap_xml(self, xml_output: str) -> list[Host]:
        hosts = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_output)

            for host_elem in root.findall(".//host"):
                state_elem = host_elem.find("status")
                if state_elem is not None and state_elem.get("state") != "up":
                    continue

                ip = ""
                mac = ""
                vendor = ""
                addr_elems = host_elem.findall("address")
                for addr in addr_elems:
                    if addr.get("addrtype") == "ipv4":
                        ip = addr.get("addr", "")
                    elif addr.get("addrtype") == "mac":
                        mac = addr.get("addr", "")
                        vendor = addr.get("vendor", "")

                hostname = ""
                hn_elem = host_elem.find(".//hostname")
                if hn_elem is not None:
                    hostname = hn_elem.get("name", "")

                os_guess = ""
                os_match = host_elem.find(".//osmatch")
                if os_match is not None:
                    os_guess = os_match.get("name", "")

                ports = []
                for port_elem in host_elem.findall(".//port"):
                    state_el = port_elem.find("state")
                    service_el = port_elem.find("service")

                    scripts = {}
                    for script_el in port_elem.findall("script"):
                        scripts[script_el.get("id", "")] = script_el.get("output", "")

                    port = Port(
                        number=int(port_elem.get("portid", 0)),
                        protocol=port_elem.get("protocol", "tcp"),
                        state=state_el.get("state", "") if state_el is not None else "",
                        service=service_el.get("name", "") if service_el is not None else "",
                        version=(
                            f"{service_el.get('product', '')} {service_el.get('version', '')}".strip()
                            if service_el is not None else ""
                        ),
                        scripts=scripts,
                    )
                    ports.append(port)

                host = Host(
                    ip=ip, mac=mac, vendor=vendor, hostname=hostname,
                    os_guess=os_guess, ports=ports,
                )
                hosts.append(host)

        except Exception as e:
            console.print(f"[red]XML parse error: {e}[/red]")

        return hosts

    def _display_hosts(self) -> None:
        table = Table(title="Discovered Hosts", show_lines=True)
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="dim")
        table.add_column("Vendor", style="green")
        table.add_column("Hostname", style="yellow")

        for host in self.hosts:
            table.add_row(host.ip, host.mac, host.vendor, host.hostname)

        console.print(table)
        console.print(f"[bold]{len(self.hosts)} hosts discovered[/bold]")

    def _display_port_scan(self, host: Host) -> None:
        tree = Tree(f"[bold cyan]{host.ip}[/bold cyan]")

        if host.hostname:
            tree.add(f"[dim]Hostname: {host.hostname}[/dim]")
        if host.os_guess:
            tree.add(f"[dim]OS: {host.os_guess}[/dim]")
        if host.mac:
            tree.add(f"[dim]MAC: {host.mac} ({host.vendor})[/dim]")

        port_table = Table(show_lines=True)
        port_table.add_column("Port", style="cyan", justify="right")
        port_table.add_column("State", width=8)
        port_table.add_column("Service", style="green")
        port_table.add_column("Version", style="dim")

        for port in host.ports:
            if port.state != "open":
                continue
            port_table.add_row(
                f"{port.number}/{port.protocol}",
                f"[green]{port.state}[/green]",
                port.service,
                port.version,
            )

        tree.add(port_table)

        if any(p.scripts for p in host.ports):
            vuln_branch = tree.add("[red bold]Vulnerabilities[/red bold]")
            for port in host.ports:
                for script_id, output in port.scripts.items():
                    if "VULNERABLE" in output.upper():
                        vuln_branch.add(
                            f"[red]{port.number}/{port.protocol} — {script_id}[/red]\n"
                            f"[dim]{output[:200]}[/dim]"
                        )

        console.print(tree)

    def to_dict(self) -> dict:
        return {
            "hosts": [
                {
                    "ip": h.ip,
                    "mac": h.mac,
                    "vendor": h.vendor,
                    "hostname": h.hostname,
                    "os": h.os_guess,
                    "ports": [
                        {
                            "port": p.number,
                            "proto": p.protocol,
                            "state": p.state,
                            "service": p.service,
                            "version": p.version,
                            "vulns": list(p.scripts.keys()),
                        }
                        for p in h.ports if p.state == "open"
                    ],
                }
                for h in self.hosts
            ],
        }
