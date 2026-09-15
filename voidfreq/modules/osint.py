"""Passive OSINT module — external intelligence gathering without touching the target."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

from rich.console import Console
from rich.panel import Panel

from ..core.logger import get_logger

console = Console()
log = get_logger("osint")


@dataclass
class WigleResult:
    bssid: str
    ssid: str = ""
    encryption: str = ""
    channel: int = 0
    first_seen: str = ""
    last_seen: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    city: str = ""
    country: str = ""


@dataclass
class VendorInfo:
    mac_prefix: str
    vendor: str
    address: str = ""


@dataclass
class OsintReport:
    target_bssid: str
    wigle: WigleResult | None = None
    vendor: VendorInfo | None = None
    pmf_detected: bool = False
    wps_enabled: bool = False
    known_vulns: list[str] = field(default_factory=list)


class OsintModule:
    """Gather intelligence about a target AP without active scanning."""

    def __init__(self, wigle_api_key: str | None = None) -> None:
        self.wigle_api_key = wigle_api_key

    def investigate(self, bssid: str, essid: str = "") -> OsintReport:
        console.print(f"[cyan]OSINT investigation: {bssid}[/cyan]")
        report = OsintReport(target_bssid=bssid)

        report.vendor = self._lookup_vendor(bssid)
        if report.vendor:
            console.print(f"[dim]Vendor: {report.vendor.vendor}[/dim]")

        if self.wigle_api_key:
            report.wigle = self._query_wigle(bssid)
        else:
            console.print("[dim]WiGLE API key not configured — skipping geolocation[/dim]")

        report.known_vulns = self._check_known_vulns(report.vendor, essid)

        self._display_report(report)
        return report

    def _lookup_vendor(self, bssid: str) -> VendorInfo | None:
        prefix = bssid[:8].upper()
        try:
            from mac_vendor_lookup import MacLookup
            lookup = MacLookup()
            vendor = lookup.lookup(bssid)
            return VendorInfo(mac_prefix=prefix, vendor=vendor)
        except Exception:
            return VendorInfo(mac_prefix=prefix, vendor="Unknown")

    def _query_wigle(self, bssid: str) -> WigleResult | None:
        try:
            import requests
        except ImportError:
            console.print("[yellow]requests library not available[/yellow]")
            return None

        try:
            resp = requests.get(
                "https://api.wigle.net/api/v2/network/search",
                params={"netid": bssid},
                headers={"Authorization": f"Basic {self.wigle_api_key}"},
                timeout=15,
            )

            if resp.status_code != 200:
                log.warning("WiGLE API returned %d", resp.status_code)
                return None

            data = resp.json()
            results = data.get("results", [])
            if not results:
                return None

            r = results[0]
            return WigleResult(
                bssid=bssid,
                ssid=r.get("ssid", ""),
                encryption=r.get("encryption", ""),
                channel=r.get("channel", 0),
                first_seen=r.get("firsttime", ""),
                last_seen=r.get("lasttime", ""),
                latitude=r.get("trilat", 0.0),
                longitude=r.get("trilong", 0.0),
                city=r.get("city", ""),
                country=r.get("country", ""),
            )

        except Exception as e:
            log.error("WiGLE query failed: %s", e)
            return None

    def _check_known_vulns(self, vendor: VendorInfo | None, essid: str) -> list[str]:
        vulns = []

        if not vendor:
            return vulns

        v = vendor.vendor.lower()

        vuln_vendors = {
            "tp-link": ["Default admin credentials often admin:admin",
                        "WPS enabled by default on older models"],
            "netgear": ["CVE-2017-5521 — password disclosure",
                        "Default WPS PIN derivable from serial/MAC on some models"],
            "d-link": ["Multiple RCE vulns in older firmware",
                       "UPnP misconfiguration common"],
            "huawei": ["Default credentials on carrier-provided models",
                       "TR-069 management interface often exposed"],
            "zte": ["Default credentials widely known",
                    "TR-069 backdoor on some models"],
            "asus": ["CVE-2023-39238 through 39240 — buffer overflow"],
            "ubiquiti": ["Default ubnt:ubnt credentials",
                         "SNMP community string guessable"],
            "mikrotik": ["CVE-2018-14847 — Winbox auth bypass",
                         "Default admin with no password"],
        }

        for vendor_key, vendor_vulns in vuln_vendors.items():
            if vendor_key in v:
                vulns.extend(vendor_vulns)

        default_essids = {
            "linksys": "Linksys default config",
            "netgear": "Netgear default config",
            "dlink": "D-Link default config",
            "tp-link": "TP-Link default config",
            "default": "Factory default SSID — likely default creds",
            "setup": "Setup mode SSID — unconfigured router",
        }

        essid_lower = essid.lower()
        for pattern, note in default_essids.items():
            if pattern in essid_lower:
                vulns.append(f"ESSID pattern match: {note}")

        return vulns

    def _display_report(self, report: OsintReport) -> None:
        lines = [f"[bold]Target:[/bold] {report.target_bssid}"]

        if report.vendor:
            lines.append(f"[bold]Vendor:[/bold] {report.vendor.vendor} ({report.vendor.mac_prefix})")

        if report.wigle:
            w = report.wigle
            lines.append("")
            lines.append("[bold]WiGLE Data:[/bold]")
            if w.ssid:
                lines.append(f"  SSID: {w.ssid}")
            if w.encryption:
                lines.append(f"  Encryption: {w.encryption}")
            if w.first_seen:
                lines.append(f"  First seen: {w.first_seen}")
            if w.last_seen:
                lines.append(f"  Last seen: {w.last_seen}")
            if w.latitude and w.longitude:
                lines.append(f"  Location: {w.latitude:.6f}, {w.longitude:.6f}")
            if w.city:
                lines.append(f"  City: {w.city}, {w.country}")

        if report.known_vulns:
            lines.append("")
            lines.append("[bold red]Known Vulnerabilities:[/bold red]")
            for vuln in report.known_vulns:
                lines.append(f"  [red]• {vuln}[/red]")

        console.print(Panel(
            "\n".join(lines),
            title="[bold]OSINT Report[/bold]",
            border_style="cyan",
        ))

    def export(self, report: OsintReport, output_dir: str = "./reports") -> str:
        os.makedirs(output_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(output_dir, f"osint_{report.target_bssid.replace(':', '')}_{ts}.json")

        data = {
            "target": report.target_bssid,
            "vendor": {
                "prefix": report.vendor.mac_prefix,
                "name": report.vendor.vendor,
            } if report.vendor else None,
            "wigle": {
                "ssid": report.wigle.ssid,
                "encryption": report.wigle.encryption,
                "channel": report.wigle.channel,
                "first_seen": report.wigle.first_seen,
                "last_seen": report.wigle.last_seen,
                "latitude": report.wigle.latitude,
                "longitude": report.wigle.longitude,
                "city": report.wigle.city,
                "country": report.wigle.country,
            } if report.wigle else None,
            "known_vulns": report.known_vulns,
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]OSINT report exported to {path}[/green]")
        return path
