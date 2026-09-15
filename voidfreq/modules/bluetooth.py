"""Bluetooth recon module — BLE and Classic device scanning, GATT enumeration."""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field

from rich.console import Console
from rich.table import Table

from ..core.config import Config
from ..core.logger import get_logger
from ..core.opsec import OpsecEngine

console = Console()
log = get_logger("bluetooth")

KNOWN_VULNERABLE_OUIS: dict[str, str] = {
    "00:1A:7D": "CyberTAN (routers — default PIN often 12345678)",
    "00:26:5A": "D-Link (BLE config often unprotected)",
    "A4:C1:38": "ESP32 (common in IoT, often no auth)",
    "B4:E6:2D": "Raspberry Pi (BLE dev boards — check for debug services)",
    "AC:23:3F": "Shenzhen generic BLE (CVE-2020-0069 style exploits)",
}

KNOWN_VULNERABLE_SERVICES: dict[str, str] = {
    "0000fee7": "Tencent WeChat BLE (data leak via unauth notify)",
    "0000180d": "Heart Rate (no encryption in many devices)",
    "0000180f": "Battery Service (fingerprinting vector)",
    "0000fff0": "Custom vendor (often has hardcoded pairing key)",
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": "Nordic UART (RX/TX — often unauthenticated shell)",
}


@dataclass
class BtDevice:
    address: str
    name: str = ""
    device_type: str = "unknown"  # classic, ble, dual
    rssi: int = 0
    manufacturer: str = ""
    services: list[str] = field(default_factory=list)
    gatt_services: list[dict] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)


@dataclass
class BtScanResult:
    devices: list[BtDevice] = field(default_factory=list)
    duration: float = 0.0
    interface: str = ""


class BluetoothModule:
    def __init__(self, config: Config, opsec: OpsecEngine) -> None:
        self.config = config
        self.opsec = opsec
        self._devices: list[BtDevice] = []

    def scan_ble(self, duration: int = 15, interface: str = "hci0") -> BtScanResult:
        console.print(f"[cyan]BLE scanning on {interface} ({duration}s)...[/cyan]")
        self.opsec.pre_operation()
        log.info("BLE scan: interface=%s duration=%d", interface, duration)

        devices: list[BtDevice] = []

        try:
            subprocess.run(
                ["sudo", "hciconfig", interface, "up"],
                capture_output=True, timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            console.print("[red]hciconfig not found — install bluez[/red]")
            return BtScanResult(interface=interface)

        devices = self._scan_ble_hcitool(interface, duration)

        if not devices:
            devices = self._scan_ble_bluetoothctl(duration)

        for dev in devices:
            self._check_vulnerabilities(dev)

        self._devices = devices
        result = BtScanResult(devices=devices, duration=duration, interface=interface)
        self._display_scan(result)
        return result

    def scan_classic(self, duration: int = 15, interface: str = "hci0") -> BtScanResult:
        console.print(f"[cyan]Bluetooth Classic scan on {interface} ({duration}s)...[/cyan]")
        self.opsec.pre_operation()
        log.info("Classic BT scan: interface=%s duration=%d", interface, duration)

        devices: list[BtDevice] = []

        try:
            result = subprocess.run(
                ["hcitool", "-i", interface, "scan", "--length", str(max(1, duration // 1))],
                capture_output=True, text=True, timeout=duration + 30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            log.warning("hcitool scan failed: %s", e)
            return BtScanResult(interface=interface)

        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            match = re.match(r"([0-9A-Fa-f:]{17})\s+(.+)", line)
            if match:
                dev = BtDevice(
                    address=match.group(1).upper(),
                    name=match.group(2).strip(),
                    device_type="classic",
                )
                devices.append(dev)

        for dev in devices:
            self._enumerate_classic_services(dev, interface)
            self._check_vulnerabilities(dev)

        self._devices = devices
        scan_result = BtScanResult(devices=devices, duration=duration, interface=interface)
        self._display_scan(scan_result)
        return scan_result

    def enumerate_gatt(self, address: str, interface: str = "hci0") -> list[dict]:
        console.print(f"[cyan]GATT enumeration for {address}...[/cyan]")
        log.info("GATT enumerate: %s on %s", address, interface)

        services: list[dict] = []

        try:
            result = subprocess.run(
                ["gatttool", "-i", interface, "-b", address, "--primary"],
                capture_output=True, text=True, timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            log.warning("gatttool failed: %s", e)
            return services

        for line in result.stdout.strip().split("\n"):
            match = re.search(r"uuid:\s*([0-9a-f-]+)", line, re.IGNORECASE)
            if match:
                uuid = match.group(1).lower()
                svc = {"uuid": uuid, "name": self._uuid_name(uuid)}

                vuln = KNOWN_VULNERABLE_SERVICES.get(uuid[:8])
                if vuln:
                    svc["vulnerability"] = vuln

                services.append(svc)

        if services:
            table = Table(title=f"GATT Services: {address}")
            table.add_column("UUID", style="cyan")
            table.add_column("Name")
            table.add_column("Vuln", style="red")

            for svc in services:
                table.add_row(
                    svc["uuid"],
                    svc.get("name", ""),
                    svc.get("vulnerability", ""),
                )
            console.print(table)

        return services

    def proximity_track(
        self, address: str, duration: int = 60, interface: str = "hci0",
    ) -> list[dict]:
        console.print(f"[cyan]Proximity tracking {address} ({duration}s)...[/cyan]")
        log.info("Proximity track: %s duration=%d", address, duration)

        readings: list[dict] = []
        start = time.time()

        while time.time() - start < duration:
            try:
                result = subprocess.run(
                    ["hcitool", "-i", interface, "rssi", address],
                    capture_output=True, text=True, timeout=10,
                )
                match = re.search(r"RSSI return value:\s*(-?\d+)", result.stdout)
                if match:
                    rssi = int(match.group(1))
                    readings.append({
                        "timestamp": time.strftime("%H:%M:%S"),
                        "rssi": rssi,
                        "estimated_distance_m": self._rssi_to_distance(rssi),
                    })
                    console.print(
                        f"[dim]{readings[-1]['timestamp']}[/dim] "
                        f"RSSI: {rssi} dBm "
                        f"(~{readings[-1]['estimated_distance_m']:.1f}m)"
                    )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                break

            time.sleep(2)

        return readings

    def _scan_ble_hcitool(self, interface: str, duration: int) -> list[BtDevice]:
        devices: list[BtDevice] = []
        try:
            result = subprocess.run(
                ["sudo", "hcitool", "-i", interface, "lescan", "--duplicates"],
                capture_output=True, text=True, timeout=duration + 5,
            )
        except subprocess.TimeoutExpired as e:
            output = e.stdout if isinstance(e.stdout, str) else (e.stdout.decode() if e.stdout else "")
            result = type("R", (), {"stdout": output, "returncode": 0})()
        except FileNotFoundError:
            return devices

        seen: set[str] = set()
        for line in result.stdout.strip().split("\n"):
            match = re.match(r"([0-9A-Fa-f:]{17})\s+(.*)", line.strip())
            if match:
                addr = match.group(1).upper()
                if addr not in seen:
                    seen.add(addr)
                    devices.append(BtDevice(
                        address=addr,
                        name=match.group(2).strip() or "(unknown)",
                        device_type="ble",
                    ))
        return devices

    def _scan_ble_bluetoothctl(self, duration: int) -> list[BtDevice]:
        devices: list[BtDevice] = []
        try:
            proc = subprocess.Popen(
                ["bluetoothctl"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            proc.stdin.write("scan on\n")
            proc.stdin.flush()
            time.sleep(duration)
            proc.stdin.write("devices\n")
            proc.stdin.flush()
            time.sleep(1)
            proc.stdin.write("scan off\nquit\n")
            proc.stdin.flush()
            stdout, _ = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return devices
        except (FileNotFoundError, BrokenPipeError):
            return devices

        seen: set[str] = set()
        for line in stdout.split("\n"):
            match = re.search(r"Device\s+([0-9A-Fa-f:]{17})\s+(.*)", line)
            if match:
                addr = match.group(1).upper()
                if addr not in seen:
                    seen.add(addr)
                    devices.append(BtDevice(
                        address=addr,
                        name=match.group(2).strip(),
                        device_type="ble",
                    ))
        return devices

    def _enumerate_classic_services(self, device: BtDevice, interface: str) -> None:
        try:
            result = subprocess.run(
                ["sdptool", "browse", device.address],
                capture_output=True, text=True, timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return

        for match in re.finditer(r'Service Name:\s*(.+)', result.stdout):
            device.services.append(match.group(1).strip())

    def _check_vulnerabilities(self, device: BtDevice) -> None:
        oui = device.address[:8]
        if oui in KNOWN_VULNERABLE_OUIS:
            device.vulnerabilities.append(KNOWN_VULNERABLE_OUIS[oui])
            device.manufacturer = KNOWN_VULNERABLE_OUIS[oui].split("(")[0].strip()

        for svc_uuid in device.services:
            short = svc_uuid[:8].lower() if len(svc_uuid) >= 8 else svc_uuid.lower()
            if short in KNOWN_VULNERABLE_SERVICES:
                device.vulnerabilities.append(KNOWN_VULNERABLE_SERVICES[short])

    def _uuid_name(self, uuid: str) -> str:
        short = uuid[:8].lower()
        names = {
            "00001800": "Generic Access",
            "00001801": "Generic Attribute",
            "0000180a": "Device Information",
            "0000180d": "Heart Rate",
            "0000180f": "Battery Service",
            "00001810": "Blood Pressure",
            "00001812": "HID (Human Interface)",
            "0000fee7": "Tencent WeChat",
            "0000fff0": "Custom Vendor",
        }
        return names.get(short, "")

    def _rssi_to_distance(self, rssi: int, tx_power: int = -59) -> float:
        if rssi >= 0:
            return 0.0
        ratio = (tx_power - rssi) / 20.0
        return round(10 ** ratio, 2)

    def _display_scan(self, result: BtScanResult) -> None:
        if not result.devices:
            console.print("[yellow]No Bluetooth devices found[/yellow]")
            return

        table = Table(title=f"Bluetooth Scan Results ({len(result.devices)} devices)")
        table.add_column("Address", style="cyan")
        table.add_column("Name")
        table.add_column("Type", style="blue")
        table.add_column("Services")
        table.add_column("Vulns", style="red")

        for dev in result.devices:
            vuln_count = len(dev.vulnerabilities)
            vuln_text = f"{vuln_count} found" if vuln_count else ""
            table.add_row(
                dev.address,
                dev.name or "(unknown)",
                dev.device_type,
                str(len(dev.services)) if dev.services else "",
                vuln_text,
            )
        console.print(table)

        vulnerable = [d for d in result.devices if d.vulnerabilities]
        if vulnerable:
            console.print(f"\n[red bold]{len(vulnerable)} device(s) with known vulnerabilities:[/red bold]")
            for dev in vulnerable:
                for vuln in dev.vulnerabilities:
                    console.print(f"  [red]{dev.address}[/red]: {vuln}")

    def to_dict(self, result: BtScanResult) -> dict:
        return {
            "duration": result.duration,
            "interface": result.interface,
            "device_count": len(result.devices),
            "devices": [
                {
                    "address": d.address,
                    "name": d.name,
                    "type": d.device_type,
                    "rssi": d.rssi,
                    "manufacturer": d.manufacturer,
                    "services": d.services,
                    "gatt_services": d.gatt_services,
                    "vulnerabilities": d.vulnerabilities,
                }
                for d in result.devices
            ],
        }
