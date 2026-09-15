"""Report generator — markdown and JSON pentest reports."""

from __future__ import annotations

import json
import os
import time


def generate_report(
    scan_data: dict | None = None,
    capture_data: dict | None = None,
    crack_data: dict | None = None,
    traffic_data: dict | None = None,
    alerts_data: dict | None = None,
    output_dir: str = "./reports",
    fmt: str = "markdown",
) -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")

    if fmt in ("markdown", "both"):
        md_path = os.path.join(output_dir, f"voidfreq_report_{ts}.md")
        _write_markdown(md_path, scan_data, capture_data, crack_data, traffic_data, alerts_data)

    if fmt in ("json", "both"):
        json_path = os.path.join(output_dir, f"voidfreq_report_{ts}.json")
        _write_json(json_path, scan_data, capture_data, crack_data, traffic_data, alerts_data)

    if fmt == "json":
        return os.path.join(output_dir, f"voidfreq_report_{ts}.json")
    return os.path.join(output_dir, f"voidfreq_report_{ts}.md")


def _write_markdown(
    path: str,
    scan_data: dict | None,
    capture_data: dict | None,
    crack_data: dict | None,
    traffic_data: dict | None,
    alerts_data: dict | None,
) -> None:
    lines = [
        "# VoidFreq — Pentest Report",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]

    if scan_data:
        lines.append("## Reconnaissance")
        lines.append("")
        lines.append("| BSSID | ESSID | Channel | Power | Encryption | Clients |")
        lines.append("|-------|-------|---------|-------|------------|---------|")
        for ap in scan_data.get("access_points", []):
            lines.append(
                f"| {ap['bssid']} | {ap['essid']} | {ap['channel']} | "
                f"{ap['power']} | {ap['encryption']} | {len(ap.get('clients', []))} |"
            )
        lines.append("")

    if capture_data:
        lines.append("## Capture")
        lines.append("")
        lines.append(f"- **Strategy:** {capture_data.get('strategy', 'N/A')}")
        lines.append(f"- **Success:** {capture_data.get('success', False)}")
        lines.append(f"- **File:** {capture_data.get('file', 'N/A')}")
        lines.append("")

    if crack_data:
        lines.append("## Cracking")
        lines.append("")
        lines.append(f"- **Method:** {crack_data.get('method', 'N/A')}")
        lines.append(f"- **Success:** {crack_data.get('success', False)}")
        if crack_data.get("password"):
            lines.append(f"- **Password:** `{crack_data['password']}`")
        lines.append("")

    if traffic_data:
        lines.append("## Traffic Analysis")
        lines.append("")
        stats = traffic_data.get("stats", {})
        lines.append(f"- **DNS queries:** {stats.get('total_dns', 0)}")
        lines.append(f"- **SNI domains:** {stats.get('total_sni', 0)}")
        lines.append(f"- **HTTP requests:** {stats.get('total_http', 0)}")
        lines.append(f"- **Unique domains:** {stats.get('unique_domains', 0)}")
        lines.append(f"- **Credentials captured:** {stats.get('total_credentials', 0)}")
        lines.append("")

        domains = set()
        for d in traffic_data.get("dns_queries", []):
            domains.add(d["domain"])
        for s in traffic_data.get("sni_domains", []):
            domains.add(s["domain"] if isinstance(s, dict) else s)

        if domains:
            lines.append("### Visited Domains")
            lines.append("")
            for d in sorted(domains):
                lines.append(f"- {d}")
            lines.append("")

    if alerts_data:
        lines.append("## Blue Team Alerts")
        lines.append("")
        for alert in alerts_data.get("alerts", []):
            sev = alert["severity"]
            icon = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🔵"}.get(sev, "⚪")
            lines.append(
                f"- {icon} **[{sev}]** {alert['type']}: {alert['message']}"
            )
        lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _write_json(
    path: str,
    scan_data: dict | None,
    capture_data: dict | None,
    crack_data: dict | None,
    traffic_data: dict | None,
    alerts_data: dict | None,
) -> None:
    from .. import __version__

    data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "tool": "VoidFreq",
        "version": __version__,
        "reconnaissance": scan_data,
        "capture": capture_data,
        "cracking": crack_data,
        "traffic": traffic_data,
        "alerts": alerts_data,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
