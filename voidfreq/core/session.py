"""Session management — save, resume, and track pentest progress."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()

SESSION_DIR = os.path.expanduser("~/.voidfreq/sessions")


class Phase(str, Enum):
    INIT = "init"
    RECON = "recon"
    CAPTURE = "capture"
    CRACK = "crack"
    ACCESS = "access"
    MITM = "mitm"
    EXFIL = "exfil"
    CLEANUP = "cleanup"
    COMPLETE = "complete"


@dataclass
class SessionData:
    id: str
    name: str
    created: str
    updated: str
    phase: str = Phase.INIT.value
    target_bssid: str = ""
    target_essid: str = ""
    target_channel: int = 0
    interface: str = "wlan0"
    stealth_level: str = "high"

    # Phase results
    recon_data: dict | None = None
    captured_file: str | None = None
    capture_strategy: str | None = None
    cracked_password: str | None = None
    crack_method: str | None = None
    network_hosts: list[dict] | None = None
    mitm_traffic: dict | None = None
    alerts: list[dict] | None = None

    notes: list[str] = field(default_factory=list)
    log: list[dict] = field(default_factory=list)


class SessionManager:
    def __init__(self) -> None:
        os.makedirs(SESSION_DIR, exist_ok=True)

    def create(
        self, name: str,
        target_bssid: str = "",
        target_essid: str = "",
        target_channel: int = 0,
        stealth_level: str = "high",
    ) -> SessionData:
        session_id = f"{int(time.time())}_{name.lower().replace(' ', '_')}"
        now = time.strftime("%Y-%m-%dT%H:%M:%S")

        session = SessionData(
            id=session_id,
            name=name,
            created=now,
            updated=now,
            target_bssid=target_bssid,
            target_essid=target_essid,
            target_channel=target_channel,
            stealth_level=stealth_level,
        )

        self._save(session)
        self._log(session, "Session created")
        console.print(f"[green]Session created: {session_id}[/green]")
        return session

    def load(self, session_id: str) -> SessionData | None:
        path = os.path.join(SESSION_DIR, f"{session_id}.json")
        if not os.path.exists(path):
            console.print(f"[red]Session not found: {session_id}[/red]")
            return None

        with open(path) as f:
            data = json.load(f)

        session = SessionData(**{
            k: v for k, v in data.items()
            if k in SessionData.__dataclass_fields__
        })

        console.print(f"[green]Session loaded: {session.name} (phase: {session.phase})[/green]")
        return session

    def save(self, session: SessionData) -> None:
        session.updated = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._save(session)

    def update_phase(self, session: SessionData, phase: Phase, **data) -> None:
        session.phase = phase.value
        for key, value in data.items():
            if hasattr(session, key):
                setattr(session, key, value)
        self._log(session, f"Phase → {phase.value}")
        self.save(session)
        console.print(f"[cyan]Phase updated: {phase.value}[/cyan]")

    def add_note(self, session: SessionData, note: str) -> None:
        session.notes.append(f"[{time.strftime('%H:%M:%S')}] {note}")
        self.save(session)

    def list_sessions(self) -> list[SessionData]:
        sessions = []
        for filename in sorted(Path(SESSION_DIR).glob("*.json"), reverse=True):
            try:
                with open(filename) as f:
                    data = json.load(f)
                sessions.append(SessionData(**{
                    k: v for k, v in data.items()
                    if k in SessionData.__dataclass_fields__
                }))
            except (json.JSONDecodeError, TypeError):
                continue

        if sessions:
            table = Table(title="Saved Sessions", show_lines=True)
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Phase", style="yellow")
            table.add_column("Target")
            table.add_column("Updated", style="dim")

            for s in sessions:
                table.add_row(
                    s.id, s.name, s.phase,
                    s.target_essid or s.target_bssid or "—",
                    s.updated,
                )

            console.print(table)
        else:
            console.print("[dim]No saved sessions[/dim]")

        return sessions

    def delete(self, session_id: str) -> bool:
        path = os.path.join(SESSION_DIR, f"{session_id}.json")
        if os.path.exists(path):
            os.unlink(path)
            console.print(f"[yellow]Session deleted: {session_id}[/yellow]")
            return True
        return False

    def display(self, session: SessionData) -> None:
        from rich.panel import Panel
        from rich.text import Text

        lines = [
            f"[bold]Name:[/bold] {session.name}",
            f"[bold]ID:[/bold] {session.id}",
            f"[bold]Phase:[/bold] {session.phase}",
            f"[bold]Created:[/bold] {session.created}",
            f"[bold]Updated:[/bold] {session.updated}",
            f"[bold]Stealth:[/bold] {session.stealth_level}",
            "",
            f"[bold]Target BSSID:[/bold] {session.target_bssid or '—'}",
            f"[bold]Target ESSID:[/bold] {session.target_essid or '—'}",
            f"[bold]Channel:[/bold] {session.target_channel or '—'}",
        ]

        if session.captured_file:
            lines.append(f"\n[bold]Capture:[/bold] {session.captured_file} ({session.capture_strategy})")
        if session.cracked_password:
            lines.append(f"[bold green]Password:[/bold green] {session.cracked_password} ({session.crack_method})")

        if session.notes:
            lines.append("\n[bold]Notes:[/bold]")
            for note in session.notes[-10:]:
                lines.append(f"  {note}")

        if session.log:
            lines.append(f"\n[dim]{len(session.log)} log entries[/dim]")

        console.print(Panel(
            "\n".join(lines),
            title=f"[bold]Session: {session.name}[/bold]",
            border_style="cyan",
        ))

    def export_report(self, session: SessionData, output_dir: str = "./reports") -> str:
        from ..utils.report import generate_report
        return generate_report(
            scan_data=session.recon_data,
            capture_data={
                "success": session.captured_file is not None,
                "strategy": session.capture_strategy,
                "file": session.captured_file,
            } if session.captured_file else None,
            crack_data={
                "success": session.cracked_password is not None,
                "password": session.cracked_password,
                "method": session.crack_method,
            } if session.cracked_password is not None else None,
            traffic_data=session.mitm_traffic,
            alerts_data={"alerts": session.alerts} if session.alerts else None,
            output_dir=output_dir,
        )

    def _save(self, session: SessionData) -> None:
        path = os.path.join(SESSION_DIR, f"{session.id}.json")
        with open(path, "w") as f:
            json.dump(asdict(session), f, indent=2, default=str)

    def _log(self, session: SessionData, message: str) -> None:
        session.log.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "message": message,
        })
