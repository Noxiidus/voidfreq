"""Interactive TUI mode — full-screen terminal UI with Textual."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from rich.console import Console

from .core.config import Config
from .core.logger import get_logger

console = Console()
log = get_logger("tui")


@dataclass
class ApEntry:
    bssid: str
    essid: str = ""
    channel: int = 0
    signal: int = 0
    encryption: str = ""
    clients: int = 0
    selected: bool = False


@dataclass
class TuiState:
    aps: list[ApEntry] = field(default_factory=list)
    selected_ap: ApEntry | None = None
    attack_running: bool = False
    attack_status: str = ""
    alerts: list[str] = field(default_factory=list)
    status_line: str = "Ready"
    scan_active: bool = False


def _signal_bar(rssi: int) -> str:
    if rssi >= -50:
        return "█████"
    if rssi >= -60:
        return "████░"
    if rssi >= -70:
        return "███░░"
    if rssi >= -80:
        return "██░░░"
    if rssi >= -90:
        return "█░░░░"
    return "░░░░░"


def run_tui(config: Config) -> None:
    try:
        from textual.app import App, ComposeResult
        from textual.binding import Binding
        from textual.containers import Container, Vertical
        from textual.widgets import DataTable, Footer, Header, Static
    except ImportError:
        console.print("[red]Textual not installed — run: pip install textual[/red]")
        console.print("[dim]TUI mode requires: pip install 'voidfreq[tui]'[/dim]")
        return

    state = TuiState()

    class ApListWidget(Static):
        def compose(self) -> ComposeResult:
            yield DataTable(id="ap-table")

        def on_mount(self) -> None:
            table = self.query_one("#ap-table", DataTable)
            table.add_columns("BSSID", "ESSID", "CH", "Signal", "Enc", "Clients")
            table.cursor_type = "row"

    class AttackPanel(Static):
        def compose(self) -> ComposeResult:
            yield Static("No target selected", id="attack-status")

        def update_status(self, text: str) -> None:
            widget = self.query_one("#attack-status", Static)
            widget.update(text)

    class AlertPanel(Static):
        def compose(self) -> ComposeResult:
            yield Static("No alerts", id="alert-log")

        def add_alert(self, text: str) -> None:
            widget = self.query_one("#alert-log", Static)
            state.alerts.append(f"[{time.strftime('%H:%M:%S')}] {text}")
            widget.update("\n".join(state.alerts[-20:]))

    class VoidFreqTui(App):
        CSS = """
        Screen {
            layout: grid;
            grid-size: 2 2;
            grid-rows: 3fr 1fr;
        }
        #ap-panel {
            column-span: 1;
            border: solid $primary;
        }
        #attack-panel {
            column-span: 1;
            border: solid $accent;
        }
        #alert-panel {
            column-span: 2;
            border: solid $warning;
        }
        DataTable {
            height: 100%;
        }
        """

        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("s", "scan", "Scan"),
            Binding("a", "attack", "Attack"),
            Binding("m", "monitor", "Monitor"),
            Binding("r", "refresh", "Refresh"),
            Binding("escape", "deselect", "Deselect"),
        ]

        TITLE = "VoidFreq"
        SUB_TITLE = "WiFi Red/Blue Team Framework"

        def compose(self) -> ComposeResult:
            yield Header()
            with Container():
                with Vertical(id="ap-panel"):
                    yield Static("[bold]Access Points[/bold]")
                    yield ApListWidget()
                with Vertical(id="attack-panel"):
                    yield Static("[bold]Attack Status[/bold]")
                    yield AttackPanel()
            with Container(id="alert-panel"):
                yield Static("[bold]Alerts[/bold]")
                yield AlertPanel()
            yield Footer()

        def action_scan(self) -> None:
            self.notify("Scan started — press 'r' to refresh results")
            state.scan_active = True
            state.status_line = "Scanning..."

        def action_attack(self) -> None:
            if not state.selected_ap:
                self.notify("Select a target AP first", severity="warning")
                return
            self.notify(f"Attack started on {state.selected_ap.bssid}")
            state.attack_running = True

        def action_monitor(self) -> None:
            self.notify("Blue team monitoring active")

        def action_refresh(self) -> None:
            self._update_ap_table()

        def action_deselect(self) -> None:
            state.selected_ap = None
            self.notify("Target deselected")

        def _update_ap_table(self) -> None:
            try:
                table = self.query_one("#ap-table", DataTable)
            except Exception:
                return

            table.clear()
            for ap in state.aps:
                bar = _signal_bar(ap.signal)
                table.add_row(
                    ap.bssid,
                    ap.essid or "[hidden]",
                    str(ap.channel),
                    f"{bar} {ap.signal}dBm",
                    ap.encryption,
                    str(ap.clients),
                )

    app = VoidFreqTui()
    app.run()
