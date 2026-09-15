"""Tests for TUI module."""

from unittest.mock import patch

from voidfreq.core.config import Config, StealthProfile
from voidfreq.tui import ApEntry, TuiState, _signal_bar


class TestSignalBar:
    def test_excellent_signal(self):
        assert _signal_bar(-40) == "█████"

    def test_good_signal(self):
        assert _signal_bar(-55) == "████░"

    def test_fair_signal(self):
        assert _signal_bar(-65) == "███░░"

    def test_weak_signal(self):
        assert _signal_bar(-75) == "██░░░"

    def test_very_weak_signal(self):
        assert _signal_bar(-85) == "█░░░░"

    def test_no_signal(self):
        assert _signal_bar(-100) == "░░░░░"


class TestApEntry:
    def test_defaults(self):
        ap = ApEntry(bssid="AA:BB:CC:DD:EE:FF")
        assert ap.essid == ""
        assert ap.channel == 0
        assert ap.signal == 0
        assert ap.selected is False

    def test_custom(self):
        ap = ApEntry(
            bssid="AA:BB:CC:DD:EE:FF",
            essid="TestNet",
            channel=6,
            signal=-45,
            encryption="WPA2",
            clients=3,
        )
        assert ap.essid == "TestNet"
        assert ap.channel == 6


class TestTuiState:
    def test_defaults(self):
        state = TuiState()
        assert state.aps == []
        assert state.selected_ap is None
        assert state.attack_running is False
        assert state.status_line == "Ready"

    def test_with_aps(self):
        aps = [
            ApEntry(bssid="AA:BB:CC:DD:EE:FF", essid="Net1"),
            ApEntry(bssid="11:22:33:44:55:66", essid="Net2"),
        ]
        state = TuiState(aps=aps)
        assert len(state.aps) == 2


class TestRunTui:
    @patch("voidfreq.tui.console")
    def test_run_without_textual(self, mock_console):
        config = Config(
            interface="wlan0",
            stealth=StealthProfile(),
            stealth_level="high",
            raw={},
        )
        with patch.dict("sys.modules", {"textual": None, "textual.app": None}):
            from voidfreq.tui import run_tui
            run_tui(config)
