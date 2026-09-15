"""Tests for attack module — PMF-aware strategy selection and hash auto-export."""

from unittest.mock import MagicMock, patch

import pytest

from voidfreq.modules.attack import AttackModule, AttackStrategy, CaptureResult


@pytest.fixture()
def attack():
    config = MagicMock()
    config.stealth.deauth_allowed = True
    opsec = MagicMock()
    return AttackModule(config, opsec)


class TestStrategySelection:
    def test_default_order(self, attack):
        strategies = attack.select_strategy()
        assert strategies == [
            AttackStrategy.PMKID,
            AttackStrategy.PASSIVE,
            AttackStrategy.DEAUTH,
        ]

    def test_no_deauth_when_not_allowed(self, attack):
        attack.config.stealth.deauth_allowed = False
        strategies = attack.select_strategy()
        assert AttackStrategy.DEAUTH not in strategies

    def test_pmf_required_skips_deauth(self, attack):
        pmf_info = {"pmf_required": True, "pmf_capable": True}
        strategies = attack.select_strategy(pmf_info=pmf_info)
        assert AttackStrategy.DEAUTH not in strategies
        assert AttackStrategy.PMKID in strategies
        assert AttackStrategy.PASSIVE in strategies

    def test_pmf_capable_keeps_deauth(self, attack):
        pmf_info = {"pmf_required": False, "pmf_capable": True}
        strategies = attack.select_strategy(pmf_info=pmf_info)
        assert AttackStrategy.DEAUTH in strategies

    def test_no_pmf_keeps_deauth(self, attack):
        pmf_info = {"pmf_required": False, "pmf_capable": False}
        strategies = attack.select_strategy(pmf_info=pmf_info)
        assert AttackStrategy.DEAUTH in strategies

    def test_none_pmf_info(self, attack):
        strategies = attack.select_strategy(pmf_info=None)
        assert AttackStrategy.DEAUTH in strategies


class TestAutoHashExport:
    def test_already_has_hash(self, attack):
        result = CaptureResult(
            success=True, strategy=AttackStrategy.PMKID,
            capture_file="/tmp/test.pcapng", hash_file="/tmp/test.hc22000",
        )
        out = attack._auto_export_hash(result, "/tmp")
        assert out.hash_file == "/tmp/test.hc22000"

    def test_no_capture_file(self, attack):
        result = CaptureResult(
            success=True, strategy=AttackStrategy.PASSIVE,
            capture_file=None,
        )
        out = attack._auto_export_hash(result, "/tmp")
        assert out.hash_file is None

    def test_hcxpcapngtool_not_found(self, attack, tmp_path):
        cap_file = tmp_path / "test.cap"
        cap_file.write_bytes(b"\x00" * 100)

        result = CaptureResult(
            success=True, strategy=AttackStrategy.DEAUTH,
            capture_file=str(cap_file),
        )

        with patch("voidfreq.modules.attack.subprocess.run", side_effect=FileNotFoundError):
            out = attack._auto_export_hash(result, str(tmp_path))

        assert out.hash_file is None

    def test_successful_hash_export(self, attack, tmp_path):
        cap_file = tmp_path / "test.cap"
        cap_file.write_bytes(b"\x00" * 100)
        hash_file = tmp_path / "test.hc22000"
        hash_file.write_text("WPA*02*hash*data")

        result = CaptureResult(
            success=True, strategy=AttackStrategy.DEAUTH,
            capture_file=str(cap_file),
        )

        mock_run = MagicMock(returncode=0)
        with patch("voidfreq.modules.attack.subprocess.run", return_value=mock_run):
            out = attack._auto_export_hash(result, str(tmp_path))

        assert out.hash_file == str(tmp_path / "test.hc22000")
