"""Tests for WPA3/SAE module."""

from unittest.mock import MagicMock, patch

from voidfreq.core.config import Config, StealthProfile
from voidfreq.core.opsec import OpsecEngine
from voidfreq.modules.wpa3 import Wpa3AttackResult, Wpa3Info, Wpa3Module


def _make_module():
    config = Config(
        interface="wlan0",
        stealth=StealthProfile(),
        stealth_level="high",
        raw={},
    )
    opsec = MagicMock(spec=OpsecEngine)
    return Wpa3Module(config, opsec)


class TestWpa3Info:
    def test_defaults(self):
        info = Wpa3Info(bssid="AA:BB:CC:DD:EE:FF")
        assert info.sae_only is False
        assert info.transition_mode is False
        assert info.pmf_required is False
        assert info.akm_suites == []

    def test_attack_result_defaults(self):
        r = Wpa3AttackResult(success=False, attack_type="test")
        assert r.capture_file is None
        assert r.password is None
        assert r.details == {}


class TestRsnParsing:
    def test_parse_rsn_sae_only(self):
        mod = _make_module()
        info = Wpa3Info(bssid="AA:BB:CC:DD:EE:FF")

        rsn = bytearray([
            0x01, 0x00,             # version
            0x00, 0x0F, 0xAC, 0x04, # group cipher (CCMP)
            0x01, 0x00,             # pairwise count
            0x00, 0x0F, 0xAC, 0x04, # pairwise cipher (CCMP)
            0x01, 0x00,             # AKM count
            0x00, 0x0F, 0xAC, 0x08, # AKM: SAE (8)
            0xC0, 0x00,             # RSN caps: PMF capable + required
        ])

        mod._parse_rsn_ie(bytes(rsn), info)
        assert "SAE" in info.akm_suites
        assert info.sae_only is True
        assert info.transition_mode is False
        assert info.pmf_capable is True
        assert info.pmf_required is True

    def test_parse_rsn_transition_mode(self):
        mod = _make_module()
        info = Wpa3Info(bssid="AA:BB:CC:DD:EE:FF")

        rsn = bytearray([
            0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x04,
            0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x04,
            0x02, 0x00,             # 2 AKM suites
            0x00, 0x0F, 0xAC, 0x01, # WPA2-PSK (AKM ID 1)
            0x00, 0x0F, 0xAC, 0x08, # SAE
            0x40, 0x00,             # PMF capable, not required
        ])

        mod._parse_rsn_ie(bytes(rsn), info)
        assert "WPA2-PSK" in info.akm_suites[0]
        assert "SAE" in info.akm_suites
        assert info.transition_mode is True
        assert info.sae_only is False
        assert info.pmf_capable is True
        assert info.pmf_required is False

    def test_parse_rsn_wpa2_only(self):
        mod = _make_module()
        info = Wpa3Info(bssid="AA:BB:CC:DD:EE:FF")

        rsn = bytearray([
            0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x04,
            0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x04,
            0x01, 0x00,             # 1 AKM
            0x00, 0x0F, 0xAC, 0x02, # WPA2-PSK (not SAE)
            0x00, 0x00,             # no PMF
        ])

        mod._parse_rsn_ie(bytes(rsn), info)
        assert info.sae_only is False
        assert info.transition_mode is False

    def test_parse_rsn_truncated(self):
        mod = _make_module()
        info = Wpa3Info(bssid="AA:BB:CC:DD:EE:FF")
        mod._parse_rsn_ie(b"\x01\x00", info)
        assert info.akm_suites == []


class TestDisplayAndDict:
    def test_to_dict(self):
        mod = _make_module()
        info = Wpa3Info(
            bssid="AA:BB:CC:DD:EE:FF",
            essid="TestNet",
            sae_only=True,
            akm_suites=["SAE"],
        )
        d = mod.to_dict(info)
        assert d["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert d["sae_only"] is True
        assert d["akm_suites"] == ["SAE"]

    def test_display_info_no_crash(self):
        mod = _make_module()
        info = Wpa3Info(bssid="AA:BB:CC:DD:EE:FF")
        mod._display_info(info)

        info.transition_mode = True
        mod._display_info(info)

        info.transition_mode = False
        info.sae_only = True
        mod._display_info(info)


class TestTransitionDowngrade:
    @patch("voidfreq.modules.wpa3.subprocess")
    def test_downgrade_no_handshake(self, mock_sub):
        mod = _make_module()

        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_sub.Popen.return_value = mock_proc
        mock_sub.run.return_value = MagicMock(stdout="", returncode=0)

        result = mod.transition_downgrade(
            "wlan0mon", "AA:BB:CC:DD:EE:FF", 6,
            output_dir="/tmp/test_wpa3",
            duration=5,
        )
        assert result.success is False
        assert result.attack_type == "transition_downgrade"


class TestTimingAttack:
    def test_timing_no_scapy(self):
        with patch.dict("sys.modules", {"scapy": None, "scapy.all": None}):
            pass

    def test_timing_result_structure(self):
        r = Wpa3AttackResult(
            success=True,
            attack_type="sae_timing",
            details={"frame_count": 10, "avg_response_ms": 5.0},
        )
        assert r.details["frame_count"] == 10
