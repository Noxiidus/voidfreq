"""Tests for OPSEC engine."""

from unittest.mock import patch, MagicMock
import subprocess

import pytest

from voidfreq.core.config import Config, StealthProfile
from voidfreq.core.opsec import OpsecEngine, OpsecState, _random_hex, _random_hostname


def test_random_hex():
    result = _random_hex(3)
    assert len(result) == 6
    assert all(c in "0123456789abcdef" for c in result)


def test_random_hex_different():
    results = {_random_hex(3) for _ in range(20)}
    assert len(results) > 1


def test_random_hostname():
    name = _random_hostname()
    assert isinstance(name, str)
    assert len(name) > 0


def test_random_hostname_patterns():
    names = {_random_hostname() for _ in range(50)}
    has_desktop = any(n.startswith("DESKTOP-") for n in names)
    has_android = any(n.startswith("android-") or n.startswith("Galaxy-") for n in names)
    assert has_desktop or has_android


def test_opsec_state_defaults():
    state = OpsecState()
    assert state.original_mac is None
    assert state.original_hostname is None
    assert state.current_mac is None
    assert state.interface == "wlan0"
    assert state.modifications == []


def test_engine_init():
    config = Config()
    engine = OpsecEngine(config)
    assert engine.state.interface == "wlan0"
    assert engine.profile.mac_rotation is False


def test_jitter_disabled():
    config = Config(stealth=StealthProfile(timing_jitter=False))
    engine = OpsecEngine(config)

    import time
    start = time.time()
    engine.jitter(1.0)
    elapsed = time.time() - start
    assert elapsed < 0.1


@patch("voidfreq.core.opsec.OpsecEngine._run")
def test_jitter_enabled(mock_run):
    config = Config(stealth=StealthProfile(timing_jitter=True))
    engine = OpsecEngine(config)

    import time
    start = time.time()
    engine.jitter(0.1)
    elapsed = time.time() - start
    assert elapsed >= 0.1


def test_status():
    config = Config(stealth_level="ghost")
    engine = OpsecEngine(config)
    status = engine.status()

    assert status["interface"] == "wlan0"
    assert status["stealth_level"] == "ghost"
    assert status["modifications"] == []


@patch("voidfreq.core.opsec.OpsecEngine._run")
def test_save_original_state(mock_run):
    mock_run.side_effect = [
        MagicMock(returncode=0, stdout="2: wlan0: <BROADCAST> mtu 1500\n    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff"),
        MagicMock(returncode=0, stdout="testhost\n"),
    ]

    config = Config()
    engine = OpsecEngine(config)
    engine.save_original_state()

    assert engine.state.original_mac == "aa:bb:cc:dd:ee:ff"
    assert engine.state.original_hostname == "testhost"


@patch("voidfreq.core.opsec.OpsecEngine._run")
def test_save_original_state_no_overwrite(mock_run):
    config = Config()
    engine = OpsecEngine(config)
    engine.state.original_mac = "11:22:33:44:55:66"
    engine.save_original_state()

    mock_run.assert_not_called()
    assert engine.state.original_mac == "11:22:33:44:55:66"


@patch("voidfreq.core.opsec.OpsecEngine._run")
def test_rotate_mac_disabled(mock_run):
    config = Config(stealth=StealthProfile(mac_rotation=False))
    engine = OpsecEngine(config)
    result = engine.rotate_mac()

    assert result is None
    mock_run.assert_not_called()


@patch("voidfreq.core.opsec.OpsecEngine._run")
def test_rotate_mac_enabled(mock_run):
    mock_run.return_value = MagicMock(returncode=0)

    config = Config(stealth=StealthProfile(mac_rotation=True))
    engine = OpsecEngine(config)
    result = engine.rotate_mac()

    assert result is not None
    assert len(result) == 17
    assert engine.state.current_mac == result
    assert len(engine.state.modifications) == 1
