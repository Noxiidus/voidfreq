"""Tests for config loader and validation."""

import os
import tempfile

import pytest

from voidfreq.core.config import (
    ConfigError,
    StealthProfile,
    load_config,
)


def test_default_config():
    config = load_config("nonexistent.yaml")
    assert config.interface == "wlan0"
    assert config.stealth_level == "high"
    assert config.use_hashcat is True
    assert config.hashcat_mode == 22000


def test_stealth_profile_defaults():
    p = StealthProfile()
    assert p.mac_rotation is False
    assert p.timing_jitter is False
    assert p.deauth_allowed is True
    assert p.deauth_max_packets == 50
    assert p.scan_timing == "aggressive"


def test_load_valid_config():
    content = """
voidfreq:
  interface: wlan1
  stealth: medium
  stealth_profiles:
    medium:
      mac_rotation: true
      timing_jitter: true
      deauth_allowed: true
      deauth_max_packets: 3
  cracking:
    wordlist: /tmp/test.txt
    use_hashcat: false
  reporting:
    format: json
    output_dir: /tmp/reports
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        f.flush()
    try:
        config = load_config(f.name)
        assert config.interface == "wlan1"
        assert config.stealth_level == "medium"
        assert config.stealth.mac_rotation is True
        assert config.stealth.timing_jitter is True
        assert config.stealth.deauth_max_packets == 3
        assert config.wordlist == "/tmp/test.txt"
        assert config.use_hashcat is False
        assert config.report_format == "json"
    finally:
        os.unlink(f.name)


def test_invalid_stealth_level():
    content = """
voidfreq:
  stealth: ultra
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        f.flush()
    try:
        with pytest.raises(ConfigError, match="Invalid stealth level 'ultra'"):
            load_config(f.name)
    finally:
        os.unlink(f.name)


def test_invalid_scan_timing():
    content = """
voidfreq:
  stealth: low
  stealth_profiles:
    low:
      scan_timing: turbo
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        f.flush()
    try:
        with pytest.raises(ConfigError, match="Invalid scan_timing 'turbo'"):
            load_config(f.name)
    finally:
        os.unlink(f.name)


def test_invalid_deauth_packets():
    content = """
voidfreq:
  stealth: low
  stealth_profiles:
    low:
      deauth_max_packets: -5
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        f.flush()
    try:
        with pytest.raises(ConfigError, match="deauth_max_packets"):
            load_config(f.name)
    finally:
        os.unlink(f.name)


def test_invalid_yaml():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("invalid: yaml: [broken")
        f.flush()
    try:
        with pytest.raises(ConfigError, match="Failed to parse"):
            load_config(f.name)
    finally:
        os.unlink(f.name)


def test_non_dict_yaml():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("- just\n- a\n- list\n")
        f.flush()
    try:
        with pytest.raises(ConfigError, match="must contain a YAML mapping"):
            load_config(f.name)
    finally:
        os.unlink(f.name)


def test_invalid_report_format():
    content = """
voidfreq:
  reporting:
    format: pdf
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        f.flush()
    try:
        with pytest.raises(ConfigError, match="Invalid report format 'pdf'"):
            load_config(f.name)
    finally:
        os.unlink(f.name)


def test_empty_config_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("")
        f.flush()
    try:
        config = load_config(f.name)
        assert config.interface == "wlan0"
    finally:
        os.unlink(f.name)


def test_config_raw_preserved():
    content = """
voidfreq:
  interface: wlan0
  custom_key: custom_value
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        f.flush()
    try:
        config = load_config(f.name)
        assert config.raw["voidfreq"]["custom_key"] == "custom_value"
    finally:
        os.unlink(f.name)
