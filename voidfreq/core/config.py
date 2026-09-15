"""Configuration loader and stealth profile manager."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    pass


VALID_STEALTH_LEVELS = ("low", "medium", "high", "ghost")
VALID_SCAN_TIMINGS = ("aggressive", "normal", "paranoid", "stealth")
VALID_REPORT_FORMATS = ("markdown", "json")


@dataclass
class StealthProfile:
    mac_rotation: bool = False
    timing_jitter: bool = False
    deauth_allowed: bool = True
    deauth_max_packets: int = 50
    scan_timing: str = "aggressive"
    fingerprint_spoof: bool = False
    probe_suppress: bool = False
    threat_detection: bool = False
    auto_killswitch: bool = False
    tx_power_adjust: bool = False
    channel_hop_random: bool = False
    burst_limit: bool = False


@dataclass
class Config:
    interface: str = "wlan0"
    stealth_level: str = "high"
    stealth: StealthProfile = field(default_factory=StealthProfile)
    wordlist: str = "/usr/share/wordlists/rockyou.txt"
    use_hashcat: bool = True
    hashcat_mode: int = 22000
    mitm_arp_rate: float = 0.5
    mitm_fullduplex: bool = True
    mitm_capture: list[str] = field(default_factory=lambda: ["dns", "sni", "http_credentials"])
    report_format: str = "markdown"
    report_dir: str = "./reports"
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


def _validate(raw: dict) -> None:
    vf = raw.get("voidfreq", {})
    if not isinstance(vf, dict):
        raise ConfigError("'voidfreq' key must be a mapping")

    stealth = vf.get("stealth")
    if stealth and stealth not in VALID_STEALTH_LEVELS:
        raise ConfigError(
            f"Invalid stealth level '{stealth}' — must be one of {VALID_STEALTH_LEVELS}"
        )

    profiles = vf.get("stealth_profiles", {})
    if not isinstance(profiles, dict):
        raise ConfigError("'stealth_profiles' must be a mapping")

    for name, profile in profiles.items():
        if not isinstance(profile, dict):
            raise ConfigError(f"Stealth profile '{name}' must be a mapping")
        timing = profile.get("scan_timing")
        if timing and timing not in VALID_SCAN_TIMINGS:
            raise ConfigError(
                f"Invalid scan_timing '{timing}' in profile '{name}' — "
                f"must be one of {VALID_SCAN_TIMINGS}"
            )
        max_pkts = profile.get("deauth_max_packets")
        if max_pkts is not None and (not isinstance(max_pkts, int) or max_pkts < 0):
            raise ConfigError(
                f"deauth_max_packets in profile '{name}' must be a non-negative integer"
            )

    cracking = vf.get("cracking", {})
    if not isinstance(cracking, dict):
        raise ConfigError("'cracking' must be a mapping")

    mode = cracking.get("hashcat_mode")
    if mode is not None and not isinstance(mode, int):
        raise ConfigError("hashcat_mode must be an integer")

    reporting = vf.get("reporting", {})
    fmt = reporting.get("format")
    if fmt and fmt not in VALID_REPORT_FORMATS:
        raise ConfigError(
            f"Invalid report format '{fmt}' — must be one of {VALID_REPORT_FORMATS}"
        )


def load_config(path: str | Path = "config.yaml") -> Config:
    path = Path(path)
    if not path.exists():
        return Config()

    try:
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"Failed to parse {path}: {e}") from e

    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a YAML mapping, got {type(raw).__name__}")

    _validate(raw)

    vf = raw.get("voidfreq", {})
    stealth_level = vf.get("stealth", "high")
    profiles = vf.get("stealth_profiles", {})
    profile_data = profiles.get(stealth_level, {})

    stealth = StealthProfile(**{
        k: v for k, v in profile_data.items()
        if k in StealthProfile.__dataclass_fields__
    })

    cracking = vf.get("cracking", {})
    mitm = vf.get("mitm", {})
    reporting = vf.get("reporting", {})

    return Config(
        interface=vf.get("interface", "wlan0"),
        stealth_level=stealth_level,
        stealth=stealth,
        wordlist=cracking.get("wordlist", "/usr/share/wordlists/rockyou.txt"),
        use_hashcat=cracking.get("use_hashcat", True),
        hashcat_mode=cracking.get("hashcat_mode", 22000),
        mitm_arp_rate=mitm.get("arp_rate", 0.5),
        mitm_fullduplex=mitm.get("fullduplex", True),
        mitm_capture=mitm.get("capture", ["dns", "sni", "http_credentials"]),
        report_format=reporting.get("format", "markdown"),
        report_dir=reporting.get("output_dir", "./reports"),
        raw=raw,
    )
