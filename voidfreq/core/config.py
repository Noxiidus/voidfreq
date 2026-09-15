"""Configuration loader and stealth profile manager."""

from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


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


def load_config(path: str | Path = "config.yaml") -> Config:
    path = Path(path)
    if not path.exists():
        return Config()

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

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
