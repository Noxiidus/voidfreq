# VoidFreq Config Schema

Default location: `config.yaml` in the project root.
User override: `~/.voidfreq/config.yaml`

All keys are under the top-level `voidfreq:` mapping.

---

## Top-level keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `interface` | string | `"wlan0"` | WiFi interface name |
| `stealth` | string | `"high"` | Active stealth level: `low`, `medium`, `high`, `ghost` |
| `stealth_profiles` | mapping | (see below) | Named stealth profiles |
| `cracking` | mapping | (see below) | Hash cracking settings |
| `mitm` | mapping | (see below) | MITM module settings |
| `reporting` | mapping | (see below) | Report output settings |

---

## `stealth_profiles.<name>`

Each profile is a mapping. Valid profile names: `low`, `medium`, `high`, `ghost`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mac_rotation` | bool | `false` | Rotate MAC before each operation |
| `timing_jitter` | bool | `false` | Add random delay between operations |
| `deauth_allowed` | bool | `true` | Allow deauthentication attacks |
| `deauth_max_packets` | int >= 0 | `50` | Max deauth frames per burst |
| `scan_timing` | string | `"aggressive"` | nmap timing: `aggressive`, `normal`, `paranoid`, `stealth` |
| `fingerprint_spoof` | bool | `false` | Spoof TCP/IP fingerprint (TTL, window size) |
| `probe_suppress` | bool | `false` | Suppress outgoing probe requests |
| `threat_detection` | bool | `false` | Check for IDS/WIDS before attacking |
| `auto_killswitch` | bool | `false` | Abort and clean up on threat detection |
| `tx_power_adjust` | bool | `false` | Lower TX power to reduce detection range |
| `channel_hop_random` | bool | `false` | Randomize channel hop order in recon |
| `burst_limit` | bool | `false` | Rate-limit deauth bursts |

### Example profile

```yaml
stealth_profiles:
  ghost:
    mac_rotation: true
    timing_jitter: true
    deauth_allowed: false
    scan_timing: stealth
    fingerprint_spoof: true
    probe_suppress: true
    threat_detection: true
    auto_killswitch: true
    tx_power_adjust: true
    channel_hop_random: true
    burst_limit: true
```

---

## `cracking`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `wordlist` | string | `"/usr/share/wordlists/rockyou.txt"` | Path to wordlist file |
| `use_hashcat` | bool | `true` | Prefer hashcat (GPU) over aircrack-ng (CPU) |
| `hashcat_mode` | int | `22000` | Hashcat mode (22000 = WPA-PBKDF2-PMKID+EAPOL) |

---

## `mitm`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `arp_rate` | float | `0.5` | ARP spoofing packet rate (seconds between bursts) |
| `fullduplex` | bool | `true` | Spoof both directions (target→gateway + gateway→target) |
| `capture` | list[string] | `["dns", "sni", "http_credentials"]` | Traffic capture types |

Valid capture types: `dns`, `sni`, `http_credentials`

---

## `reporting`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `format` | string | `"markdown"` | Report format: `markdown`, `json`, `both` |
| `output_dir` | string | `"./reports"` | Output directory for generated reports |

---

## Full example

```yaml
voidfreq:
  interface: wlan0mon
  stealth: high

  stealth_profiles:
    low:
      mac_rotation: false
      deauth_allowed: true
      deauth_max_packets: 100
      scan_timing: aggressive

    medium:
      mac_rotation: true
      timing_jitter: true
      deauth_allowed: true
      deauth_max_packets: 30
      scan_timing: normal

    high:
      mac_rotation: true
      timing_jitter: true
      deauth_allowed: true
      deauth_max_packets: 10
      scan_timing: paranoid
      fingerprint_spoof: true
      threat_detection: true

    ghost:
      mac_rotation: true
      timing_jitter: true
      deauth_allowed: false
      scan_timing: stealth
      fingerprint_spoof: true
      probe_suppress: true
      threat_detection: true
      auto_killswitch: true
      tx_power_adjust: true
      channel_hop_random: true
      burst_limit: true

  cracking:
    wordlist: /usr/share/wordlists/rockyou.txt
    use_hashcat: true
    hashcat_mode: 22000

  mitm:
    arp_rate: 0.5
    fullduplex: true
    capture:
      - dns
      - sni
      - http_credentials

  reporting:
    format: both
    output_dir: ./reports
```

---

## Validation

Config loading validates:
- `stealth` must be one of: `low`, `medium`, `high`, `ghost`
- `scan_timing` must be one of: `aggressive`, `normal`, `paranoid`, `stealth`
- `deauth_max_packets` must be a non-negative integer
- `hashcat_mode` must be an integer
- `format` must be one of: `markdown`, `json`, `both`

Invalid config raises `ConfigError` with a human-readable message.
