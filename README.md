# VoidFreq

**WiFi Red/Blue Team Framework** — all-in-one offensive and defensive wireless security testing with built-in OPSEC.

```
 ██╗   ██╗ ██████╗ ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗
 ██║   ██║██╔═══██╗██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗
 ██║   ██║██║   ██║██║██║  ██║█████╗  ██████╔╝█████╗  ██║   ██║
 ╚██╗ ██╔╝██║   ██║██║██║  ██║██╔══╝  ██╔══██╗██╔══╝  ██║▄▄ ██║
  ╚████╔╝ ╚██████╔╝██║██████╔╝██║     ██║  ██║███████╗╚██████╔╝
   ╚═══╝   ╚═════╝ ╚═╝╚═════╝ ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚══▀▀═╝
```

VoidFreq wraps aircrack-ng, hcxdumptool, tshark, arpspoof and other industry-standard tools into a single framework with **automatic stealth** at every step. Attack, intercept, and monitor — while minimizing your footprint.

> **⚠️ Legal disclaimer:** This tool is for authorized penetration testing and educational purposes only. Only use it on networks you own or have explicit written permission to test. Unauthorized access to computer networks is illegal.

## Features

### Red Team (Offensive)
- **Passive recon** — AP and client enumeration with vendor resolution
- **PMKID capture** — silent attack, no deauth required
- **Passive handshake** — wait for natural reconnects
- **Targeted deauth** — minimal packets, single client (when stealth allows)
- **Auto cracking** — hashcat (GPU) with aircrack-ng fallback
- **MITM** — ARP spoofing with DNS, SNI, and HTTP traffic capture
- **Credential sniffing** — HTTP form data extraction

### Blue Team (Defensive)
- **ARP anomaly detection** — duplicate MAC / IP-MAC change alerts
- **Deauth flood detection** — windowed frame counting
- **New device alerts** — unknown MAC notifications
- **Live dashboard** — real-time alert monitoring with Rich TUI

### OPSEC Engine (Always Active)
- **MAC rotation** — vendor-aware random MAC before each operation
- **Hostname spoofing** — realistic Windows/Android hostnames
- **Timing jitter** — randomized delays to evade IDS thresholds
- **Probe suppression** — suppress probe requests in monitor mode
- **Fingerprint spoofing** — OS fingerprint modification
- **Kill switch** — auto-stop on detection
- **Auto-cleanup** — restore MAC, hostname, routes on exit

## Installation

### Prerequisites

**Platform:** Linux with a monitor-mode capable WiFi adapter (Atheros AR9271 or Realtek RTL8812AU recommended).

```bash
# Kali Linux (most tools pre-installed)
sudo apt install aircrack-ng hcxdumptool hcxpcapngtool hashcat tshark dsniff nmap

# Ubuntu/Debian
sudo apt install aircrack-ng tshark dsniff nmap
# hcxdumptool and hashcat: install from source for latest version
```

### Install VoidFreq

```bash
git clone https://github.com/Noxiidus/voidfreq.git
cd voidfreq
pip install -e .
```

### Verify dependencies

```bash
voidfreq check
```

## Usage

### Quick start — full automated chain

```bash
# Automated recon → capture → crack with high stealth
sudo voidfreq auto -t <AP_BSSID> -ch <CHANNEL> -s high
```

### Individual modules

```bash
# Passive reconnaissance (30 seconds)
sudo voidfreq recon -d 30

# Attack specific AP (PMKID → passive → deauth fallback)
sudo voidfreq attack -t AA:BB:CC:DD:EE:FF -ch 6

# Attack with specific client target, no cracking
sudo voidfreq attack -t AA:BB:CC:DD:EE:FF -ch 6 --client 11:22:33:44:55:66 --no-crack

# MITM with live dashboard
sudo voidfreq mitm -t 192.168.1.50 -g 192.168.1.1 --dashboard

# Blue team monitoring with live dashboard
sudo voidfreq monitor --dashboard

# OPSEC status
sudo voidfreq opsec --status

# Restore original state
sudo voidfreq opsec --cleanup
```

### Stealth levels

| Level | MAC Rotate | Jitter | Deauth | Scan Speed | Kill Switch |
|-------|-----------|--------|--------|------------|-------------|
| `low` | ❌ | ❌ | ✅ (50 pkts) | Aggressive | ❌ |
| `medium` | ✅ | ✅ | ✅ (3 pkts) | Normal | ❌ |
| `high` | ✅ | ✅ | ❌ | Paranoid | ✅ |
| `ghost` | ✅ | ✅ | ❌ | Stealth | ✅ |

```bash
# Override stealth level
sudo voidfreq auto -t <BSSID> -ch 6 -s ghost
```

## Architecture

```
voidfreq/
├── core/
│   ├── config.py      # YAML config loader, stealth profiles
│   ├── interface.py   # Monitor mode, channel control
│   └── opsec.py       # OPSEC engine — MAC/hostname/jitter/cleanup
├── modules/
│   ├── recon.py       # Passive AP/client scanning
│   ├── attack.py      # PMKID/handshake capture + cracking
│   ├── mitm.py        # ARP spoof + DNS/SNI/HTTP capture
│   └── monitor.py     # Blue team detection & alerting
├── utils/
│   ├── deps.py        # Dependency checker
│   └── report.py      # Markdown/JSON report generator
└── cli.py             # CLI entry point
```

## Configuration

Edit `config.yaml` to customize behavior:

```yaml
voidfreq:
  interface: wlan0
  stealth: high

  cracking:
    wordlist: /usr/share/wordlists/rockyou.txt
    use_hashcat: true

  mitm:
    arp_rate: 0.5
    fullduplex: true
    capture: [dns, sni, http_credentials]

  monitor:
    arp_anomaly: true
    deauth_detection: true
    rogue_ap_detection: true
    new_device_alert: true
```

## Recommended Lab Setup

1. **Router** — any home router with WPA2
2. **Attacker** — Kali Linux + external WiFi adapter (monitor mode capable)
3. **Target** — old phone/laptop on the network
4. **Monitoring** — second terminal running `voidfreq monitor --dashboard`

## License

MIT — see [LICENSE](LICENSE).
