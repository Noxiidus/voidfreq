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

VoidFreq wraps aircrack-ng, hcxdumptool, tshark, nmap, hostapd, and other industry-standard tools into a single framework with **automatic stealth** at every step. Attack, intercept, and monitor — while minimizing your footprint.

> **Legal disclaimer:** This tool is for authorized penetration testing and educational purposes only. Only use it on networks you own or have explicit written permission to test. Unauthorized access to computer networks is illegal.

## Features

### Red Team (Offensive)
- **Passive recon** — AP and client enumeration with vendor resolution
- **PMKID capture** — silent attack, no deauth required
- **Passive handshake** — wait for natural reconnects
- **Targeted deauth** — minimal packets, single client (when stealth allows)
- **Scapy native packets** — deauth, beacon scan, probe injection, handshake capture without external tools
- **Auto cracking** — hashcat (GPU) with aircrack-ng fallback
- **Network scanning** — nmap-based host discovery, port scanning, vulnerability detection, OS fingerprinting
- **MITM** — ARP spoofing with DNS, SNI, and HTTP traffic capture
- **DNS spoofing** — redirect specific domains to attacker-controlled IPs
- **Evil Twin** — rogue AP with DHCP, NAT, optional captive portal, traffic capture
- **Captive portal** — credential harvesting HTTP server with custom templates
- **Credential sniffing** — HTTP form data extraction
- **Targeted wordlist generator** — ESSID-based wordlist with leet speak, years, common patterns
- **Pcap analyzer** — offline capture file analysis (DNS, SNI, HTTP, credentials, handshakes)
- **Hidden SSID reveal** — passive probe response monitoring

### Blue Team (Defensive)
- **ARP anomaly detection** — duplicate MAC / IP-MAC change alerts
- **Deauth flood detection** — windowed frame counting
- **New device alerts** — unknown MAC notifications
- **Threat assessment** — detect IDS/WIDS presence (Snort, Suricata, Kismet, enterprise APs)
- **Live dashboard** — real-time alert monitoring with Rich TUI

### OPSEC Engine (Always Active)
- **MAC rotation** — vendor-aware random MAC before each operation
- **Hostname spoofing** — realistic Windows/Android hostnames
- **Timing jitter** — randomized delays to evade IDS thresholds
- **Probe suppression** — suppress probe requests in monitor mode
- **Fingerprint spoofing** — OS fingerprint modification (TTL, window size)
- **Stealth scanning** — fragmented packets, decoy IPs, zombie scans
- **Threat detection** — IDS port scanning, enterprise AP identification
- **Kill switch** — auto-stop when defensive systems detected
- **Auto-cleanup** — restore MAC, hostname, routes, iptables on exit

### Session Management
- **Save/resume** — interrupt and resume pentest sessions
- **Phase tracking** — automatic progress through recon → capture → crack → access → mitm
- **Session export** — generate pentest reports from saved sessions

## Installation

### Prerequisites

**Platform:** Linux with a monitor-mode capable WiFi adapter (Atheros AR9271 or Realtek RTL8812AU recommended).

```bash
# Kali Linux (most tools pre-installed)
sudo apt install aircrack-ng hcxdumptool hcxpcapngtool hashcat tshark dsniff nmap hostapd dnsmasq

# Ubuntu/Debian
sudo apt install aircrack-ng tshark dsniff nmap hostapd dnsmasq
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

### Full system diagnostic

```bash
voidfreq doctor
```

Checks tool versions + paths, WiFi interfaces, kernel modules, Python packages, config validation, and feature availability. Run this before your first operation.

## Usage

### Quick start — full automated chain

```bash
# Automated recon → capture → crack → network enum with high stealth
sudo voidfreq auto -t <AP_BSSID> -ch <CHANNEL> -s high

# With session save (resume if interrupted)
sudo voidfreq auto -t <AP_BSSID> -ch <CHANNEL> --session "lab_test_1"

# Resume interrupted session
sudo voidfreq auto --resume <SESSION_ID> -t <AP_BSSID> -ch <CHANNEL>
```

### Reconnaissance

```bash
# Passive WiFi scan (30 seconds)
sudo voidfreq recon -d 30

# Extended scan (2 minutes)
sudo voidfreq recon -d 120 -s ghost
```

### Attack

```bash
# Attack AP (PMKID → passive → deauth fallback)
sudo voidfreq attack -t AA:BB:CC:DD:EE:FF -ch 6

# Target specific client, capture only
sudo voidfreq attack -t AA:BB:CC:DD:EE:FF -ch 6 --client 11:22:33:44:55:66 --no-crack
```

### Network scanning

```bash
# Host discovery
sudo voidfreq scan -t 192.168.1.0/24 --discover

# Port scan with service detection
sudo voidfreq scan -t 192.168.1.50 -p 1-65535

# Vulnerability scan
sudo voidfreq scan -t 192.168.1.50 --vuln

# OS detection
sudo voidfreq scan -t 192.168.1.50 --os
```

### MITM

```bash
# Basic MITM with live dashboard
sudo voidfreq mitm -t 192.168.1.50 -g 192.168.1.1 --dashboard

# MITM with DNS spoofing
sudo voidfreq mitm -t 192.168.1.50 -g 192.168.1.1 --dns-spoof login.example.com 192.168.1.100
```

### Evil Twin

```bash
# Open rogue AP
sudo voidfreq eviltwin -e "FreeWiFi" -ch 6

# WPA2 clone
sudo voidfreq eviltwin -e "TargetNetwork" -ch 6 --wpa "password123"

# With captive portal
sudo voidfreq eviltwin -e "CoffeeShop_WiFi" -ch 1 --captive
```

### Blue Team

```bash
# Network monitoring with live dashboard
sudo voidfreq monitor --dashboard

# Threat assessment (scan for IDS/WIDS)
sudo voidfreq threat -g 192.168.1.1
```

### Sessions

```bash
# List saved sessions
voidfreq session --list

# Show session details
voidfreq session --show <SESSION_ID>

# Export session report
voidfreq session --export <SESSION_ID>

# Delete session
voidfreq session --delete <SESSION_ID>
```

### Wordlist generator

```bash
# Generate targeted wordlist from ESSID
voidfreq wordlist -e "CoffeeShop_WiFi"

# With custom words and output path
voidfreq wordlist -e "CompanyNet" --words admin root guest -o custom_wordlist.txt

# Skip leet speak variants for a smaller list
voidfreq wordlist -e "HomeNetwork" --no-leet --no-years
```

### Pcap analyzer

```bash
# Analyze a capture file
voidfreq analyze capture.pcap

# Analyze and export results to JSON
voidfreq analyze capture.pcapng --export
```

### OPSEC

```bash
# Show OPSEC status
sudo voidfreq opsec --status

# Restore original state
sudo voidfreq opsec --cleanup
```

### Stealth levels

| Level | MAC Rotate | Jitter | Deauth | Scan Speed | Kill Switch | Decoys |
|-------|-----------|--------|--------|------------|-------------|--------|
| `low` | - | - | 50 pkts | Aggressive | - | - |
| `medium` | yes | yes | 3 pkts | Normal | - | - |
| `high` | yes | yes | - | Paranoid | yes | - |
| `ghost` | yes | yes | - | Stealth | yes | yes |

```bash
# Override stealth level for any command
sudo voidfreq auto -t <BSSID> -ch 6 -s ghost
```

## Architecture

```
voidfreq/
├── core/
│   ├── config.py      # YAML config loader, stealth profiles, validation
│   ├── interface.py   # Monitor mode, channel control, TX power
│   ├── logger.py      # Centralized file logging
│   ├── opsec.py       # MAC rotation, hostname spoof, jitter, cleanup
│   ├── session.py     # Save/resume pentest sessions
│   └── threat.py      # IDS/WIDS detection, kill switch
├── modules/
│   ├── recon.py       # Passive AP/client scanning
│   ├── attack.py      # PMKID/handshake capture + cracking
│   ├── scanner.py     # nmap host/port/vuln scanning
│   ├── mitm.py        # ARP spoof + DNS/SNI/HTTP capture
│   ├── dnsspoof.py    # DNS spoofing with iptables redirect
│   ├── eviltwin.py    # Rogue AP (hostapd + dnsmasq + NAT)
│   ├── monitor.py     # Blue team detection & alerting
│   ├── packets.py     # Native Scapy packet operations
│   ├── captive.py     # Captive portal credential harvesting
│   ├── wordlist.py    # ESSID-based wordlist generator
│   └── analyzer.py    # Offline pcap capture analysis
├── utils/
│   ├── deps.py        # Dependency checker + doctor mode
│   └── report.py      # Markdown/JSON report generator
└── cli.py             # CLI entry point with Rich TUI
```

## Configuration

Edit `config.yaml` to customize behavior. See the included default config for all options.

## Recommended Lab Setup

1. **Router** — any home router with WPA2
2. **Attacker** — Kali Linux + external WiFi adapter (monitor mode capable)
3. **Target** — old phone/laptop on the network
4. **Monitoring** — second terminal running `voidfreq monitor --dashboard`

Run both sides simultaneously: attack from one terminal, watch detections from another.

## License

MIT — see [LICENSE](LICENSE).
