# VoidFreq Lab Setup Guide

Step-by-step guide to set up a WiFi pentesting lab for VoidFreq.

---

## Hardware

### WiFi Adapters (monitor mode + packet injection required)

| Adapter | Chipset | Bands | Notes |
|---------|---------|-------|-------|
| Alfa AWUS036ACH | RTL8812AU | 2.4/5 GHz | Best overall, dual-band |
| Alfa AWUS036AXML | MT7921AU | 2.4/5/6 GHz | WiFi 6E support |
| Alfa AWUS036ACM | MT7612U | 2.4/5 GHz | Good Linux support |
| TP-Link TL-WN722N v1 | AR9271 | 2.4 GHz | Budget, v1 only |
| Panda PAU09 | RT5572 | 2.4/5 GHz | Plug-and-play |

> **Important:** Only version 1 of the TL-WN722N supports monitor mode. Later versions use a different chipset.

### Target AP

Any router or a Raspberry Pi 4 running hostapd as a test AP.

Recommended: **GL.iNet GL-AR750S** — cheap, dual-band, OpenWrt, perfect as a disposable test AP.

### Lab machine

- **Kali Linux** (bare metal or USB boot) — all tools pre-installed
- Minimum: 4 GB RAM, 2 cores
- GPU optional but recommended for hashcat (NVIDIA with CUDA or AMD with OpenCL)

---

## Software Installation

### 1. Install VoidFreq

```bash
git clone https://github.com/Noxiidus/voidfreq.git
cd voidfreq
pip install -e ".[dev]"
```

### 2. Install required tools

On Kali Linux, most are pre-installed:

```bash
# Core (required)
sudo apt install aircrack-ng hcxdumptool hcxtools

# Network
sudo apt install nmap tshark dsniff dnsmasq hostapd

# Optional
sudo apt install hashcat reaver bully mitmproxy hostapd-mana
pip install scapy mac-vendor-lookup
```

### 3. Verify installation

```bash
voidfreq doctor
```

This checks all tools, versions, WiFi interfaces, kernel modules, and Python packages.

---

## Lab Network Setup

### Option A: Isolated WiFi network

1. Set up a test AP on a dedicated router (WPA2-PSK, known password)
2. Connect 1-2 test clients (phone, laptop)
3. Use a separate adapter for VoidFreq in monitor mode

```
[Test AP] ---- WiFi ---- [Test clients]
    |
    |---- WiFi (monitor) ---- [Attack machine running VoidFreq]
```

### Option B: Raspberry Pi AP

```bash
# On the Pi:
sudo apt install hostapd dnsmasq
# Configure /etc/hostapd/hostapd.conf with:
#   ssid=VoidFreq-Lab
#   wpa_passphrase=testpassword123
#   channel=6
sudo systemctl start hostapd
```

### Option C: Virtual lab (no hardware)

For testing CLI, parsing, and module logic without real WiFi:

```bash
# Create a virtual monitor interface
sudo modprobe mac80211_hwsim radios=2
# This creates wlan0 and wlan1 virtual interfaces
sudo airmon-ng start wlan0
# Now wlan0mon exists for testing
```

---

## Quick Start

### 1. Enable monitor mode

```bash
sudo airmon-ng start wlan0
```

### 2. Scan for networks

```bash
sudo voidfreq recon -i wlan0mon -d 30
```

### 3. Attack a target

```bash
sudo voidfreq attack -i wlan0mon -t AA:BB:CC:DD:EE:FF -ch 6 --pmf-check
```

### 4. Check OPSEC status

```bash
voidfreq opsec --status
```

### 5. Clean up

```bash
sudo voidfreq opsec --cleanup
sudo airmon-ng stop wlan0mon
```

---

## Troubleshooting

### "No WiFi interfaces found"

```bash
# Check if adapter is detected
lsusb | grep -i wireless
# Load driver
sudo modprobe 88XXau  # for RTL8812AU
```

### "Permission denied"

Most VoidFreq commands require root:

```bash
sudo voidfreq <command>
```

### "hcxdumptool: not found"

```bash
sudo apt install hcxdumptool hcxtools
# Or build from source:
git clone https://github.com/ZerBea/hcxdumptool
cd hcxdumptool && make && sudo make install
```

### Hashcat GPU issues

```bash
# Check GPU detection
hashcat -I
# If no GPU, use CPU fallback:
# Set use_hashcat: false in config.yaml
# VoidFreq falls back to aircrack-ng automatically
```

---

## Safety

- **Only test networks you own or have written permission to test**
- Keep the lab air-gapped from production networks
- Use the `ghost` stealth profile to minimize RF footprint
- Run `voidfreq opsec --cleanup` after every session
