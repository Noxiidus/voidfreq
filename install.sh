#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}"
echo ' ██╗   ██╗ ██████╗ ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗'
echo ' ██║   ██║██╔═══██╗██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗'
echo ' ██║   ██║██║   ██║██║██║  ██║█████╗  ██████╔╝█████╗  ██║   ██║'
echo ' ╚██╗ ██╔╝██║   ██║██║██║  ██║██╔══╝  ██╔══██╗██╔══╝  ██║▄▄ ██║'
echo '  ╚████╔╝ ╚██████╔╝██║██████╔╝██║     ██║  ██║███████╗╚██████╔╝'
echo '   ╚═══╝   ╚═════╝ ╚═╝╚═════╝ ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚══▀▀═╝'
echo -e "${NC}"
echo "WiFi Red/Blue Team Framework — Installer"
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This installer requires root privileges.${NC}"
    echo "Run with: sudo bash install.sh"
    exit 1
fi

echo -e "${YELLOW}[1/4] Installing system dependencies...${NC}"
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq \
        aircrack-ng hcxdumptool hcxtools hashcat \
        hostapd dnsmasq nmap tshark tcpdump \
        reaver bully iw wireless-tools \
        python3 python3-pip python3-venv \
        bluez 2>/dev/null || true
elif command -v pacman &>/dev/null; then
    pacman -Sy --noconfirm \
        aircrack-ng hcxdumptool hcxtools hashcat \
        hostapd dnsmasq nmap wireshark-cli tcpdump \
        reaver iw python python-pip \
        bluez 2>/dev/null || true
else
    echo -e "${YELLOW}Unsupported package manager — install deps manually.${NC}"
fi

echo -e "${YELLOW}[2/4] Cloning VoidFreq...${NC}"
INSTALL_DIR="/opt/voidfreq"
if [ -d "$INSTALL_DIR" ]; then
    echo "Updating existing installation..."
    cd "$INSTALL_DIR"
    git pull origin main
else
    git clone https://github.com/Noxiidus/voidfreq.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

echo -e "${YELLOW}[3/4] Installing Python package...${NC}"
pip3 install --break-system-packages -e ".[dev]" 2>/dev/null || \
    pip3 install -e ".[dev]"

echo -e "${YELLOW}[4/4] Running diagnostics...${NC}"
voidfreq doctor || true

echo ""
echo -e "${GREEN}VoidFreq installed successfully!${NC}"
echo ""
echo "Usage:"
echo "  voidfreq --help       # Show all commands"
echo "  voidfreq doctor       # Check system readiness"
echo "  voidfreq recon -d 30  # Start scanning"
echo ""
echo -e "${YELLOW}Note: Most operations require root and a WiFi adapter in monitor mode.${NC}"
