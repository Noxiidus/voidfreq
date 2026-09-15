FROM kalilinux/kali-rolling:latest

LABEL maintainer="Noxiidus"
LABEL description="VoidFreq WiFi Red/Blue Team Framework"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    aircrack-ng \
    hcxdumptool \
    hcxtools \
    hashcat \
    hostapd \
    dnsmasq \
    nmap \
    tshark \
    tcpdump \
    mitmproxy \
    reaver \
    bully \
    iw \
    wireless-tools \
    net-tools \
    iproute2 \
    iptables \
    bluez \
    python3 \
    python3-pip \
    python3-scapy \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/voidfreq
COPY . .

RUN pip3 install --no-cache-dir --break-system-packages -e ".[dev]"

RUN voidfreq doctor || true

ENTRYPOINT ["voidfreq"]
CMD ["--help"]
