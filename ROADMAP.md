# VoidFreq Roadmap

> Current version: **v0.5.0** — 36 Python files, ~7500 lines, 55 unit tests, CI pipeline active.

---

## Current State (v0.5.0)

### What's done and working

**Red Team modules:**
- `recon` — passive AP/client scan via airodump-ng, vendor resolution
- `attack` — PMKID capture (hcxdumptool), passive handshake, targeted deauth; cracking via hashcat (GPU) with aircrack-ng fallback; PMF-aware strategy selection; auto hash export (hc22000 + hccapx)
- `scan` — nmap host discovery, port scan, vuln scan, OS fingerprinting
- `mitm` — ARP spoofing (fullduplex), DNS/SNI/HTTP capture via tshark, live dashboard, TTL spoofing to hide MITM hop
- `dnsspoof` — domain-level DNS redirection via dnsmasq + iptables
- `eviltwin` — rogue AP with hostapd + dnsmasq, DHCP, NAT, optional captive portal, traffic capture
- `captive` — HTTP captive portal with credential harvesting, custom HTML templates, JSON export
- `packets` — native Scapy: deauth (single + broadcast), beacon scan, probe injection, handshake capture, hidden SSID reveal, PMF detection (802.11w RSN IE parsing), client isolation detection
- `wps` — WPS AP scanning via wash, Pixie Dust attack (reaver + bully), PIN brute-force
- `proxy` — HTTPS interception proxy via mitmproxy (transparent mode, credential capture, cookie/TLS logging, live dashboard)
- `karma` — Karma/MANA attack via hostapd-mana (respond to all probes, MANA loud mode, probe monitoring, traffic capture, NAT, captive portal redirect)
- `osint` — passive OSINT: MAC vendor lookup, WiGLE geolocation API, known vendor vulnerability database, default ESSID pattern detection
- `wordlist` — ESSID-based wordlist generator (leet speak, year combos, keyboard walks, custom words)
- `analyzer` — offline pcap analysis (DNS, SNI, HTTP, credentials, handshakes, deauths, beacons, top talkers)
- `auto` — full automated chain: threat check → recon → capture → crack → network enum, with session save/resume

**Blue Team modules:**
- `monitor` — ARP anomaly detection, deauth flood detection, new device alerts, rogue AP detection (duplicate SSIDs), Evil Twin detection (same SSID+channel from multiple BSSIDs), live Rich dashboard
- `threat` — IDS/WIDS port scanning, enterprise AP MAC detection, WIDS process detection, kill switch

**OPSEC engine:**
- MAC rotation (vendor-aware random MACs)
- Hostname spoofing (Windows/Android patterns)
- Timing jitter
- Fingerprint spoofing (TTL, window size)
- Kill switch on threat detection
- Auto-cleanup (MAC, hostname, routes, iptables restore)

**Infrastructure:**
- CLI with 20 subcommands (including `doctor`, `check`, `wps`, `proxy`, `karma`, `osint`, `pmf`)
- YAML config with 4 stealth profiles (low/medium/high/ghost)
- Config validation with clear error messages
- Session management (save/resume/export pentest sessions)
- Centralized file logging (`~/.voidfreq/logs/voidfreq.log`)
- Doctor mode (tool versions, WiFi interfaces, kernel modules, Python packages, feature map)
- 55 unit tests (config, session, opsec, wordlist, deps, logger)
- GitHub Actions CI (ruff lint + pytest on Python 3.11/3.12/3.13)
- pyproject.toml with `[dev]` extras
- Markdown/JSON report generation

---

## Phase 1.5: New Modules (v0.5.0) — DONE

Priority: expand attack surface and detection capabilities.

### New Red Team modules
- [x] WPS module — wash AP discovery, Pixie Dust (reaver + bully), PIN brute-force
- [x] HTTPS proxy — mitmproxy transparent mode, credential/cookie/TLS capture, live dashboard
- [x] Karma/MANA — hostapd-mana rogue AP, probe request monitoring, MANA loud, NAT, captive portal redirect
- [x] Passive OSINT — MAC vendor lookup, WiGLE geolocation, known vendor vulnerability DB, default ESSID patterns

### Attack enhancements
- [x] PMF detection (802.11w) — RSN IE parsing from beacon frames, capability bits 6/7
- [x] PMF-aware attack strategy — auto-skip deauth if PMF required
- [x] Client isolation detection — inter-client traffic test via Scapy
- [x] Handshake hash auto-export — automatic hc22000 + hccapx conversion after capture
- [x] TTL spoofing in MITM — iptables mangle rule to normalize outgoing TTL (hides MITM hop)

### Blue Team enhancements
- [x] Rogue AP detection — alert when same SSID appears on multiple BSSIDs
- [x] Evil Twin detection — alert when same SSID + channel seen from different BSSIDs (CRITICAL)

### CLI
- [x] `wps scan` / `wps pixie` / `wps brute` subcommands
- [x] `proxy` subcommand with transparent mode + dashboard
- [x] `karma` subcommand with MANA loud + dashboard
- [x] `osint` subcommand with WiGLE API + export
- [x] `pmf` subcommand for standalone PMF detection
- [x] `attack --pmf-check` flag for pre-attack PMF assessment
- [x] `mitm --ttl-spoof` flag for TTL normalization

---

## Phase 1: Hardening (v0.4.0) — DONE

Priority: make existing features bullet-proof.

### Error handling & resilience
- [x] Graceful fallback when external tools are missing (try/catch FileNotFoundError in threat detector)
- [x] Timeout handling for all subprocess calls (threat detector, scanner)
- [x] Signal handling cleanup — Ctrl+C now uses threading.Event + try/finally instead of signal.pause + sys.exit
- [x] Evil Twin iptables cleanup now removes only its own rules instead of flushing all nat rules
- [x] DNS spoof iptables restore now matches the exact rules that were added (includes interface)
- [x] DNS spoof wildcard rules now go to dnsmasq config (--conf-file) instead of hosts file (--addn-hosts)
- [x] Fixed hardcoded version "0.1.0" in JSON reports — now uses __version__
- [x] Fixed scanner vuln display showing all script output as vulns — now only VULNERABLE matches
- [x] Fixed callable type hint in ThreatDetector to use collections.abc.Callable
- [x] Fixed os.getuid/geteuid inconsistency in doctor mode
- [x] Added POSIX platform check to check_root()
- [x] MITM module now initializes _arp_proc1/_arp_proc2 in __init__
- [x] Report format validation now accepts "both"
- [x] Wordlist year range extended to 2018–2027
- [ ] Wrap all `subprocess.run` calls through a central runner with logging, timeout, and error reporting

### Testing
- [ ] Integration tests with mock subprocess calls for attack/recon/scan/mitm modules
- [ ] Test CLI argument parsing and command dispatch
- [ ] Test report generation (markdown + JSON output)
- [ ] Test captive portal HTTP server (start/stop/credential capture)
- [ ] Test config edge cases (missing profiles, partial configs)
- [ ] Coverage target: 80%+

### Logging
- [ ] Add logging to all modules (currently only opsec + threat have it)
- [ ] Log rotation (max 10MB per file, keep 5 rotated files)
- [ ] `--verbose` / `--quiet` CLI flags for console output level
- [ ] Log all subprocess commands and their exit codes

### Documentation
- [ ] Man page or `--help` improvements with examples per command
- [ ] `config.yaml` schema documentation (all keys, types, defaults, valid values)
- [ ] Lab setup guide with specific hardware recommendations and step-by-step

---

## Phase 2: Protocol Coverage (v0.5.0)

Priority: support modern WiFi security standards.

### WPA3 / SAE support
- [ ] SAE handshake detection and capture
- [ ] Dragonblood attack vectors (CVE-2019-9494, CVE-2019-9496)
- [ ] SAE side-channel timing attacks
- [ ] WPA3 transition mode downgrade detection
- [ ] Update attack strategy selection: if WPA3 detected, skip deauth, try SAE-specific vectors

### 802.1X / Enterprise WiFi
- [ ] EAP type detection (PEAP, EAP-TLS, EAP-TTLS, LEAP)
- [ ] Fake RADIUS server for credential capture
- [ ] Certificate impersonation for EAP-PEAP
- [ ] `hostapd-wpe` integration for enterprise evil twin
- [ ] GTC downgrade attack

### Deauth evasion (IDS bypass)
- [ ] Randomized reason codes in deauth frames
- [ ] Fragmented deauth with inter-frame jitter
- [ ] Client-side disassociation instead of deauth (different frame type, often not monitored)
- [ ] Rate-limiting awareness — stay below common IDS thresholds (e.g., 10 frames/sec)

---

## Phase 3: Advanced Features (v0.6.0)

Priority: extend beyond WiFi into broader wireless and network features.

### Bluetooth recon module
- [ ] BLE device scanning (hcitool/bluetoothctl)
- [ ] Bluetooth Classic device enumeration
- [ ] BLE GATT service enumeration
- [ ] Known vulnerable device detection (by OUI/service UUID)
- [ ] Bluetooth proximity tracking

### Plugin system
- [ ] Plugin discovery from `~/.voidfreq/plugins/` directory
- [ ] Plugin YAML manifest (name, version, commands, dependencies)
- [ ] Plugin lifecycle hooks (pre_operation, post_operation, on_alert)
- [ ] Built-in plugin: custom deauth patterns
- [ ] Built-in plugin: MAC vendor database update

### Webhook & Discord alerts
- [ ] Webhook URL config for monitor module alerts
- [ ] Discord bot integration (alert channel, threat notifications)
- [ ] Slack webhook support
- [ ] Telegram bot support
- [ ] Alert severity filtering (only send high-confidence threats)
- [ ] Rate limiting to avoid alert fatigue

### Interactive TUI mode
- [ ] Full-screen terminal UI with Textual library
- [ ] Real-time AP list with signal strength bars
- [ ] Point-and-click target selection
- [ ] Live attack progress visualization
- [ ] Split-pane: attack on left, monitor on right
- [ ] Keyboard shortcuts for common operations

---

## Phase 4: Polish (v1.0.0)

Priority: production-ready release.

### Performance
- [ ] Async I/O for concurrent operations (asyncio subprocess)
- [ ] Parallel scanning (multiple channels simultaneously)
- [ ] Memory-efficient pcap parsing for large capture files
- [ ] Lazy imports to reduce startup time

### Distribution
- [ ] Docker image with all dependencies pre-installed
- [ ] Kali Linux package (.deb)
- [ ] AUR package for Arch Linux
- [ ] pip install from PyPI
- [ ] One-liner install script

### Security
- [ ] Credential encryption in session files (AES-256)
- [ ] Session file permissions enforcement (600)
- [ ] Secure temp file handling (no world-readable captures)
- [ ] Audit log of all operations performed

### Community
- [ ] Contributing guide (CONTRIBUTING.md)
- [ ] Issue templates (bug report, feature request)
- [ ] Example pentest walkthrough (full lab session, start to finish)
- [ ] Video demo / tutorial
- [ ] Badge: CI status, Python versions, license

---

## Architecture Notes

For anyone continuing development from another machine:

### Setup
```bash
git clone https://github.com/Noxiidus/voidfreq.git
cd voidfreq
pip install -e ".[dev]"
voidfreq doctor          # check what tools you have
pytest tests/ -v         # run tests
ruff check voidfreq/     # lint
```

### File layout
```
voidfreq/
├── core/               # Framework internals
│   ├── config.py       # YAML config loader, StealthProfile/Config dataclasses, validation
│   ├── interface.py    # Monitor mode enable/disable via airmon-ng, channel/TX control
│   ├── logger.py       # Centralized file logger (~/.voidfreq/logs/)
│   ├── opsec.py        # OpsecEngine: MAC rotation, hostname spoof, jitter, cleanup
│   ├── session.py      # SessionManager: save/resume/export pentest sessions as JSON
│   └── threat.py       # ThreatDetector: IDS port scan, enterprise AP detection, kill switch
├── modules/            # Feature modules (each is standalone with config + opsec injection)
│   ├── analyzer.py     # PcapAnalyzer: offline tshark-based capture analysis
│   ├── attack.py       # AttackModule: PMKID/handshake capture, hashcat/aircrack cracking
│   ├── captive.py      # CaptivePortal: HTTP server, login page, credential harvest
│   ├── dnsspoof.py     # DnsSpoofModule: dnsmasq + iptables PREROUTING redirect
│   ├── eviltwin.py     # EvilTwinModule: hostapd + dnsmasq + NAT + tcpdump
│   ├── karma.py        # KarmaModule: hostapd-mana Karma/MANA, probe monitoring, NAT
│   ├── mitm.py         # MitmModule: ARP spoof + DNS/SNI/HTTP capture + TTL spoof
│   ├── monitor.py      # MonitorModule: ARP anomaly, deauth flood, rogue AP, Evil Twin detection
│   ├── osint.py        # OsintModule: MAC vendor, WiGLE, known vulns, ESSID patterns
│   ├── packets.py      # Native Scapy: deauth, beacon, probe, PMF detect, client isolation
│   ├── proxy.py        # ProxyModule: mitmproxy HTTPS interception, cred/cookie/TLS capture
│   ├── recon.py        # ReconModule: airodump-ng wrapper with CSV parsing
│   ├── scanner.py      # ScannerModule: nmap wrapper (host/port/vuln/OS)
│   ├── wordlist.py     # WordlistGenerator: ESSID-based with leet/years/patterns/walks
│   └── wps.py          # WpsModule: wash scan, Pixie Dust (reaver/bully), PIN brute-force
├── utils/
│   ├── deps.py         # check_dependencies() + doctor() full system diagnostic
│   └── report.py       # Markdown/JSON pentest report generation
├── cli.py              # argparse CLI, 15 subcommands, banner, command dispatch
└── __init__.py         # __version__ = "0.4.0", __author__ = "Noxiidus"
```

### Key patterns
- **Every module** takes `Config` + `OpsecEngine` in its constructor
- **OpsecEngine.pre_operation()** runs before every major action (MAC rotate + jitter)
- **OpsecEngine.cleanup()** must always run in `finally` blocks
- **StealthProfile** controls what OPSEC features are active per stealth level
- **SessionManager** saves state as JSON in `~/.voidfreq/sessions/`
- **All external tools** are called via `subprocess.run()` — never shell=True
- **Config validation** raises `ConfigError` with human-readable messages
- **Tests** use `unittest.mock.patch` to mock subprocess calls, no real tools needed

### Key decisions
- **No bettercap dependency** — we wrap individual tools (arpspoof, tshark, nmap) directly for finer control
- **Scapy is optional** — `packets.py` gracefully degrades if scapy is not installed
- **Rich for all TUI** — tables, panels, progress bars, live dashboards
- **Ghost stealth** = no deauth, no active scanning, decoy IPs, randomized everything
- **Strategy pattern in attack**: tries PMKID first (silent), falls back to passive, then deauth only if stealth allows

### Testing
```bash
pytest tests/ -v                    # all tests
pytest tests/test_config.py -v      # single module
pytest tests/ -v --cov=voidfreq     # with coverage
ruff check voidfreq/                # lint
```

### Config
Default config in `config.yaml` at repo root. User override at `~/.voidfreq/config.yaml`. All stealth profiles defined there. See `voidfreq/core/config.py` for valid values and validation rules.

### CI
GitHub Actions runs on every push/PR to main:
- `ruff check voidfreq/` (lint)
- `pytest tests/ -v` on Python 3.11, 3.12, 3.13
