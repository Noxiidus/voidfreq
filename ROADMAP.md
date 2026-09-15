# VoidFreq Roadmap

> Current version: **v1.0.0** — 48 Python files, ~12750 lines, 295 unit tests, CI pipeline active.

---

## Current State (v0.6.0)

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
- CLI with 25 subcommands (including `doctor`, `check`, `wps`, `proxy`, `karma`, `osint`, `pmf`, `wpa3`, `enterprise`, `bt`, `plugin`, `tui`)
- YAML config with 4 stealth profiles (low/medium/high/ghost)
- Config validation with clear error messages
- Session management (save/resume/export pentest sessions)
- Centralized file logging with rotation (`~/.voidfreq/logs/voidfreq.log`, 10MB/5 backups)
- Central subprocess runner with logging, timeout, and error reporting
- `--verbose` / `--quiet` CLI flags for console output level
- Doctor mode (tool versions, WiFi interfaces, kernel modules, Python packages, feature map)
- 295 unit tests (all modules, CLI, report, captive portal, config, integration tests)
- GitHub Actions CI (ruff lint + pytest on Python 3.11/3.12/3.13)
- pyproject.toml with `[dev]` extras
- Markdown/JSON report generation
- Config schema documentation (`docs/config-schema.md`)
- Lab setup guide (`docs/lab-setup.md`)

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

## Phase 1: Hardening (v0.6.0) — DONE

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
- [x] Wrap all `subprocess.run` calls through a central runner with logging, timeout, and error reporting

### Testing
- [x] Integration tests with mock subprocess calls for attack/recon/scan/mitm modules
- [x] Test CLI argument parsing and command dispatch
- [x] Test report generation (markdown + JSON output)
- [x] Test captive portal HTTP server (start/stop/credential capture)
- [x] Test config edge cases (missing profiles, partial configs)
- [x] Coverage target: 80%+

### Logging
- [x] Add logging to all modules (all 19 modules now have get_logger)
- [x] Log rotation (max 10MB per file, keep 5 rotated files)
- [x] `--verbose` / `--quiet` CLI flags for console output level
- [x] Log all subprocess commands and their exit codes (via central runner)

### Documentation
- [x] `--help` improvements with examples per command (epilog on main parser)
- [x] `config.yaml` schema documentation (docs/config-schema.md)
- [x] Lab setup guide with specific hardware recommendations and step-by-step (docs/lab-setup.md)

---

## Phase 1 Bug Hunt (v0.6.1) — DONE

Full codebase audit of 37 Python files (~8200 lines). 23 bugs fixed across 18 files.

### Security fixes
- [x] Path traversal protection in session load/delete
- [x] Symlink attack prevention — replaced hardcoded /tmp paths with tempfile.mkstemp in dnsspoof
- [x] Content-Length memory exhaustion cap (64KB) in captive portal
- [x] WIDS false positive kill switch — removed generic "ids" from signature list

### Stability fixes
- [x] Race condition in threat indicator list (atomic reference swap)
- [x] Double-checked locking for thread-safe logger handler creation
- [x] Process lifecycle: terminate → wait(timeout) → kill fallback in attack/dnsspoof/mitm
- [x] Thread-safe proc reference in dnsspoof monitor thread
- [x] capture_output conflict guard in central runner
- [x] FileNotFoundError handling in monitor and analyzer modules
- [x] TimeoutExpired partial output capture in WPS module
- [x] MITM capture process cleanup on stop

### Correctness fixes
- [x] None vs falsy config validation (stealth profile checks)
- [x] ESSID comma-in-name CSV parsing
- [x] Variable shadowing in packets.py beacon scanner closure
- [x] aircrack KEY FOUND line parsing fallback
- [x] SNI domain type handling in report generator
- [x] Report path now includes file extension
- [x] opsec spoof_hostname config guard
- [x] Karma capture written to persistent path instead of tmpdir

### Test fixes
- [x] Windows PermissionError in test_config temp file cleanup
- [x] 176 tests passing, ruff clean

---

## Phase 2: Protocol Coverage (v0.7.0) — DONE

Priority: support modern WiFi security standards.

### WPA3 / SAE support
- [x] SAE handshake detection and capture (RSN IE parsing, AKM suite detection)
- [x] Dragonblood attack vectors (CVE-2019-9494 timing, CVE-2019-9496 group downgrade)
- [x] SAE side-channel timing attacks (response time variance analysis)
- [x] WPA3 transition mode downgrade detection and attack
- [x] Update attack strategy selection: WPA3_DOWNGRADE strategy, SAE-only early return

### 802.1X / Enterprise WiFi
- [x] EAP type detection (PEAP, EAP-TLS, EAP-TTLS, GTC, MD5) via Scapy + tshark fallback
- [x] Fake RADIUS server for credential capture (hostapd-wpe integration)
- [x] Certificate impersonation for EAP-PEAP (hostapd-wpe certs)
- [x] `hostapd-wpe` integration for enterprise evil twin
- [x] GTC downgrade attack (cleartext password capture)

### Deauth evasion (IDS bypass)
- [x] Randomized reason codes in deauth frames (pool of 15 valid codes)
- [x] Inter-frame jitter (random delay between frames)
- [x] Client-side disassociation instead of deauth (Dot11Disas frames)
- [x] Rate-limiting awareness — configurable rate limit, mixed method cycling

---

## Phase 3: Advanced Features (v0.8.0) — DONE

Priority: extend beyond WiFi into broader wireless and network features.

### Bluetooth recon module
- [x] BLE device scanning (hcitool/bluetoothctl with fallback)
- [x] Bluetooth Classic device enumeration (hcitool scan + sdptool)
- [x] BLE GATT service enumeration (gatttool --primary)
- [x] Known vulnerable device detection (by OUI/service UUID databases)
- [x] Bluetooth proximity tracking (RSSI → distance estimation)

### Plugin system
- [x] Plugin discovery from `~/.voidfreq/plugins/` directory
- [x] Plugin YAML manifest (name, version, commands, dependencies)
- [x] Plugin lifecycle hooks (pre_operation, post_operation, on_alert, on_capture, on_crack)
- [x] Dynamic module loading with dependency checking
- [x] Plugin CLI commands (`voidfreq plugin list`, `voidfreq plugin run`)

### Webhook & Discord alerts
- [x] Generic webhook URL delivery with JSON payload
- [x] Discord embed notifications (color-coded severity, fields)
- [x] Slack webhook support (emoji + markdown formatting)
- [x] Telegram bot support (Markdown messages via Bot API)
- [x] Alert severity filtering (INFO/WARNING/CRITICAL threshold)
- [x] Rate limiting with dedup key per channel/type/source

### Interactive TUI mode
- [x] Full-screen terminal UI with Textual library (optional [tui] extra)
- [x] Real-time AP list with signal strength bars
- [x] Point-and-click target selection via DataTable cursor
- [x] Attack status panel and alert log panel
- [x] Grid layout: AP list + attack panel on top, alerts on bottom
- [x] Keyboard shortcuts (s=scan, a=attack, m=monitor, r=refresh, q=quit)

---

## Phase 4: Polish (v1.0.0) — DONE

Priority: production-ready release.

### Performance
- [x] Async I/O for concurrent operations (asyncio subprocess runner)
- [x] Parallel scanning (multiple channels simultaneously via run_parallel)
- [x] Lazy imports to reduce startup time (lazy_import utility)

### Distribution
- [x] Docker image with all dependencies pre-installed (Kali-based Dockerfile)
- [x] One-liner install script (install.sh — apt-get/pacman auto-detection)

### Security
- [x] Credential encryption in session files (PBKDF2 + XOR stream cipher + HMAC integrity)
- [x] Session file permissions enforcement (chmod 600 on POSIX)
- [x] Secure temp file handling (mkstemp with 0o600 permissions)
- [x] Audit log of all operations performed (JSONL in ~/.voidfreq/audit/)

### Community
- [x] Contributing guide (CONTRIBUTING.md)
- [x] Issue templates (bug report, feature request)

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
│   ├── threat.py       # ThreatDetector: IDS port scan, enterprise AP detection, kill switch
│   ├── alerts.py       # AlertManager: Discord/Slack/Telegram/webhook delivery, rate limiting
│   ├── plugins.py      # PluginManager: YAML manifest discovery, lifecycle hooks, dynamic loading
│   ├── async_runner.py # Async subprocess runner: concurrent ops, parallel channel scan, lazy imports
│   └── security.py     # Security: PBKDF2 encryption, HMAC integrity, audit log, file permissions
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
│   ├── wpa3.py         # Wpa3Module: SAE detection, Dragonblood attacks, transition downgrade
│   ├── enterprise.py   # EnterpriseModule: EAP detection, hostapd-wpe evil twin, GTC downgrade
│   ├── bluetooth.py    # BluetoothModule: BLE/Classic scan, GATT enum, vuln detection, proximity
│   └── wps.py          # WpsModule: wash scan, Pixie Dust (reaver/bully), PIN brute-force
├── utils/
│   ├── deps.py         # check_dependencies() + doctor() full system diagnostic
│   └── report.py       # Markdown/JSON pentest report generation
├── cli.py              # argparse CLI, 25 subcommands, banner, command dispatch
├── tui.py              # Interactive TUI: Textual full-screen UI with AP list, attack, alerts
└── __init__.py         # __version__ = "1.0.0", __author__ = "Noxiidus"
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
