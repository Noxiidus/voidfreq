"""Tests for CLI argument parsing and command dispatch."""

from __future__ import annotations

from voidfreq.cli import build_parser


class TestBuildParser:
    def test_version_flag(self):
        parser = build_parser()
        assert parser.prog == "voidfreq"

    def test_recon_command(self):
        parser = build_parser()
        args = parser.parse_args(["recon", "-d", "60"])
        assert args.command == "recon"
        assert args.duration == 60

    def test_attack_command(self):
        parser = build_parser()
        args = parser.parse_args([
            "attack", "-t", "AA:BB:CC:DD:EE:FF", "-ch", "6",
            "--client", "11:22:33:44:55:66", "--pmf-check",
        ])
        assert args.command == "attack"
        assert args.target == "AA:BB:CC:DD:EE:FF"
        assert args.channel == 6
        assert args.client == "11:22:33:44:55:66"
        assert args.pmf_check is True

    def test_scan_command(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "-t", "192.168.1.0/24", "--vuln", "--os"])
        assert args.command == "scan"
        assert args.target == "192.168.1.0/24"
        assert args.vuln is True

    def test_mitm_command(self):
        parser = build_parser()
        args = parser.parse_args([
            "mitm", "-t", "192.168.1.5", "-g", "192.168.1.1",
            "--ttl-spoof", "--dashboard",
        ])
        assert args.command == "mitm"
        assert args.target == "192.168.1.5"
        assert args.gateway == "192.168.1.1"
        assert args.ttl_spoof is True
        assert args.dashboard is True

    def test_eviltwin_command(self):
        parser = build_parser()
        args = parser.parse_args([
            "eviltwin", "-e", "FreeWiFi", "-ch", "11", "--captive",
        ])
        assert args.command == "eviltwin"
        assert args.essid == "FreeWiFi"
        assert args.channel == 11
        assert args.captive is True

    def test_wps_scan(self):
        parser = build_parser()
        args = parser.parse_args(["wps", "scan", "-d", "15"])
        assert args.command == "wps"
        assert args.wps_action == "scan"
        assert args.duration == 15

    def test_wps_pixie(self):
        parser = build_parser()
        args = parser.parse_args(["wps", "pixie", "-t", "AA:BB:CC:DD:EE:FF", "-ch", "6"])
        assert args.command == "wps"
        assert args.wps_action == "pixie"

    def test_proxy_command(self):
        parser = build_parser()
        args = parser.parse_args(["proxy", "-p", "9090", "--no-transparent"])
        assert args.command == "proxy"
        assert args.port == 9090
        assert args.no_transparent is True

    def test_karma_command(self):
        parser = build_parser()
        args = parser.parse_args(["karma", "-ch", "6", "--captive"])
        assert args.command == "karma"
        assert args.channel == 6
        assert args.captive is True

    def test_osint_command(self):
        parser = build_parser()
        args = parser.parse_args([
            "osint", "-t", "AA:BB:CC:DD:EE:FF", "-e", "TestNet",
        ])
        assert args.command == "osint"
        assert args.target == "AA:BB:CC:DD:EE:FF"
        assert args.essid == "TestNet"

    def test_pmf_command(self):
        parser = build_parser()
        args = parser.parse_args(["pmf", "-t", "AA:BB:CC:DD:EE:FF", "-d", "10"])
        assert args.command == "pmf"
        assert args.duration == 10

    def test_wordlist_command(self):
        parser = build_parser()
        args = parser.parse_args([
            "wordlist", "-e", "HomeNetwork",
            "--no-leet", "--min-len", "10", "--max-len", "32",
        ])
        assert args.command == "wordlist"
        assert args.essid == "HomeNetwork"
        assert args.no_leet is True
        assert args.min_len == 10
        assert args.max_len == 32

    def test_analyze_command(self):
        parser = build_parser()
        args = parser.parse_args(["analyze", "/tmp/cap.pcap", "--export"])
        assert args.command == "analyze"
        assert args.file == "/tmp/cap.pcap"
        assert args.export is True

    def test_verbose_flag(self):
        parser = build_parser()
        args = parser.parse_args(["-v", "check"])
        assert args.verbose is True
        assert args.quiet is False

    def test_quiet_flag(self):
        parser = build_parser()
        args = parser.parse_args(["-q", "check"])
        assert args.quiet is True
        assert args.verbose is False

    def test_stealth_override(self):
        parser = build_parser()
        args = parser.parse_args(["-s", "ghost", "recon"])
        assert args.stealth == "ghost"

    def test_interface_override(self):
        parser = build_parser()
        args = parser.parse_args(["-i", "wlan0mon", "recon"])
        assert args.interface == "wlan0mon"

    def test_config_override(self):
        parser = build_parser()
        args = parser.parse_args(["-c", "/etc/voidfreq.yaml", "check"])
        assert args.config == "/etc/voidfreq.yaml"

    def test_no_command(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.command is None

    def test_check_command(self):
        parser = build_parser()
        args = parser.parse_args(["check"])
        assert args.command == "check"

    def test_doctor_command(self):
        parser = build_parser()
        args = parser.parse_args(["doctor"])
        assert args.command == "doctor"

    def test_mitm_dns_spoof(self):
        parser = build_parser()
        args = parser.parse_args([
            "mitm", "-t", "192.168.1.5", "-g", "192.168.1.1",
            "--dns-spoof", "example.com", "10.0.0.1",
            "--dns-spoof", "evil.com", "10.0.0.2",
        ])
        assert len(args.dns_spoof) == 2
        assert args.dns_spoof[0] == ["example.com", "10.0.0.1"]
