"""Tests for webhook & messaging alerts."""

import time
from unittest.mock import MagicMock, patch

from voidfreq.core.alerts import (
    AlertChannel,
    AlertConfig,
    AlertEvent,
    AlertManager,
    AlertSeverity,
    _parse_severity,
)


class TestAlertSeverity:
    def test_parse_valid(self):
        assert _parse_severity("CRITICAL") == AlertSeverity.CRITICAL
        assert _parse_severity("WARNING") == AlertSeverity.WARNING
        assert _parse_severity("INFO") == AlertSeverity.INFO

    def test_parse_case_insensitive(self):
        assert _parse_severity("warning") == AlertSeverity.WARNING

    def test_parse_invalid(self):
        assert _parse_severity("UNKNOWN") == AlertSeverity.WARNING


class TestAlertConfig:
    def test_defaults(self):
        c = AlertConfig(channel=AlertChannel.WEBHOOK, url="https://example.com/hook")
        assert c.min_severity == AlertSeverity.WARNING
        assert c.rate_limit_seconds == 30
        assert c.enabled is True

    def test_from_config_empty(self):
        mgr = AlertManager.from_config({})
        assert mgr.channels == []

    def test_from_config_webhook(self):
        raw = {
            "voidfreq": {
                "alerts": {
                    "webhook_url": "https://example.com/hook",
                    "min_severity": "CRITICAL",
                    "rate_limit": 60,
                }
            }
        }
        mgr = AlertManager.from_config(raw)
        assert len(mgr.channels) == 1
        assert mgr.channels[0].channel == AlertChannel.WEBHOOK
        assert mgr.channels[0].min_severity == AlertSeverity.CRITICAL

    def test_from_config_discord(self):
        raw = {
            "voidfreq": {
                "alerts": {
                    "discord_webhook": "https://discord.com/api/webhooks/123/abc",
                }
            }
        }
        mgr = AlertManager.from_config(raw)
        assert len(mgr.channels) == 1
        assert mgr.channels[0].channel == AlertChannel.DISCORD

    def test_from_config_slack(self):
        raw = {
            "voidfreq": {
                "alerts": {
                    "slack_webhook": "https://hooks.slack.com/services/T/B/X",
                }
            }
        }
        mgr = AlertManager.from_config(raw)
        assert len(mgr.channels) == 1
        assert mgr.channels[0].channel == AlertChannel.SLACK

    def test_from_config_telegram(self):
        raw = {
            "voidfreq": {
                "alerts": {
                    "telegram_token": "123:ABC",
                    "telegram_chat_id": "456",
                }
            }
        }
        mgr = AlertManager.from_config(raw)
        assert len(mgr.channels) == 1
        assert mgr.channels[0].channel == AlertChannel.TELEGRAM

    def test_from_config_multiple(self):
        raw = {
            "voidfreq": {
                "alerts": {
                    "webhook_url": "https://example.com/hook",
                    "discord_webhook": "https://discord.com/api/webhooks/123/abc",
                    "slack_webhook": "https://hooks.slack.com/services/T/B/X",
                }
            }
        }
        mgr = AlertManager.from_config(raw)
        assert len(mgr.channels) == 3


class TestSeverityFilter:
    def test_critical_passes_all(self):
        mgr = AlertManager()
        assert mgr._passes_severity(AlertSeverity.CRITICAL, AlertSeverity.INFO) is True
        assert mgr._passes_severity(AlertSeverity.CRITICAL, AlertSeverity.WARNING) is True
        assert mgr._passes_severity(AlertSeverity.CRITICAL, AlertSeverity.CRITICAL) is True

    def test_info_only_passes_info(self):
        mgr = AlertManager()
        assert mgr._passes_severity(AlertSeverity.INFO, AlertSeverity.INFO) is True
        assert mgr._passes_severity(AlertSeverity.INFO, AlertSeverity.WARNING) is False
        assert mgr._passes_severity(AlertSeverity.INFO, AlertSeverity.CRITICAL) is False


class TestRateLimiting:
    def test_not_limited_first_time(self):
        mgr = AlertManager()
        assert mgr._is_rate_limited("test:key", 30) is False

    def test_limited_after_send(self):
        mgr = AlertManager()
        mgr._last_sent["test:key"] = time.time()
        assert mgr._is_rate_limited("test:key", 30) is True

    def test_not_limited_after_expiry(self):
        mgr = AlertManager()
        mgr._last_sent["test:key"] = time.time() - 60
        assert mgr._is_rate_limited("test:key", 30) is False


class TestSendAlert:
    @patch("voidfreq.core.alerts.AlertManager._post_json", return_value=True)
    def test_send_webhook(self, mock_post):
        config = AlertConfig(
            channel=AlertChannel.WEBHOOK,
            url="https://example.com/hook",
            min_severity=AlertSeverity.INFO,
        )
        mgr = AlertManager([config])
        event = AlertEvent(
            severity=AlertSeverity.WARNING,
            alert_type="DEAUTH_FLOOD",
            message="10 deauths detected",
            source="AA:BB:CC:DD:EE:FF",
        )
        mgr.send(event)
        assert mgr.sent_count == 1
        mock_post.assert_called_once()

    @patch("voidfreq.core.alerts.AlertManager._post_json", return_value=True)
    def test_send_filtered_by_severity(self, mock_post):
        config = AlertConfig(
            channel=AlertChannel.WEBHOOK,
            url="https://example.com/hook",
            min_severity=AlertSeverity.CRITICAL,
        )
        mgr = AlertManager([config])
        event = AlertEvent(
            severity=AlertSeverity.INFO,
            alert_type="NEW_DEVICE",
            message="New device seen",
        )
        mgr.send(event)
        assert mgr.sent_count == 0
        mock_post.assert_not_called()

    @patch("voidfreq.core.alerts.AlertManager._post_json", return_value=True)
    def test_send_rate_limited(self, mock_post):
        config = AlertConfig(
            channel=AlertChannel.WEBHOOK,
            url="https://example.com/hook",
            min_severity=AlertSeverity.INFO,
            rate_limit_seconds=60,
        )
        mgr = AlertManager([config])
        event = AlertEvent(
            severity=AlertSeverity.WARNING,
            alert_type="ARP_SPOOF",
            message="ARP spoof detected",
            source="10.0.0.1",
        )
        mgr.send(event)
        assert mgr.sent_count == 1

        mgr.send(event)
        assert mgr.sent_count == 1
        assert mgr.suppressed_count == 1

    @patch("voidfreq.core.alerts.AlertManager._post_json", return_value=True)
    def test_send_discord(self, mock_post):
        config = AlertConfig(
            channel=AlertChannel.DISCORD,
            url="https://discord.com/api/webhooks/123/abc",
            min_severity=AlertSeverity.INFO,
        )
        mgr = AlertManager([config])
        event = AlertEvent(
            severity=AlertSeverity.CRITICAL,
            alert_type="EVIL_TWIN",
            message="Evil twin detected!",
        )
        mgr.send(event)
        assert mgr.sent_count == 1

        payload = mock_post.call_args[0][1]
        assert "embeds" in payload
        assert payload["embeds"][0]["title"] == "VoidFreq Alert: EVIL_TWIN"

    @patch("voidfreq.core.alerts.AlertManager._post_json", return_value=True)
    def test_send_slack(self, mock_post):
        config = AlertConfig(
            channel=AlertChannel.SLACK,
            url="https://hooks.slack.com/services/T/B/X",
            min_severity=AlertSeverity.INFO,
        )
        mgr = AlertManager([config])
        event = AlertEvent(
            severity=AlertSeverity.WARNING,
            alert_type="ROGUE_AP",
            message="Rogue AP found",
        )
        mgr.send(event)
        payload = mock_post.call_args[0][1]
        assert "text" in payload
        assert "ROGUE_AP" in payload["text"]

    @patch("voidfreq.core.alerts.AlertManager._post_json", return_value=True)
    def test_send_telegram(self, mock_post):
        config = AlertConfig(
            channel=AlertChannel.TELEGRAM,
            token="123:ABC",
            chat_id="456",
            min_severity=AlertSeverity.INFO,
        )
        mgr = AlertManager([config])
        event = AlertEvent(
            severity=AlertSeverity.CRITICAL,
            alert_type="DEAUTH_FLOOD",
            message="Massive deauth",
        )
        mgr.send(event)
        assert mgr.sent_count == 1
        url = mock_post.call_args[0][0]
        assert "api.telegram.org" in url

    def test_disabled_channel(self):
        config = AlertConfig(
            channel=AlertChannel.WEBHOOK,
            url="https://example.com/hook",
            enabled=False,
        )
        mgr = AlertManager([config])
        event = AlertEvent(
            severity=AlertSeverity.CRITICAL,
            alert_type="TEST",
            message="Test",
        )
        mgr.send(event)
        assert mgr.sent_count == 0


class TestPostJson:
    @patch("voidfreq.core.alerts.urllib.request.urlopen")
    def test_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        mgr = AlertManager()
        assert mgr._post_json("https://example.com/hook", {"test": True}) is True

    @patch("voidfreq.core.alerts.urllib.request.urlopen")
    def test_failure(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        mgr = AlertManager()
        assert mgr._post_json("https://example.com/hook", {"test": True}) is False
