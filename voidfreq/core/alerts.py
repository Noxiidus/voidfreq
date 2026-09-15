"""Webhook & messaging alerts — Discord, Slack, Telegram, generic webhook."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from rich.console import Console

from .logger import get_logger

console = Console()
log = get_logger("alerts")


class AlertSeverity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AlertChannel(Enum):
    WEBHOOK = "webhook"
    DISCORD = "discord"
    SLACK = "slack"
    TELEGRAM = "telegram"


@dataclass
class AlertConfig:
    channel: AlertChannel
    url: str = ""
    token: str = ""
    chat_id: str = ""
    min_severity: AlertSeverity = AlertSeverity.WARNING
    rate_limit_seconds: int = 30
    enabled: bool = True


@dataclass
class AlertEvent:
    severity: AlertSeverity
    alert_type: str
    message: str
    source: str = ""
    timestamp: str = ""
    details: dict[str, Any] = field(default_factory=dict)


class AlertManager:
    def __init__(self, configs: list[AlertConfig] | None = None) -> None:
        self._configs: list[AlertConfig] = configs or []
        self._last_sent: dict[str, float] = {}
        self._sent_count = 0
        self._suppressed_count = 0

    def add_channel(self, config: AlertConfig) -> None:
        self._configs.append(config)

    @classmethod
    def from_config(cls, raw: dict) -> AlertManager:
        alerts_config = raw.get("voidfreq", {}).get("alerts", {})
        if not alerts_config:
            return cls()

        configs: list[AlertConfig] = []

        if alerts_config.get("webhook_url"):
            configs.append(AlertConfig(
                channel=AlertChannel.WEBHOOK,
                url=alerts_config["webhook_url"],
                min_severity=_parse_severity(alerts_config.get("min_severity", "WARNING")),
                rate_limit_seconds=alerts_config.get("rate_limit", 30),
            ))

        if alerts_config.get("discord_webhook"):
            configs.append(AlertConfig(
                channel=AlertChannel.DISCORD,
                url=alerts_config["discord_webhook"],
                min_severity=_parse_severity(alerts_config.get("min_severity", "WARNING")),
                rate_limit_seconds=alerts_config.get("rate_limit", 30),
            ))

        if alerts_config.get("slack_webhook"):
            configs.append(AlertConfig(
                channel=AlertChannel.SLACK,
                url=alerts_config["slack_webhook"],
                min_severity=_parse_severity(alerts_config.get("min_severity", "WARNING")),
                rate_limit_seconds=alerts_config.get("rate_limit", 30),
            ))

        if alerts_config.get("telegram_token") and alerts_config.get("telegram_chat_id"):
            configs.append(AlertConfig(
                channel=AlertChannel.TELEGRAM,
                token=alerts_config["telegram_token"],
                chat_id=alerts_config["telegram_chat_id"],
                min_severity=_parse_severity(alerts_config.get("min_severity", "WARNING")),
                rate_limit_seconds=alerts_config.get("rate_limit", 30),
            ))

        return cls(configs)

    def send(self, event: AlertEvent) -> None:
        if not event.timestamp:
            event.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        for config in self._configs:
            if not config.enabled:
                continue

            if not self._passes_severity(event.severity, config.min_severity):
                continue

            dedup_key = f"{config.channel.value}:{event.alert_type}:{event.source}"
            if self._is_rate_limited(dedup_key, config.rate_limit_seconds):
                self._suppressed_count += 1
                continue

            success = False
            if config.channel == AlertChannel.WEBHOOK:
                success = self._send_webhook(config, event)
            elif config.channel == AlertChannel.DISCORD:
                success = self._send_discord(config, event)
            elif config.channel == AlertChannel.SLACK:
                success = self._send_slack(config, event)
            elif config.channel == AlertChannel.TELEGRAM:
                success = self._send_telegram(config, event)

            if success:
                self._last_sent[dedup_key] = time.time()
                self._sent_count += 1

    def _passes_severity(self, event_sev: AlertSeverity, min_sev: AlertSeverity) -> bool:
        order = {AlertSeverity.INFO: 0, AlertSeverity.WARNING: 1, AlertSeverity.CRITICAL: 2}
        return order.get(event_sev, 0) >= order.get(min_sev, 0)

    def _is_rate_limited(self, key: str, limit_seconds: int) -> bool:
        last = self._last_sent.get(key, 0)
        return (time.time() - last) < limit_seconds

    def _send_webhook(self, config: AlertConfig, event: AlertEvent) -> bool:
        payload = {
            "timestamp": event.timestamp,
            "severity": event.severity.value,
            "type": event.alert_type,
            "message": event.message,
            "source": event.source,
            "details": event.details,
        }
        return self._post_json(config.url, payload)

    def _send_discord(self, config: AlertConfig, event: AlertEvent) -> bool:
        color_map = {
            AlertSeverity.INFO: 3447003,       # blue
            AlertSeverity.WARNING: 16776960,   # yellow
            AlertSeverity.CRITICAL: 15158332,  # red
        }
        payload = {
            "embeds": [{
                "title": f"VoidFreq Alert: {event.alert_type}",
                "description": event.message,
                "color": color_map.get(event.severity, 0),
                "fields": [
                    {"name": "Severity", "value": event.severity.value, "inline": True},
                    {"name": "Source", "value": event.source or "N/A", "inline": True},
                    {"name": "Time", "value": event.timestamp, "inline": True},
                ],
                "footer": {"text": "VoidFreq WiFi Framework"},
            }],
        }
        return self._post_json(config.url, payload)

    def _send_slack(self, config: AlertConfig, event: AlertEvent) -> bool:
        emoji = {"INFO": ":information_source:", "WARNING": ":warning:", "CRITICAL": ":rotating_light:"}
        payload = {
            "text": (
                f"{emoji.get(event.severity.value, ':bell:')} "
                f"*VoidFreq [{event.severity.value}]*: {event.alert_type}\n"
                f">{event.message}\n"
                f"_Source: {event.source or 'N/A'} | {event.timestamp}_"
            ),
        }
        return self._post_json(config.url, payload)

    def _send_telegram(self, config: AlertConfig, event: AlertEvent) -> bool:
        icon = {"INFO": "ℹ️", "WARNING": "⚠️", "CRITICAL": "🚨"}
        text = (
            f"{icon.get(event.severity.value, '🔔')} *VoidFreq Alert*\n"
            f"*Type:* {event.alert_type}\n"
            f"*Severity:* {event.severity.value}\n"
            f"*Message:* {event.message}\n"
            f"*Source:* {event.source or 'N/A'}\n"
            f"*Time:* {event.timestamp}"
        )
        url = f"https://api.telegram.org/bot{config.token}/sendMessage"
        payload = {
            "chat_id": config.chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }
        return self._post_json(url, payload)

    def _post_json(self, url: str, data: dict) -> bool:
        try:
            body = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status < 400
        except (urllib.error.URLError, OSError, ValueError) as e:
            log.warning("Alert delivery failed to %s: %s", url[:50], e)
            return False

    @property
    def sent_count(self) -> int:
        return self._sent_count

    @property
    def suppressed_count(self) -> int:
        return self._suppressed_count

    @property
    def channels(self) -> list[AlertConfig]:
        return self._configs


def _parse_severity(value: str) -> AlertSeverity:
    try:
        return AlertSeverity(value.upper())
    except ValueError:
        return AlertSeverity.WARNING
