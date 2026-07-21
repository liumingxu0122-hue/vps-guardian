from __future__ import annotations

import asyncio
import os
import smtplib
import ssl
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlparse

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from guardian.models import AlertInstance, NotificationChannel, NotificationDelivery


class NotificationConfigurationError(ValueError):
    pass


def _read_protected_file(path_value: str) -> str:
    path = Path(path_value)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise NotificationConfigurationError("notification secret file is unavailable")
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise NotificationConfigurationError("notification secret file permissions are too broad")
    value = path.read_text(encoding="utf-8").strip()
    if not value or "\x00" in value or len(value) > 4096:
        raise NotificationConfigurationError("notification secret file is invalid")
    return value


def resolve_channel_configuration(channel: NotificationChannel) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for key, reference in channel.configuration.items():
        if not isinstance(reference, str):
            raise NotificationConfigurationError("notification secret reference is invalid")
        if key.endswith("_env"):
            value = os.getenv(reference, "")
            output_key = key.removesuffix("_env")
        elif key.endswith("_file"):
            value = _read_protected_file(reference)
            output_key = key.removesuffix("_file")
        else:
            raise NotificationConfigurationError(
                "notification value must use an external reference"
            )
        if not value or "\x00" in value:
            raise NotificationConfigurationError("notification secret reference is unavailable")
        resolved[output_key] = value
    return resolved


def _is_local_target(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and parsed.hostname in {"127.0.0.1", "::1"}


def _notification_payload(alert: AlertInstance, event_type: str) -> dict[str, object]:
    return {
        "event": event_type,
        "alert_id": alert.id,
        "state": alert.state,
        "summary": alert.summary,
        "observed_at": alert.last_observed_at.isoformat(),
    }


async def _send_webhook(
    configuration: dict[str, str], payload: dict[str, object], *, external_enabled: bool
) -> int:
    endpoint = configuration.get("endpoint", "")
    if not external_enabled and not _is_local_target(endpoint):
        raise NotificationConfigurationError("external notification delivery is disabled")
    async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
        response = await client.post(endpoint, json=payload)
    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(f"notification endpoint returned HTTP {response.status_code}")
    return response.status_code


async def _send_telegram(
    configuration: dict[str, str], payload: dict[str, object], *, external_enabled: bool
) -> int:
    token = configuration.get("token", "")
    chat_id = configuration.get("chat_id", "")
    api_base = configuration.get("api_base", "https://api.telegram.org")
    if not token or not chat_id:
        raise NotificationConfigurationError("Telegram channel references are incomplete")
    if not external_enabled and not _is_local_target(api_base):
        raise NotificationConfigurationError("external notification delivery is disabled")
    endpoint = f"{api_base.rstrip('/')}/bot{token}/sendMessage"
    body = {
        "chat_id": chat_id,
        "text": f"[{payload['state']}] {payload['summary']}",
        "disable_web_page_preview": True,
    }
    async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
        response = await client.post(endpoint, json=body)
    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(f"notification endpoint returned HTTP {response.status_code}")
    return response.status_code


def _send_smtp_sync(
    configuration: dict[str, str], payload: dict[str, object], *, external_enabled: bool
) -> int:
    host = configuration.get("host", "")
    port = int(configuration.get("port", "587"))
    if not external_enabled and host not in {"127.0.0.1", "::1"}:
        raise NotificationConfigurationError("external notification delivery is disabled")
    message = EmailMessage()
    message["From"] = configuration.get("from", "")
    message["To"] = configuration.get("to", "")
    message["Subject"] = f"VPS Guardian alert: {payload['state']}"
    message.set_content(str(payload["summary"]))
    use_tls = configuration.get("tls", "true").lower() != "false"
    client: smtplib.SMTP
    if use_tls:
        client = smtplib.SMTP_SSL(host, port, timeout=10, context=ssl.create_default_context())
    else:
        client = smtplib.SMTP(host, port, timeout=10)
    try:
        username = configuration.get("username")
        password = configuration.get("password")
        if username and password:
            client.login(username, password)
        client.send_message(message)
    finally:
        client.quit()
    return 250


async def _send(
    channel: NotificationChannel,
    alert: AlertInstance,
    delivery: NotificationDelivery,
    *,
    external_enabled: bool,
) -> int:
    configuration = resolve_channel_configuration(channel)
    payload = _notification_payload(alert, delivery.event_type)
    if channel.kind == "webhook":
        return await _send_webhook(configuration, payload, external_enabled=external_enabled)
    if channel.kind == "telegram":
        return await _send_telegram(configuration, payload, external_enabled=external_enabled)
    if channel.kind == "smtp":
        return await asyncio.to_thread(
            _send_smtp_sync, configuration, payload, external_enabled=external_enabled
        )
    raise NotificationConfigurationError("unsupported notification channel")


async def send_test_notification(channel: NotificationChannel) -> int:
    configuration = resolve_channel_configuration(channel)
    payload: dict[str, object] = {
        "event": "test",
        "alert_id": "test-notification",
        "state": "ok",
        "summary": "VPS Guardian local notification test",
        "observed_at": datetime.now(UTC).isoformat(),
    }
    if channel.kind == "webhook":
        return await _send_webhook(configuration, payload, external_enabled=False)
    if channel.kind == "telegram":
        return await _send_telegram(configuration, payload, external_enabled=False)
    if channel.kind == "smtp":
        return await asyncio.to_thread(
            _send_smtp_sync, configuration, payload, external_enabled=False
        )
    raise NotificationConfigurationError("unsupported notification channel")


async def deliver_pending_notifications(
    db: Session,
    *,
    external_enabled: bool = False,
    now: datetime | None = None,
) -> int:
    now = now or datetime.now(UTC)
    deliveries = db.scalars(
        select(NotificationDelivery)
        .where(
            NotificationDelivery.status.in_(["pending", "retrying"]),
            NotificationDelivery.next_attempt_at <= now,
        )
        .order_by(NotificationDelivery.created_at)
        .limit(100)
    ).all()
    delivered = 0
    for delivery in deliveries:
        channel = db.get(NotificationChannel, delivery.channel_id)
        alert = db.get(AlertInstance, delivery.alert_id)
        if channel is None or alert is None or not channel.enabled:
            delivery.status = "cancelled"
            continue
        sent_last_minute = db.scalar(
            select(func.count(NotificationDelivery.id)).where(
                NotificationDelivery.channel_id == channel.id,
                NotificationDelivery.status == "delivered",
                NotificationDelivery.delivered_at >= now - timedelta(minutes=1),
            )
        )
        if (sent_last_minute or 0) >= channel.rate_limit_per_minute:
            delivery.next_attempt_at = now + timedelta(minutes=1)
            delivery.status = "retrying"
            continue
        delivery.attempt_count += 1
        try:
            response_code = await _send(
                channel, alert, delivery, external_enabled=external_enabled
            )
        except Exception as exc:  # noqa: BLE001 - error details must remain type-only.
            delivery.error_summary = type(exc).__name__
            if delivery.attempt_count >= 5:
                delivery.status = "failed"
            else:
                delivery.status = "retrying"
                delay = min(3600, 2 ** (delivery.attempt_count - 1) * 30)
                delivery.next_attempt_at = now + timedelta(seconds=delay)
        else:
            delivery.status = "delivered"
            delivery.response_code = response_code
            delivery.delivered_at = now
            delivery.error_summary = None
            delivered += 1
    return delivered
