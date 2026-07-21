from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

from guardian.database import SessionLocal
from guardian.models import AlertInstance, AlertRule, NotificationChannel, NotificationDelivery
from guardian.notifications import deliver_pending_notifications
from sqlalchemy import select


async def test_webhook_uses_external_reference_and_retries_without_secret_leak(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    attempts = 0
    received: list[dict[str, object]] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal attempts
        attempts += 1
        request = await reader.read(65536)
        body = request.split(b"\r\n\r\n", 1)[1]
        received.append(json.loads(body))
        status = b"500 Error" if attempts == 1 else b"204 No Content"
        writer.write(b"HTTP/1.1 " + status + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}/mock"
    monkeypatch.setenv("GUARDIAN_TEST_WEBHOOK_URL", endpoint)
    now = datetime.now(UTC)
    try:
        with SessionLocal() as db:
            rule = AlertRule(
                name="notification-test",
                source_type="service_check",
                source_id="check-test",
            )
            db.add(rule)
            db.flush()
            alert = AlertInstance(
                rule_id=rule.id,
                fingerprint="b" * 64,
                state="firing",
                summary="service unavailable",
            )
            channel = NotificationChannel(
                name="local-webhook",
                kind="webhook",
                configuration={"endpoint_env": "GUARDIAN_TEST_WEBHOOK_URL"},
            )
            db.add_all([alert, channel])
            db.flush()
            delivery = NotificationDelivery(
                channel_id=channel.id,
                alert_id=alert.id,
                event_type="firing",
                next_attempt_at=now,
            )
            db.add(delivery)
            db.commit()
            assert await deliver_pending_notifications(db, now=now) == 0
            db.flush()
            db.refresh(delivery)
            assert delivery.status == "retrying"
            assert delivery.error_summary == "RuntimeError"
            assert endpoint not in (delivery.error_summary or "")
            assert await deliver_pending_notifications(
                db, now=now + timedelta(seconds=31)
            ) == 1
            db.flush()
            db.refresh(delivery)
            assert delivery.status == "delivered"
            assert delivery.attempt_count == 2
            assert delivery.response_code == 204
            assert received[0]["summary"] == "service unavailable"
    finally:
        server.close()
        await server.wait_closed()


async def test_external_webhook_is_blocked_by_default(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("GUARDIAN_EXTERNAL_WEBHOOK", "https://example.test/hook")
    now = datetime.now(UTC)
    with SessionLocal() as db:
        rule = AlertRule(
            name="external-notification-test",
            source_type="host_liveness",
            source_id="host-test",
        )
        db.add(rule)
        db.flush()
        alert = AlertInstance(
            rule_id=rule.id,
            fingerprint="c" * 64,
            state="firing",
            summary="offline",
        )
        channel = NotificationChannel(
            name="external-webhook",
            kind="webhook",
            configuration={"endpoint_env": "GUARDIAN_EXTERNAL_WEBHOOK"},
        )
        db.add_all([alert, channel])
        db.flush()
        delivery = NotificationDelivery(
            channel_id=channel.id,
            alert_id=alert.id,
            event_type="firing",
            next_attempt_at=now,
        )
        db.add(delivery)
        db.commit()
        assert await deliver_pending_notifications(db, now=now) == 0
        failed = db.scalar(select(NotificationDelivery))
        assert failed is not None
        assert failed.status == "retrying"
        assert failed.error_summary == "NotificationConfigurationError"
