from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from guardian import __version__
from guardian.api import router
from guardian.config import Settings, get_settings
from guardian.database import Base, SessionLocal, engine
from guardian.liveness import mark_stale_agents_offline
from guardian.monitoring import prune_monitoring_history, run_due_controller_checks
from guardian.notifications import deliver_pending_notifications


async def monitor_agent_liveness(offline_after_seconds: int) -> None:
    interval = max(10, min(30, offline_after_seconds // 3))
    while True:
        try:
            with SessionLocal() as database:
                mark_stale_agents_offline(
                    database, offline_after_seconds=offline_after_seconds
                )
                database.commit()
        except Exception:  # noqa: BLE001 - keep the bounded monitor alive and log the failure.
            logging.exception("agent liveness reconciliation failed")
        await asyncio.sleep(interval)


async def monitor_service_checks(settings: Settings) -> None:
    while True:
        try:
            with SessionLocal() as database:
                await run_due_controller_checks(database)
                await deliver_pending_notifications(
                    database,
                    external_enabled=settings.external_notifications_enabled,
                )
                prune_monitoring_history(
                    database,
                    metric_retention_days=settings.metric_retention_days,
                    check_retention_days=settings.service_result_retention_days,
                    max_metric_rows_per_host=settings.max_metric_rows_per_host,
                    max_results_per_check=settings.max_results_per_check,
                )
                database.commit()
        except Exception:  # noqa: BLE001 - keep the bounded monitor alive and log the failure.
            logging.exception("service monitoring reconciliation failed")
        await asyncio.sleep(10)


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if settings.auto_create_schema:
            Base.metadata.create_all(engine)
        liveness_task = asyncio.create_task(
            monitor_agent_liveness(settings.agent_offline_after_seconds),
            name="guardian-agent-liveness",
        )
        service_check_task = asyncio.create_task(
            monitor_service_checks(settings), name="guardian-service-checks"
        )
        try:
            yield
        finally:
            liveness_task.cancel()
            service_check_task.cancel()
            with suppress(asyncio.CancelledError):
                await liveness_task
            with suppress(asyncio.CancelledError):
                await service_check_task

    app = FastAPI(
        title="VPS Guardian Controller",
        version=__version__,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
    )
    app.include_router(router)

    return app


app = create_app()


def run() -> None:
    uvicorn.run("guardian.main:app", host="127.0.0.1", port=8090, reload=False)


if __name__ == "__main__":
    run()
