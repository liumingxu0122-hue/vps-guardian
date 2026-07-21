from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from guardian.probes import ProbeDefinition, ProbeResult, run_probe
from guardian.state_machine import MonitorState, MonitorStateMachine


async def test_tcp_probe_against_local_server() -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await run_probe(
            ProbeDefinition(id="tcp-local", kind="tcp", target="127.0.0.1", port=port)
        )
    finally:
        server.close()
        await server.wait_closed()
    assert result.success is True
    assert result.latency_ms >= 0


async def test_http_json_probe() -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(4096)
        body = b'{"status":"ok","nested":{"ready":true}}'
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await run_probe(
            ProbeDefinition(
                id="http-local",
                kind="http",
                target=f"http://127.0.0.1:{port}/health",
                expected_json={"status": "ok", "nested.ready": True},
            )
        )
    finally:
        server.close()
        await server.wait_closed()
    assert result.success is True
    assert result.evidence["status"] == 200


def observation(success: bool) -> ProbeResult:
    return ProbeResult("probe", "http", success, datetime.now(UTC), 1.0)


def test_state_machine_hysteresis() -> None:
    machine = MonitorStateMachine(failure_threshold=3, recovery_threshold=2, cooldown_seconds=0)
    assert machine.observe(observation(True)).current == MonitorState.healthy
    assert machine.observe(observation(False)).current == MonitorState.pending_failure
    assert machine.observe(observation(False)).incident_opened is False
    opened = machine.observe(observation(False))
    assert opened.current == MonitorState.failing
    assert opened.incident_opened is True
    assert machine.observe(observation(True)).current == MonitorState.pending_recovery
    recovered = machine.observe(observation(True))
    assert recovered.current == MonitorState.healthy
    assert recovered.incident_recovered is True


def test_disabled_probe_is_explicit_success() -> None:
    result = asyncio.run(
        run_probe(ProbeDefinition(id="icmp-off", kind="icmp", target="127.0.0.1", enabled=False))
    )
    assert result.success is True
    assert result.evidence == {"disabled": True}
