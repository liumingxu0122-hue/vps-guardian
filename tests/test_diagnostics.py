from __future__ import annotations

import pytest
from guardian.diagnostics import DiagnosticContext, DiagnosticEngine


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        (
            {"external_https_ok": False, "agent_online": True, "local_app_healthy": True},
            "external_entrance_failure",
        ),
        ({"domain_http_ok": False, "direct_origin_ok": True}, "dns_or_edge_failure"),
        (
            {"tcp_443_ok": True, "tls_ok": True, "http_status": 502},
            "reverse_proxy_backend_unavailable",
        ),
        ({"agent_online": True, "container_state": "exited"}, "container_exited"),
        (
            {"systemd_state": "failed", "logs": ["unit exited with status 1"]},
            "systemd_service_failed",
        ),
        (
            {"local_port_listening": True, "external_port_ok": False},
            "ingress_or_route_failure",
        ),
        (
            {"agent_online": False, "all_external_probes_failed": True},
            "host_provider_or_network_outage",
        ),
        ({"logs": ["kernel: Out of memory: Killed process 42 (worker)"]}, "memory_oom"),
        (
            {
                "disk_percent": 96.0,
                "inode_percent": 30.0,
                "disk_usage_sources": [{"path": "/var/log", "bytes": 1000}],
            },
            "storage_pressure",
        ),
        (
            {"local_app_healthy": False, "recent_deployment": {"image": "app:v2"}},
            "post_deployment_regression",
        ),
        (
            {
                "database_error": "password authentication failed",
                "database_service_running": True,
                "database_port_open": True,
            },
            "database_authentication_failed",
        ),
        (
            {"probe_locations": {"hong_kong": False, "tokyo": True, "frankfurt": True}},
            "hong_kong_route_failure",
        ),
    ],
)
def test_required_diagnostic_rules(overrides: dict[str, object], expected: str) -> None:
    context = DiagnosticContext(host_id="node-1", service="api", **overrides)
    diagnoses = DiagnosticEngine().diagnose(context)
    assert expected in {diagnosis.fault_type for diagnosis in diagnoses}
    selected = next(diagnosis for diagnosis in diagnoses if diagnosis.fault_type == expected)
    assert selected.evidence
    assert 0.0 <= selected.confidence <= 1.0
    assert selected.verification


@pytest.mark.parametrize(
    ("error", "running", "port", "expected"),
    [
        ("connection refused", False, False, "database_service_stopped"),
        ("connection refused", True, False, "database_port_unreachable"),
        ("too many connections", True, True, "database_connections_exhausted"),
        ("no space left on device", True, True, "database_storage_failure"),
    ],
)
def test_database_failure_classification(
    error: str,
    running: bool,
    port: bool,
    expected: str,
) -> None:
    diagnoses = DiagnosticEngine().diagnose(
        DiagnosticContext(
            host_id="node-1",
            database_error=error,
            database_service_running=running,
            database_port_open=port,
        )
    )
    assert diagnoses[0].fault_type == expected


def test_single_region_failure_never_restarts_service() -> None:
    diagnosis = DiagnosticEngine().diagnose(
        DiagnosticContext(
            host_id="node-1",
            service="api",
            probe_locations={"hong_kong": False, "tokyo": True},
        )
    )[0]
    assert diagnosis.auto_repair_allowed is False
    assert "Do not restart" in diagnosis.risk
