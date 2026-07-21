from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(slots=True)
class DiagnosticContext:
    host_id: str
    service: str = "unknown"
    agent_online: bool = False
    local_app_healthy: bool | None = None
    external_https_ok: bool | None = None
    domain_http_ok: bool | None = None
    direct_origin_ok: bool | None = None
    tcp_443_ok: bool | None = None
    tls_ok: bool | None = None
    http_status: int | None = None
    container_state: str | None = None
    systemd_state: str | None = None
    local_port_listening: bool | None = None
    external_port_ok: bool | None = None
    all_external_probes_failed: bool = False
    logs: list[str] = field(default_factory=list)
    disk_percent: float | None = None
    inode_percent: float | None = None
    disk_usage_sources: list[dict[str, object]] = field(default_factory=list)
    recent_deployment: dict[str, object] | None = None
    database_error: str | None = None
    database_service_running: bool | None = None
    database_port_open: bool | None = None
    probe_locations: dict[str, bool] = field(default_factory=dict)


@dataclass(slots=True)
class Diagnosis:
    fault_type: str
    impact: list[str]
    evidence: list[dict[str, object]]
    excluded_causes: list[str]
    confidence: float
    recommendations: list[str]
    auto_repair_allowed: bool
    risk: str
    verification: list[str]
    rule_id: str


Rule = Callable[[DiagnosticContext], Diagnosis | None]


def evidence(name: str, value: object, source: str) -> dict[str, object]:
    return {"name": name, "value": value, "source": source}


def external_entrance_failure(ctx: DiagnosticContext) -> Diagnosis | None:
    if ctx.external_https_ok is False and ctx.agent_online and ctx.local_app_healthy is True:
        return Diagnosis(
            "external_entrance_failure",
            [ctx.host_id, ctx.service],
            [
                evidence("external_https", "failed", "external_probe"),
                evidence("agent", "online", "agent"),
                evidence("local_application", "healthy", "agent"),
            ],
            ["application process failure"],
            0.9,
            [
                "check DNS result",
                "check TLS certificate",
                "validate reverse proxy",
                "inspect route/firewall",
            ],
            False,
            "Do not restart a healthy application; entrance changes may require approval.",
            ["external HTTPS succeeds from two probe locations"],
            "R01",
        )
    return None


def dns_or_edge_failure(ctx: DiagnosticContext) -> Diagnosis | None:
    if ctx.domain_http_ok is False and ctx.direct_origin_ok is True:
        return Diagnosis(
            "dns_or_edge_failure",
            [ctx.service],
            [
                evidence("domain", "failed", "external_probe"),
                evidence("origin", "healthy", "origin_probe"),
            ],
            ["origin application failure"],
            0.95,
            ["compare authoritative DNS", "inspect Cloudflare/edge status", "check proxied record"],
            False,
            "DNS and production edge changes require manual approval.",
            ["domain resolves as expected", "domain HTTPS succeeds"],
            "R02",
        )
    return None


def reverse_proxy_backend(ctx: DiagnosticContext) -> Diagnosis | None:
    if ctx.tcp_443_ok and ctx.tls_ok and ctx.http_status == 502:
        return Diagnosis(
            "reverse_proxy_backend_unavailable",
            [ctx.service],
            [
                evidence("tcp_443", "connected", "external_probe"),
                evidence("tls", "valid", "external_probe"),
                evidence("http_status", 502, "external_probe"),
            ],
            ["DNS failure", "TLS failure", "public port block"],
            0.99,
            ["check configured upstream", "check local upstream health", "inspect proxy error log"],
            False,
            "Restart is allowed only when the upstream process is proven failed.",
            ["local upstream health succeeds", "external HTTP is not 502"],
            "R03",
        )
    return None


def application_health_failure(ctx: DiagnosticContext) -> Diagnosis | None:
    if (
        ctx.agent_online
        and ctx.local_app_healthy is False
        and ctx.container_state == "running"
    ):
        return Diagnosis(
            "application_health_failed",
            [ctx.host_id, ctx.service],
            [
                evidence("container_state", "running", "agent"),
                evidence("local_application", "failed", "agent_probe"),
                evidence("http_status", ctx.http_status, "agent_probe"),
            ],
            ["host offline", "container exited", "DNS failure"],
            0.97,
            ["run one bounded restart", "stop after failed postcheck", "escalate"],
            True,
            "A persistent failure must not create a restart loop.",
            ["local health check succeeds", "attempt limit remains enforced"],
            "R13",
        )
    return None


def exited_container(ctx: DiagnosticContext) -> Diagnosis | None:
    if ctx.agent_online and ctx.container_state in {"exited", "dead"}:
        return Diagnosis(
            "container_exited",
            [ctx.host_id, ctx.service],
            [evidence("container_state", ctx.container_state, "agent")],
            ["host offline"],
            0.98,
            ["collect bounded container logs", "restart once if the service allowlist permits"],
            True,
            "Level 1; one restart with cooldown and health verification.",
            ["container is running/healthy", "local and external health checks pass"],
            "R04",
        )
    return None


def failed_systemd(ctx: DiagnosticContext) -> Diagnosis | None:
    if ctx.systemd_state == "failed":
        return Diagnosis(
            "systemd_service_failed",
            [ctx.host_id, ctx.service],
            [
                evidence("systemd_state", "failed", "agent"),
                evidence("journal", ctx.logs[-20:], "journalctl"),
            ],
            [],
            0.97,
            ["classify exit code", "restart once if the unit is allowlisted"],
            True,
            "Level 1 with rate limit.",
            ["systemd is-active", "local and external health checks pass"],
            "R05",
        )
    return None


def ingress_block(ctx: DiagnosticContext) -> Diagnosis | None:
    if ctx.local_port_listening is True and ctx.external_port_ok is False:
        return Diagnosis(
            "ingress_or_route_failure",
            [ctx.host_id, ctx.service],
            [
                evidence("local_listener", True, "agent"),
                evidence("external_connect", False, "external_probe"),
            ],
            ["application not listening"],
            0.93,
            [
                "inspect host firewall read-only",
                "inspect provider security group/NAT",
                "compare routes",
            ],
            False,
            "Firewall and provider security group changes require approval.",
            ["external TCP connects from two locations"],
            "R06",
        )
    return None


def host_or_provider_outage(ctx: DiagnosticContext) -> Diagnosis | None:
    if not ctx.agent_online and ctx.all_external_probes_failed:
        return Diagnosis(
            "host_provider_or_network_outage",
            [ctx.host_id, "all services"],
            [
                evidence("agent", "offline", "controller"),
                evidence("all_external_probes", "failed", "external"),
            ],
            [],
            0.9,
            [
                "check provider console",
                "check regional route probes",
                "wait for recovery threshold",
            ],
            False,
            "Never auto-reinstall or rebuild a host from reachability evidence alone.",
            ["agent reconnects", "external probes recover"],
            "R07",
        )
    return None


def oom_failure(ctx: DiagnosticContext) -> Diagnosis | None:
    matches = [
        line for line in ctx.logs if re.search(r"(?i)out of memory|oom-kill|killed process", line)
    ]
    if matches:
        return Diagnosis(
            "memory_oom",
            [ctx.host_id, ctx.service],
            [evidence("oom_log", matches[-10:], "kernel/journal")],
            [],
            0.99,
            [
                "identify killed process and memory trend",
                "set safe limits or add memory after review",
            ],
            False,
            "Restarting without capacity correction can create a loop.",
            ["no new OOM event", "memory remains below threshold", "service health passes"],
            "R08",
        )
    return None


def storage_pressure(ctx: DiagnosticContext) -> Diagnosis | None:
    disk_high = ctx.disk_percent is not None and ctx.disk_percent >= 90
    inode_high = ctx.inode_percent is not None and ctx.inode_percent >= 90
    if disk_high or inode_high:
        return Diagnosis(
            "storage_pressure",
            [ctx.host_id],
            [
                evidence("disk_percent", ctx.disk_percent, "agent"),
                evidence("inode_percent", ctx.inode_percent, "agent"),
                evidence("largest_sources", ctx.disk_usage_sources[:20], "agent"),
            ],
            [],
            0.98,
            ["classify logs/Docker/database/cache usage", "clean only an explicit cache allowlist"],
            True,
            "Level 1 only for platform-owned expired temporary files or allowlisted cache.",
            ["disk and inode usage below threshold", "database and user paths unchanged"],
            "R09",
        )
    return None


def post_deployment_failure(ctx: DiagnosticContext) -> Diagnosis | None:
    unhealthy = (
        ctx.container_state in {"exited", "dead"}
        or ctx.systemd_state == "failed"
        or ctx.local_app_healthy is False
    )
    if unhealthy and ctx.recent_deployment:
        return Diagnosis(
            "post_deployment_regression",
            [ctx.host_id, ctx.service],
            [
                evidence("recent_deployment", ctx.recent_deployment, "change_log"),
                evidence("service_unhealthy", True, "agent"),
            ],
            [],
            0.92,
            ["compare deployment diff", "prefer a verified previous release rollback"],
            False,
            "Level 2 rollback is disabled until explicitly enabled for the service.",
            ["previous image/config restored", "local and external health checks pass"],
            "R10",
        )
    return None


def database_failure(ctx: DiagnosticContext) -> Diagnosis | None:
    if not ctx.database_error:
        return None
    error = ctx.database_error.lower()
    if ctx.database_service_running is False:
        subtype = "database_service_stopped"
    elif ctx.database_port_open is False:
        subtype = "database_port_unreachable"
    elif any(word in error for word in ("password", "authentication", "access denied")):
        subtype = "database_authentication_failed"
    elif any(word in error for word in ("too many connections", "pool exhausted")):
        subtype = "database_connections_exhausted"
    elif any(word in error for word in ("no space", "read-only file system", "disk full")):
        subtype = "database_storage_failure"
    elif any(word in error for word in ("corrupt", "malformed page", "checksum mismatch")):
        subtype = "database_corruption"
    else:
        subtype = "database_connection_failed"
    return Diagnosis(
        subtype,
        [ctx.host_id, ctx.service],
        [
            evidence("database_error", ctx.database_error, "application"),
            evidence("database_service_running", ctx.database_service_running, "agent"),
            evidence("database_port_open", ctx.database_port_open, "agent"),
        ],
        [],
        0.9,
        [
            "inspect database health without changing data",
            "check pool, authentication source, and storage",
        ],
        False,
        "Database recovery or credential changes require approval.",
        ["database health query succeeds", "application pool recovers"],
        "R11",
    )


def hong_kong_route_failure(ctx: DiagnosticContext) -> Diagnosis | None:
    locations = ctx.probe_locations
    if locations.get("hong_kong") is False and any(
        ok for name, ok in locations.items() if name != "hong_kong"
    ):
        return Diagnosis(
            "hong_kong_route_failure",
            ["hong_kong probe path", ctx.service],
            [evidence("probe_locations", locations, "external_probes")],
            ["global service outage", "target host outage"],
            0.96,
            ["compare traceroutes", "contact transit/provider if persistent"],
            False,
            "Do not restart a healthy remote service for a single-region route issue.",
            ["Hong Kong probe recovers for configured threshold"],
            "R12",
        )
    return None


class DiagnosticEngine:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules or [
            reverse_proxy_backend,
            application_health_failure,
            dns_or_edge_failure,
            hong_kong_route_failure,
            exited_container,
            failed_systemd,
            oom_failure,
            storage_pressure,
            post_deployment_failure,
            database_failure,
            ingress_block,
            external_entrance_failure,
            host_or_provider_outage,
        ]

    def diagnose(self, context: DiagnosticContext) -> list[Diagnosis]:
        results = [diagnosis for rule in self.rules if (diagnosis := rule(context)) is not None]
        return sorted(results, key=lambda item: item.confidence, reverse=True)
