from __future__ import annotations

import asyncio
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Literal
from urllib.parse import urljoin, urlparse

import httpx
from pydantic import BaseModel, Field, field_validator


class ProbeDefinition(BaseModel):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,119}$")
    kind: Literal["tcp", "http", "dns", "tls", "icmp"]
    target: str = Field(min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    timeout_seconds: float = Field(default=5.0, ge=0.2, le=30.0)
    expected_statuses: list[int] = Field(default_factory=lambda: [200])
    expected_contains: str | None = Field(default=None, max_length=1024)
    expected_json: dict[str, object] | None = None
    expected_addresses: list[str] = Field(default_factory=list)
    verify_tls: bool = True
    enabled: bool = True
    allowed_networks: list[str] = Field(default_factory=list, max_length=32)
    denied_networks: list[str] = Field(default_factory=list, max_length=32)
    max_response_bytes: int = Field(default=65536, ge=1024, le=1_048_576)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        if "\x00" in value or any(character.isspace() for character in value):
            raise ValueError("target contains invalid characters")
        return value


@dataclass(slots=True)
class ProbeResult:
    probe_id: str
    kind: str
    success: bool
    checked_at: datetime
    latency_ms: float
    evidence: dict[str, object] = field(default_factory=dict)
    error: str | None = None
    status: Literal["ok", "failed", "unsupported"] = "ok"


_ALWAYS_DENIED_ADDRESSES = {
    ip_address("169.254.169.254"),
    ip_address("100.100.100.200"),
}


def _address_is_allowed(
    address: IPv4Address | IPv6Address, definition: ProbeDefinition
) -> bool:
    if address in _ALWAYS_DENIED_ADDRESSES:
        return False
    denied = [ip_network(value, strict=False) for value in definition.denied_networks]
    if any(address in network for network in denied):
        return False
    allowed = [ip_network(value, strict=False) for value in definition.allowed_networks]
    if allowed:
        return any(address in network for network in allowed)
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


async def _resolve_allowed_addresses(
    definition: ProbeDefinition, hostname: str, port: int
) -> list[str]:
    try:
        literal = ip_address(hostname)
        addresses = [literal]
    except ValueError:
        loop = asyncio.get_running_loop()
        records = await asyncio.wait_for(
            loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM),
            timeout=definition.timeout_seconds,
        )
        addresses = sorted({ip_address(record[4][0]) for record in records}, key=str)
    if not addresses or any(not _address_is_allowed(address, definition) for address in addresses):
        raise ValueError("target address is blocked by probe network policy")
    return [str(address) for address in addresses]


def _safe_hostname(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}")
    hostname = parsed.hostname or target
    if len(hostname) > 253 or not re.fullmatch(r"[A-Za-z0-9._:-]+", hostname):
        raise ValueError("invalid hostname")
    return hostname


async def _tcp_probe(definition: ProbeDefinition) -> dict[str, object]:
    if not definition.port:
        raise ValueError("TCP probe requires a port")
    host = _safe_hostname(definition.target)
    addresses = await _resolve_allowed_addresses(definition, host, definition.port)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(addresses[0], definition.port),
        timeout=definition.timeout_seconds,
    )
    del reader
    peer = writer.get_extra_info("peername")
    writer.close()
    await writer.wait_closed()
    return {"peer": str(peer), "port": definition.port, "resolved_addresses": addresses}


async def _dns_probe(definition: ProbeDefinition) -> dict[str, object]:
    host = _safe_hostname(definition.target)
    addresses = await _resolve_allowed_addresses(definition, host, definition.port or 443)
    if definition.expected_addresses and not set(definition.expected_addresses).issubset(addresses):
        raise ValueError("DNS result does not contain all expected addresses")
    return {"addresses": addresses}


async def _tls_probe(definition: ProbeDefinition) -> dict[str, object]:
    if not definition.port:
        definition.port = 443
    host = _safe_hostname(definition.target)
    addresses = await _resolve_allowed_addresses(definition, host, definition.port)
    context = ssl.create_default_context()
    if not definition.verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            addresses[0], definition.port, ssl=context, server_hostname=host
        ),
        timeout=definition.timeout_seconds,
    )
    del reader
    ssl_object = writer.get_extra_info("ssl_object")
    certificate = ssl_object.getpeercert() if ssl_object else {}
    writer.close()
    await writer.wait_closed()
    not_after = certificate.get("notAfter") if certificate else None
    expires_at = None
    days_remaining = None
    if isinstance(not_after, str):
        expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC)
        days_remaining = (expires_at - datetime.now(UTC)).total_seconds() / 86400
    return {
        "subject": certificate.get("subject", []),
        "issuer": certificate.get("issuer", []),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_remaining": round(days_remaining, 2) if days_remaining is not None else None,
        "cipher": ssl_object.cipher()[0] if ssl_object else None,
        "resolved_addresses": addresses,
    }


def _lookup_json(document: object, path: str) -> object:
    current = document
    for component in path.split("."):
        if not isinstance(current, dict) or component not in current:
            raise KeyError(path)
        current = current[component]
    return current


async def _http_probe(definition: ProbeDefinition) -> dict[str, object]:
    current_url = definition.target
    timeout = httpx.Timeout(definition.timeout_seconds)
    async with httpx.AsyncClient(
        timeout=timeout,
        verify=definition.verify_tls,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        response: httpx.Response | None = None
        sample = bytearray()
        resolved_addresses: list[str] = []
        for redirect_count in range(4):
            parsed = urlparse(current_url)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("HTTP probe requires a credential-free HTTP(S) URL")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            resolved_addresses = await _resolve_allowed_addresses(
                definition, parsed.hostname, port
            )
            approved_url = httpx.URL(current_url).copy_with(host=resolved_addresses[0])
            request = client.build_request(
                "GET",
                approved_url,
                headers={
                    "Host": parsed.netloc,
                    "User-Agent": "VPS-Guardian/0.1",
                    "Accept": "*/*",
                },
            )
            request.extensions["sni_hostname"] = parsed.hostname
            response = await client.send(request, stream=True)
            try:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location or redirect_count >= 3:
                        raise ValueError("HTTP redirect limit exceeded")
                    current_url = urljoin(current_url, location)
                    continue
                async for chunk in response.aiter_bytes():
                    sample.extend(chunk)
                    if len(sample) > definition.max_response_bytes:
                        raise ValueError("HTTP response exceeded the configured size limit")
                break
            finally:
                await response.aclose()
        if response is None:
            raise ValueError("HTTP probe produced no response")
    if response.status_code not in definition.expected_statuses:
        raise ValueError(f"unexpected HTTP status {response.status_code}")
    sample_text = sample.decode(response.encoding or "utf-8", errors="replace")
    if definition.expected_contains and definition.expected_contains not in sample_text:
        raise ValueError("expected response content missing")
    json_matches: dict[str, object] = {}
    if definition.expected_json:
        document = json.loads(sample_text)
        for path, expected in definition.expected_json.items():
            actual = _lookup_json(document, path)
            if actual != expected:
                raise ValueError(f"JSON field {path} did not match")
            json_matches[path] = actual
    return {
        "status": response.status_code,
        "final_url": current_url,
        "content_length": len(sample),
        "json_matches": json_matches,
        "resolved_addresses": resolved_addresses,
    }


async def _icmp_probe(definition: ProbeDefinition) -> dict[str, object]:
    host = _safe_hostname(definition.target)
    addresses = await _resolve_allowed_addresses(definition, host, 0)
    timeout_ms = max(1000, int(definition.timeout_seconds * 1000))
    if __import__("os").name == "nt":
        arguments = ["ping", "-n", "1", "-w", str(timeout_ms), addresses[0]]
    else:
        arguments = [
            "ping",
            "-c",
            "1",
            "-W",
            str(max(1, int(definition.timeout_seconds))),
            addresses[0],
        ]
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(process.communicate(), definition.timeout_seconds + 2)
    if process.returncode != 0:
        raise OSError((stderr or stdout).decode(errors="replace")[:256])
    return {
        "reply": stdout.decode(errors="replace")[-256:],
        "resolved_addresses": addresses,
    }


async def run_probe(definition: ProbeDefinition) -> ProbeResult:
    started = time.perf_counter()
    checked_at = datetime.now(UTC)
    if not definition.enabled:
        return ProbeResult(
            probe_id=definition.id,
            kind=definition.kind,
            success=True,
            checked_at=checked_at,
            latency_ms=0,
            evidence={"disabled": True},
        )
    handlers = {
        "tcp": _tcp_probe,
        "dns": _dns_probe,
        "tls": _tls_probe,
        "http": _http_probe,
        "icmp": _icmp_probe,
    }
    try:
        evidence = await handlers[definition.kind](definition)
        return ProbeResult(
            probe_id=definition.id,
            kind=definition.kind,
            success=True,
            checked_at=checked_at,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            evidence=evidence,
        )
    except (FileNotFoundError, PermissionError) as exc:
        if definition.kind != "icmp":
            raise
        return ProbeResult(
            probe_id=definition.id,
            kind=definition.kind,
            success=False,
            checked_at=checked_at,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            error=f"{type(exc).__name__}: ICMP probe is unsupported",
            status="unsupported",
        )
    except (TimeoutError, OSError, ValueError, json.JSONDecodeError, KeyError) as exc:
        return ProbeResult(
            probe_id=definition.id,
            kind=definition.kind,
            success=False,
            checked_at=checked_at,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            error=f"{type(exc).__name__}: {str(exc)[:300]}",
            status="failed",
        )
