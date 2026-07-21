from __future__ import annotations

import pytest
from guardian.redaction import REDACTED, redact_structure, redact_text


@pytest.mark.parametrize(
    ("source", "forbidden"),
    [
        ("Authorization: Bearer super-secret-token-value", "super-secret"),
        ("Cookie: session=abc123; csrf=xyz", "abc123"),
        ("Set-Cookie: session=abc123", "abc123"),
        ("API_KEY=sk-production-secret", "sk-production"),
        ("postgresql://admin:password@db/internal", "password"),
        ("https://host/path?token=secret-value&safe=yes", "secret-value"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123", "eyJhbGci"),
        ("-----BEGIN " + "PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----", "abc123"),
    ],
)
def test_redacts_secret_forms(source: str, forbidden: str) -> None:
    result = redact_text(source)
    assert forbidden not in result
    assert REDACTED in result


def test_redacts_nested_structures() -> None:
    source = {
        "message": "safe",
        "authorization": "Bearer secret",
        "nested": {"db_password": "password", "url": "https://x/?api_key=secret"},
    }
    result = redact_structure(source)
    assert result["message"] == "safe"
    assert result["authorization"] == REDACTED
    assert result["nested"]["db_password"] == REDACTED
    assert "secret" not in result["nested"]["url"]
