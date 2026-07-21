from __future__ import annotations

import gzip

from guardian.diagnostics import Diagnosis
from guardian.reports import (
    bounded_redacted_log_bundle,
    incident_document,
    report_html,
    report_json,
    report_markdown,
)


def test_all_report_formats_are_redacted() -> None:
    diagnosis = Diagnosis(
        fault_type="container_exited",
        impact=["api"],
        evidence=[
            {
                "name": "log",
                "value": "Authorization: Bearer secret-token-value",
                "source": "docker",
            }
        ],
        excluded_causes=[],
        confidence=0.98,
        recommendations=["restart once"],
        auto_repair_allowed=True,
        risk="low",
        verification=["health succeeds"],
        rule_id="R04",
    )
    document = incident_document(
        incident_id="incident-1",
        title="API failed",
        diagnosis=diagnosis,
        timeline=[{"at": "2026-07-13T00:00:00Z", "message": "Cookie: session=private"}],
        repairs=[],
    )
    for rendered in (report_json(document), report_markdown(document), report_html(document)):
        assert "secret-token-value" not in rendered
        assert "session=private" not in rendered
        assert "REDACTED" in rendered


def test_log_bundle_is_bounded_compressed_and_redacted() -> None:
    lines = ["API_KEY=secret-value"] + ["x" * 100 for _ in range(100)]
    bundle = bounded_redacted_log_bundle(lines, max_bytes=500)
    unpacked = gzip.decompress(bundle).decode()
    assert "secret-value" not in unpacked
    assert "REDACTED" in unpacked
    assert "TRUNCATED" in unpacked
