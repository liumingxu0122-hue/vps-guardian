from __future__ import annotations

import gzip
import html
import io
import json
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any, cast

from guardian.diagnostics import Diagnosis
from guardian.redaction import redact_structure, redact_text


def incident_document(
    *,
    incident_id: str,
    title: str,
    diagnosis: Diagnosis,
    timeline: list[dict[str, Any]],
    repairs: list[dict[str, Any]],
    recovered_at: datetime | None = None,
) -> dict[str, Any]:
    document = {
        "schema_version": 1,
        "incident_id": incident_id,
        "title": title,
        "generated_at": datetime.now(UTC).isoformat(),
        "first_seen_at": timeline[0].get("at") if timeline else None,
        "recovered_at": recovered_at.isoformat() if recovered_at else None,
        "diagnosis": asdict(diagnosis),
        "timeline": timeline,
        "repairs": repairs,
        "follow_up": diagnosis.recommendations,
    }
    return cast(dict[str, Any], redact_structure(document))


def report_json(document: dict[str, Any]) -> str:
    return json.dumps(redact_structure(document), ensure_ascii=False, indent=2)


def report_markdown(document: dict[str, Any]) -> str:
    doc = redact_structure(document)
    diagnosis = doc["diagnosis"]
    evidence_lines = "\n".join(
        f"- **{item['name']}** ({item['source']}): "
        f"`{json.dumps(item['value'], ensure_ascii=False)}`"
        for item in diagnosis["evidence"]
    )
    timeline_lines = "\n".join(
        f"- {item.get('at', 'unknown')}: {redact_text(str(item.get('message', '')))}"
        for item in doc["timeline"]
    )
    return (
        f"# Incident {doc['incident_id']}: {doc['title']}\n\n"
        f"- Fault type: `{diagnosis['fault_type']}`\n"
        f"- Confidence: `{diagnosis['confidence']}`\n"
        f"- Auto repair: `{diagnosis['auto_repair_allowed']}`\n"
        f"- Risk: {diagnosis['risk']}\n\n"
        f"## Evidence\n\n{evidence_lines}\n\n"
        f"## Timeline\n\n{timeline_lines}\n"
    )


def report_html(document: dict[str, Any]) -> str:
    markdown = report_markdown(document)
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Incident report</title>"
        "<style>body{font:14px system-ui;max-width:960px;margin:40px auto;padding:0 24px;"
        "background:#11151b;color:#e7edf4}pre{white-space:pre-wrap;line-height:1.6}</style>"
        f"</head><body><pre>{html.escape(markdown)}</pre></body></html>"
    )


def bounded_redacted_log_bundle(lines: list[str], max_bytes: int = 2_000_000) -> bytes:
    output = io.BytesIO()
    current = 0
    with gzip.GzipFile(fileobj=output, mode="wb", compresslevel=6) as archive:
        for line in lines:
            encoded = (redact_text(line.rstrip()) + "\n").encode()
            if current + len(encoded) > max_bytes:
                archive.write(b"[TRUNCATED: incident log byte limit reached]\n")
                break
            archive.write(encoded)
            current += len(encoded)
    return output.getvalue()
