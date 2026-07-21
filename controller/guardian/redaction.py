from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"

PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.DOTALL,
)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
BEARER = re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/-]{8,}=*")
HEADER_SECRET = re.compile(
    r"(?im)^((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)\s*:\s*).+$"
)
KEY_VALUE_SECRET = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|jwt)"
    r"(\s*[:=]\s*)([^\s,;]+|\"[^\"]*\"|'[^']*')"
)
DATABASE_URL = re.compile(
    r"(?i)\b(postgresql(?:\+\w+)?|mysql(?:\+\w+)?|mongodb(?:\+srv)?|redis)://([^\s/@:]+):([^\s/@]+)@"
)
SENSITIVE_QUERY_KEYS = {
    "token",
    "access_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "signature",
    "auth",
    "password",
}


def _redact_url_queries(text: str) -> str:
    url_pattern = re.compile(r"https?://[^\s<>\"']+")

    def replace(match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            parts = urlsplit(raw)
            if not parts.query:
                return raw
            query = [
                (key, REDACTED if key.lower() in SENSITIVE_QUERY_KEYS else value)
                for key, value in parse_qsl(parts.query, keep_blank_values=True)
            ]
            return urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    parts.path,
                    urlencode(query, safe="[]"),
                    parts.fragment,
                )
            )
        except ValueError:
            return raw

    return url_pattern.sub(replace, text)


def redact_text(value: str) -> str:
    value = PEM_PRIVATE_KEY.sub(REDACTED, value)
    value = HEADER_SECRET.sub(lambda m: f"{m.group(1)}{REDACTED}", value)
    value = BEARER.sub(lambda m: f"{m.group(1)}{REDACTED}", value)
    value = JWT.sub(REDACTED, value)
    value = DATABASE_URL.sub(lambda m: f"{m.group(1)}://{REDACTED}:{REDACTED}@", value)
    value = KEY_VALUE_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", value)
    return _redact_url_queries(value)


def redact_structure(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_structure(item) for item in value)
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if any(
                marker in normalized
                for marker in (
                    "password",
                    "secret",
                    "token",
                    "cookie",
                    "authorization",
                    "private_key",
                    "api_key",
                )
            ):
                output[str(key)] = REDACTED
            else:
                output[str(key)] = redact_structure(item)
        return output
    return value
