"""Shared provider result types and fixed-origin HTTP safeguards."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass(slots=True)
class ProviderOutcome:
    """Small, provider-neutral result returned to the worker."""

    provider: str
    status: str
    items: list[dict[str, Any]] = field(default_factory=list)
    message: str | None = None

    @classmethod
    def skipped(cls, provider: str, reason: str) -> ProviderOutcome:
        # Missing optional credentials are a normal, successful no-op.
        return cls(provider=provider, status="skipped", message=reason)


def provider_error_code(error: Exception) -> str:
    """Map exceptions to safe operational codes.

    Raw provider messages can include request details, so they are never copied
    into the database or shown in the admin interface.
    """
    if isinstance(error, httpx.TimeoutException):
        return "provider_timeout"
    if isinstance(error, httpx.HTTPStatusError):
        status = error.response.status_code
        if status == 429:
            return "provider_rate_limited"
        if status in {401, 403}:
            return "provider_auth_failed"
        if status >= 500:
            return "provider_unavailable"
        return "provider_http_error"
    if isinstance(error, (httpx.NetworkError, httpx.ProtocolError)):
        return "provider_connection_failed"
    if isinstance(error, (ValueError, TypeError, KeyError)):
        return "provider_response_invalid"
    return "provider_error"
