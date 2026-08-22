"""Optional passive enrichment adapters using allow-listed API origins only."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx

from ..security import normalize_domain
from .base import ProviderOutcome

MAX_PROVIDER_REQUESTS = 3
MAX_PROVIDER_RESPONSE_BYTES = 2 * 1024 * 1024


class URLScanAdapter:
    """Read existing URLScan reports without submitting or visiting a domain."""

    origin = "https://urlscan.io"

    async def search(self, query: str, api_key: str | None, limit: int = 50) -> ProviderOutcome:
        if not api_key:
            return ProviderOutcome.skipped("urlscan", "missing_api_key")
        limit = min(max(limit, 1), 100)

        # Query text is sent only to the fixed URLScan origin below. Newlines are
        # rejected so a stored target cannot alter the request structure.
        if len(query) > 200 or any(char in query for char in "\r\n"):
            raise ValueError("invalid URLScan query")

        async with httpx.AsyncClient(base_url=self.origin, timeout=20, follow_redirects=False) as client:
            payload = await _bounded_json(
                client,
                "/api/v1/search/",
                params={"q": query, "size": limit},
                headers={"api-key": api_key, "Accept": "application/json"},
            )
        results = payload.get("results", [])
        if not isinstance(results, list):
            raise ValueError("URLScan results must be a list")

        items: list[dict[str, Any]] = []
        for result in results[:limit]:
            item = _parse_urlscan_result(result, self.origin)
            if item is not None:
                items.append(item)
        return ProviderOutcome("urlscan", "success", items)


class VirusTotalAdapter:
    """Read passive VirusTotal resolution relationships for one domain."""

    origin = "https://www.virustotal.com"

    async def domain_relationships(self, domain: str, api_key: str | None, limit: int = 40) -> ProviderOutcome:
        if not api_key:
            return ProviderOutcome.skipped("virustotal", "missing_api_key")
        domain = normalize_domain(domain)
        limit = min(max(limit, 1), 40)
        async with httpx.AsyncClient(base_url=self.origin, timeout=20, follow_redirects=False) as client:
            payload = await _bounded_json(
                client,
                f"/api/v3/domains/{domain}/relationships/resolutions",
                params={"limit": limit},
                headers={"x-apikey": api_key, "Accept": "application/json"},
            )
        data = payload.get("data", [])
        if not isinstance(data, list):
            raise ValueError("VirusTotal relationship data must be a list")

        items = [_parse_virustotal_result(entry) for entry in data[:limit] if isinstance(entry, dict)]
        return ProviderOutcome("virustotal", "success", items)


def _parse_urlscan_result(result: Any, origin: str) -> dict[str, Any] | None:
    if not isinstance(result, dict):
        return None
    page = result.get("page", {})
    task = result.get("task", {})
    if not isinstance(page, dict) or not isinstance(task, dict):
        return None

    raw_domain = page.get("domain")
    if not isinstance(raw_domain, str):
        return None
    try:
        domain = normalize_domain(raw_domain)
    except ValueError:
        return None

    scan_id = str(task.get("uuid", ""))[:80]
    reference = None
    if re.fullmatch(r"[A-Za-z0-9-]{12,80}", scan_id):
        # Construct the reference from a validated ID. Never store the scanned
        # URL, whose path or query may contain victim-specific information.
        reference = f"{origin}/result/{scan_id}/"

    return {
        "domain": domain,
        "observable": domain,
        "scan_id": scan_id,
        "reference": reference,
        "observed_at": task.get("time"),
        "ip_address": str(page.get("ip", ""))[:64] or None,
        "country": str(page.get("country", ""))[:2].upper() or None,
        "status_code": page.get("status") if isinstance(page.get("status"), int) else None,
    }


def _parse_virustotal_result(entry: dict[str, Any]) -> dict[str, Any]:
    raw_attributes = entry.get("attributes", {})
    attributes = raw_attributes if isinstance(raw_attributes, dict) else {}
    return {
        "resolution_id": str(entry.get("id", ""))[:200],
        "date": attributes.get("date"),
        "host_name": str(attributes.get("host_name", ""))[:253],
        "ip_address": str(attributes.get("ip_address", ""))[:64],
    }


async def _bounded_json(
    client: httpx.AsyncClient,
    path: str,
    *,
    params: dict[str, Any],
    headers: dict[str, str],
    maximum_bytes: int = MAX_PROVIDER_RESPONSE_BYTES,
) -> dict[str, Any]:
    """GET a JSON object with a strict three-request and size budget."""
    for request_number in range(1, MAX_PROVIDER_REQUESTS + 1):
        try:
            async with client.stream("GET", path, params=params, headers=headers) as response:
                transient_status = response.status_code == 429 or response.status_code >= 500
                if not transient_status or request_number == MAX_PROVIDER_REQUESTS:
                    response.raise_for_status()
                    return await _read_json_object(response, maximum_bytes)
        except (httpx.TimeoutException, httpx.NetworkError):
            if request_number == MAX_PROVIDER_REQUESTS:
                raise

        # Retry only timeouts, network failures, rate limits, and server errors.
        # Authentication, validation, and other client errors are terminal.
        await asyncio.sleep(2 ** (request_number - 1))
    raise RuntimeError("provider retry budget exhausted")


async def _read_json_object(response: httpx.Response, maximum_bytes: int) -> dict[str, Any]:
    content = bytearray()
    async for chunk in response.aiter_bytes():
        content.extend(chunk)
        if len(content) > maximum_bytes:
            raise ValueError("provider response exceeded size limit")

    decoded = json.loads(content)
    if not isinstance(decoded, dict):
        raise ValueError("provider response must be a JSON object")
    return decoded
