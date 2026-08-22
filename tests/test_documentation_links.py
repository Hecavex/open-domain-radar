"""Validate documentation links without making normal CI depend on the network."""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+['\"][^'\"]*['\"])?\)|<(https?://[^>]+)>")

pytestmark = pytest.mark.release


def markdown_files() -> list[Path]:
    return sorted(path for path in ROOT.rglob("*.md") if ".git" not in path.parts)


def links_in(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [next(value for value in match.groups() if value) for match in MARKDOWN_LINK.finditer(text)]


def external_links() -> set[str]:
    return {
        link
        for path in markdown_files()
        for link in links_in(path)
        if urlsplit(link).scheme in {"http", "https"} and urlsplit(link).hostname not in {"127.0.0.1", "localhost"}
    }


def test_documentation_links_are_local_files_or_secure_external_urls() -> None:
    errors: list[str] = []
    for document in markdown_files():
        for link in links_in(document):
            parsed = urlsplit(link)
            if parsed.scheme in {"http", "https"}:
                if parsed.hostname not in {"127.0.0.1", "localhost"} and parsed.scheme != "https":
                    errors.append(f"{document.relative_to(ROOT)}: external link is not HTTPS: {link}")
                if parsed.username or parsed.password:
                    errors.append(f"{document.relative_to(ROOT)}: link contains credentials: {link}")
                continue
            if parsed.scheme in {"mailto"} or link.startswith("#"):
                continue
            target = (document.parent / unquote(parsed.path)).resolve()
            if not target.exists() or not target.is_relative_to(ROOT):
                errors.append(f"{document.relative_to(ROOT)}: missing or escaped local target: {link}")
    assert not errors, "\n".join(errors)


@pytest.mark.external
def test_external_documentation_links_reach_their_hosts_when_enabled() -> None:
    if os.getenv("ODR_CHECK_EXTERNAL_LINKS") != "1":
        pytest.skip("set ODR_CHECK_EXTERNAL_LINKS=1 for the live, non-hermetic link rehearsal")

    failures: list[str] = []
    with httpx.Client(
        follow_redirects=True,
        timeout=20,
        headers={"User-Agent": "Open-Domain-Radar-link-check/0.1"},
    ) as client:
        for link in sorted(external_links()):
            try:
                response = client.get(link)
            except httpx.HTTPError as exc:
                failures.append(f"{link}: {exc.__class__.__name__}")
                continue
            # Authentication and rate-limit responses still prove the target
            # exists; 404 and server errors indicate a stale or broken link.
            if response.status_code == 404 or response.status_code >= 500:
                failures.append(f"{link}: HTTP {response.status_code}")
    assert not failures, "\n".join(failures)
