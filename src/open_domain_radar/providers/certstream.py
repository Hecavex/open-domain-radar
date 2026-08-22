"""Bounded CertStream collection; certificate names are never contacted."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import websockets
from sqlalchemy.orm import Session

from ..config import Settings
from ..matching import match_domain
from ..models import CollectionRun, Suppression, WatchTarget
from ..security import normalize_domain
from ..services import active_suppressions, active_targets, ingest_observable, queue_configured_pivots


def parse_certstream_message(message: str | bytes | dict[str, Any]) -> list[str]:
    """Return normalized DNS names from one certificate-update message."""
    if isinstance(message, (str, bytes)):
        try:
            payload = json.loads(message)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []
    else:
        payload = message

    if not isinstance(payload, dict):
        return []
    if payload.get("message_type") != "certificate_update":
        return []

    data = payload.get("data", {})
    if not isinstance(data, dict):
        return []
    leaf = data.get("leaf_cert", {})
    if not isinstance(leaf, dict):
        return []
    names = leaf.get("all_domains", [])
    if not isinstance(names, list):
        return []

    output: set[str] = set()
    # A malformed or unusually large certificate should not monopolize one
    # collection pass. Five hundred names is already far above normal usage.
    for value in names[:500]:
        if not isinstance(value, str):
            continue
        try:
            output.add(normalize_domain(value.removeprefix("*.")))
        except ValueError:
            continue
    return sorted(output)


class CertStreamCollector:
    def __init__(self, url: str, session_factory: Callable[[], Session], settings: Settings):
        self.url = url
        self.session_factory = session_factory
        self.settings = settings

    async def collect(self, seconds: int = 240) -> dict[str, int]:
        """Listen for a bounded window and store matching certificate names."""
        seconds = min(max(seconds, 5), 900)
        stats = {"messages": 0, "dns_names": 0, "matches": 0, "pivots_queued": 0, "pivots_skipped": 0}
        session = self.session_factory()
        run = CollectionRun(provider="certstream", state="running", stats=dict(stats))
        session.add(run)
        session.commit()
        try:
            targets = active_targets(session)
            suppressions = active_suppressions(session)
            if not any(target.enabled for target in targets):
                run.state = "skipped"
                run.error = "no_watch_targets"
                return stats
            async with asyncio.timeout(seconds):
                async with websockets.connect(
                    self.url,
                    open_timeout=15,
                    close_timeout=5,
                    max_size=2 * 1024 * 1024,
                    max_queue=64,
                    ping_interval=20,
                ) as socket:
                    async for message in socket:
                        stats["messages"] += 1
                        domains = parse_certstream_message(message)
                        stats["dns_names"] += len(domains)
                        for domain in domains:
                            matched, pivots_queued, pivots_skipped = self._process_domain(
                                session,
                                domain,
                                targets,
                                suppressions,
                            )
                            stats["matches"] += matched
                            stats["pivots_queued"] += pivots_queued
                            stats["pivots_skipped"] += pivots_skipped

                        if stats["messages"] % 100 == 0:
                            # Periodic commits bound the amount of work lost if
                            # the WebSocket disconnects or the worker restarts.
                            session.commit()
        except TimeoutError:
            run.state = "success" if stats["matches"] else "healthy_empty"
        except Exception:
            run.state = "failed"
            run.error = "certstream_connection_failed"
            raise
        else:
            run.state = "success" if stats["matches"] else "healthy_empty"
        finally:
            run.stats = stats
            run.finished_at = datetime.now(UTC)
            session.commit()
            session.close()
        return stats

    def _process_domain(
        self,
        session: Session,
        domain: str,
        targets: list[WatchTarget],
        suppressions: list[Suppression],
    ) -> tuple[int, int, int]:
        decision = match_domain(domain, targets, suppressions)
        candidate = ingest_observable(
            session,
            domain,
            provider="certstream",
            payload={"certificate_name": domain},
            decision=decision,
        )
        if candidate is None:
            return 0, 0, 0

        # CertStream is only discovery metadata. We never connect to the domain
        # itself; configured passive providers may enrich it later.
        queued, skipped = queue_configured_pivots(
            session,
            candidate,
            self.settings,
            trigger="certstream_match",
        )
        return 1, len(queued), len(skipped)
