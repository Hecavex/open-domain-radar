"""Collection and passive-pivot worker."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .config import Settings
from .db import Database
from .matching import match_domain
from .models import Candidate, CollectionRun, PivotJob, Provider
from .providers import CertStreamCollector, URLScanAdapter, VirusTotalAdapter
from .providers.base import ProviderOutcome, provider_error_code
from .security import SecretBox
from .services import active_suppressions, active_targets, ingest_observable


@dataclass(frozen=True, slots=True)
class _ClaimedPivot:
    job_id: int
    provider_kind: str
    provider_config: dict[str, Any]
    target_id: int | None
    domain: str
    secret_ciphertext: str | None


class RadarWorker:
    def __init__(self, database: Database, settings: Settings):
        self.database = database
        self.settings = settings

    async def run_once(self, limit: int = 10) -> dict[str, int]:
        """Process a bounded batch of queued passive-pivot jobs."""
        counters = {"processed": 0, "success": 0, "skipped": 0, "failed": 0, "discovered": 0}
        self._recover_stale_jobs()

        for job_id in self._due_job_ids(limit):
            counters["processed"] += 1
            claimed = self._claim_job(job_id)
            if claimed is None:
                counters["skipped"] += 1
                continue

            try:
                secret = self._provider_secret(claimed)
                # Keep provider I/O outside a database transaction. A slow API
                # must not hold SQLite locks or block the public dashboard.
                outcome = await self._pivot(
                    claimed.domain,
                    claimed.provider_kind,
                    claimed.provider_config,
                    secret,
                )
            except Exception as exc:
                error_code = provider_error_code(exc)
                self._record_job_failure(claimed.job_id, claimed.provider_kind, error_code)
                counters["failed"] += 1
                continue

            result, discovered = self._store_pivot_outcome(claimed, outcome)
            counters[result] += 1
            counters["discovered"] += discovered
        return counters

    def _due_job_ids(self, limit: int) -> list[int]:
        batch_size = min(max(limit, 1), 50)
        with self.database.session() as db:
            return list(
                db.scalars(
                    select(PivotJob.id)
                    .where(PivotJob.state == "queued", PivotJob.not_before <= datetime.now(UTC))
                    .order_by(PivotJob.created_at)
                    .limit(batch_size)
                )
            )

    def _provider_secret(self, claimed: _ClaimedPivot) -> str | None:
        environment_secret: str | None = None
        if claimed.provider_kind == "urlscan":
            environment_secret = self.settings.urlscan_api_key
        elif claimed.provider_kind == "virustotal":
            environment_secret = self.settings.virustotal_api_key

        if environment_secret:
            return environment_secret
        if claimed.secret_ciphertext:
            return SecretBox.load(self.settings).decrypt(claimed.secret_ciphertext)
        return None

    def _store_pivot_outcome(
        self,
        claimed: _ClaimedPivot,
        outcome: ProviderOutcome,
    ) -> tuple[str, int]:
        """Commit one provider outcome after all network work has finished."""
        with self.database.session() as db:
            job = db.get(PivotJob, claimed.job_id)
            candidate = db.get(Candidate, job.candidate_id) if job else None
            provider = db.scalar(select(Provider).where(Provider.kind == claimed.provider_kind))
            if job is None or job.state != "running" or candidate is None or provider is None:
                return "skipped", 0

            provider.last_status = outcome.status
            provider.last_message = outcome.message
            provider.last_run_at = datetime.now(UTC)

            if outcome.status == "skipped":
                job.state = "skipped"
                job.last_error = outcome.message
                job.finished_at = datetime.now(UTC)
                return "skipped", 0

            discovered = self._ingest_pivot_items(
                db,
                job,
                claimed.target_id,
                outcome.items,
            )
            job.state = "success"
            job.last_error = None
            job.finished_at = datetime.now(UTC)
            return "success", discovered

    @staticmethod
    def _ingest_pivot_items(
        db: Session,
        job: PivotJob,
        expected_target_id: int | None,
        items: list[dict[str, Any]],
    ) -> int:
        targets = active_targets(db)
        suppressions = active_suppressions(db)
        discovered = 0

        for item in items:
            observable = item.get("observable") or item.get("domain") or item.get("host_name")
            if not isinstance(observable, str) or not observable:
                continue

            try:
                item_domain = item.get("domain") or item.get("host_name") or observable
                decision = match_domain(str(item_domain), targets, suppressions)

                # A pivot can return unrelated infrastructure. Keep only items
                # that independently match the same target as the seed.
                if not decision.accepted or decision.target_id != expected_target_id:
                    continue

                reference = item.get("reference")
                safe_reference = reference if isinstance(reference, str) else None
                candidate = ingest_observable(
                    db,
                    observable,
                    provider=job.provider,
                    payload=item,
                    reference=safe_reference,
                    decision=decision,
                )
                if candidate is not None:
                    discovered += 1
            except ValueError:
                # One malformed provider row must not discard the rest of the
                # bounded response or fail the already-valid seed candidate.
                continue
        return discovered

    def _claim_job(self, job_id: int) -> _ClaimedPivot | None:
        """Atomically claim one due job before any provider work begins.

        The conditional UPDATE is the concurrency boundary: when two workers
        see the same queued ID, exactly one can change it to ``running``.
        """
        claimed_at = datetime.now(UTC)
        with self.database.session() as db:
            result = db.execute(
                update(PivotJob)
                .where(
                    PivotJob.id == job_id,
                    PivotJob.state == "queued",
                    PivotJob.not_before <= claimed_at,
                )
                .values(
                    state="running",
                    started_at=claimed_at,
                    finished_at=None,
                    attempts=PivotJob.attempts + 1,
                )
            )
            if result.rowcount != 1:
                return None
            job = db.get(PivotJob, job_id)
            candidate = db.get(Candidate, job.candidate_id) if job else None
            provider = db.scalar(select(Provider).where(Provider.kind == job.provider)) if job else None
            if job is None or candidate is None or provider is None or not provider.enabled:
                if job is not None:
                    job.state = "skipped"
                    job.last_error = "candidate_or_provider_unavailable"
                    job.finished_at = claimed_at
                return None
            return _ClaimedPivot(
                job_id=job.id,
                provider_kind=provider.kind,
                provider_config=dict(provider.config),
                target_id=candidate.target_id,
                domain=candidate.canonical_domain,
                secret_ciphertext=provider.secret_ciphertext,
            )

    async def collect_certstream(self) -> dict[str, int]:
        with self.database.session() as db:
            provider = db.scalar(select(Provider).where(Provider.kind == "certstream"))
            if provider is None or not provider.enabled:
                return {"messages": 0, "dns_names": 0, "matches": 0}
            seconds = int(provider.config.get("collection_seconds", 240))
        collector = CertStreamCollector(self.settings.certstream_url, self.database.session_factory, self.settings)
        try:
            stats = await collector.collect(seconds=seconds)
        finally:
            self._update_certstream_status()
        return stats

    def _update_certstream_status(self) -> None:
        with self.database.session() as db:
            provider = db.scalar(select(Provider).where(Provider.kind == "certstream"))
            latest_run = db.scalar(
                select(CollectionRun).where(CollectionRun.provider == "certstream").order_by(CollectionRun.id.desc())
            )
            if provider is not None and latest_run is not None:
                provider.last_status = latest_run.state
                provider.last_message = latest_run.error
                provider.last_run_at = latest_run.finished_at

    async def loop(self) -> None:
        while True:
            try:
                await self.collect_certstream()
            except Exception:
                # A temporary WebSocket outage must not stop queued passive
                # pivots. The failed collection run still records health state.
                await asyncio.sleep(15)
            await self.run_once()
            await asyncio.sleep(15)

    async def _pivot(
        self,
        domain: str,
        provider_kind: str,
        provider_config: dict[str, Any],
        secret: str | None,
    ) -> ProviderOutcome:
        if provider_kind == "urlscan":
            limit = int(provider_config.get("result_limit", 50))
            return await URLScanAdapter().search(f"domain:{domain}", secret, limit)
        if provider_kind == "virustotal":
            limit = int(provider_config.get("result_limit", 40))
            return await VirusTotalAdapter().domain_relationships(domain, secret, limit)
        raise ValueError("unsupported pivot provider")

    def _record_job_failure(self, job_id: int, provider_kind: str, error_code: str) -> None:
        with self.database.session() as db:
            job = db.get(PivotJob, job_id)
            provider = db.scalar(select(Provider).where(Provider.kind == provider_kind))
            if job is None:
                return
            job.last_error = error_code
            # Passive adapters own the complete three-request HTTP retry budget.
            # Re-queuing here would multiply that budget and could repeat
            # terminal authentication or response-validation failures.
            job.state = "failed"
            job.finished_at = datetime.now(UTC)
            if provider is not None:
                provider.last_status = "failed"
                provider.last_message = error_code
                provider.last_run_at = datetime.now(UTC)

    def _recover_stale_jobs(self) -> None:
        cutoff = datetime.now(UTC) - timedelta(minutes=15)
        with self.database.session() as db:
            jobs = db.scalars(select(PivotJob).where(PivotJob.state == "running", PivotJob.started_at < cutoff)).all()
            for job in jobs:
                job.last_error = "worker_interrupted"
                # The provider may have accepted a request before interruption.
                # Failing closed avoids duplicate execution; the existing manual
                # queue and 24-hour automatic cooldown provide safe recovery.
                job.state = "failed"
                job.finished_at = datetime.now(UTC)
