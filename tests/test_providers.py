from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from open_domain_radar.config import Settings
from open_domain_radar.db import Database
from open_domain_radar.models import Candidate, CollectionRun, PivotJob, Provider, WatchTarget
from open_domain_radar.providers.certstream import CertStreamCollector, parse_certstream_message
from open_domain_radar.providers.passive import URLScanAdapter, VirusTotalAdapter
from open_domain_radar.services import ingest_observable
from open_domain_radar.worker import RadarWorker


def test_certstream_parser_deduplicates_and_rejects_bad_names() -> None:
    message = {
        "message_type": "certificate_update",
        "data": {
            "leaf_cert": {
                "all_domains": ["*.Login.Example.test", "login.example.test", "bad name", 42],
            }
        },
    }
    assert parse_certstream_message(message) == ["login.example.test"]
    assert parse_certstream_message("not json") == []
    assert parse_certstream_message({"message_type": "heartbeat"}) == []


@pytest.mark.asyncio
async def test_urlscan_without_key_is_successful_skip_and_makes_no_request() -> None:
    outcome = await URLScanAdapter().search("domain:example.test", None)
    assert outcome.status == "skipped"
    assert outcome.message == "missing_api_key"
    assert outcome.items == []


@pytest.mark.asyncio
async def test_virustotal_without_key_is_successful_skip_and_makes_no_request() -> None:
    outcome = await VirusTotalAdapter().domain_relationships("example.test", None)
    assert outcome.status == "skipped"
    assert outcome.message == "missing_api_key"
    assert outcome.items == []


def test_passive_adapters_have_fixed_https_origins() -> None:
    assert URLScanAdapter.origin == "https://urlscan.io"
    assert VirusTotalAdapter.origin == "https://www.virustotal.com"


def test_worker_skips_missing_optional_key_without_losing_candidate(tmp_path: Path) -> None:
    settings = Settings(
        tmp_path,
        f"sqlite:///{tmp_path / 'radar.db'}",
        None,
        "127.0.0.1",
        8787,
        "http://127.0.0.1:8787",
        False,
        12,
        "wss://certstream.calidog.io/",
    )
    database = Database(settings)
    database.initialize()
    with database.session() as session:
        target = WatchTarget(name="Example", aliases=["example"], keywords=[], official_domains=[])
        session.add(target)
        session.flush()
        candidate = ingest_observable(session, "example-login.test", provider="certstream")
        assert candidate is not None
        urlscan = session.scalar(select(Provider).where(Provider.kind == "urlscan"))
        assert urlscan is not None
        urlscan.enabled = True
        session.add(PivotJob(candidate_id=candidate.id, provider="urlscan"))
        candidate_id = candidate.id
    result = asyncio.run(RadarWorker(database, settings).run_once())
    assert result["skipped"] == 1
    with database.session() as session:
        assert session.get(Candidate, candidate_id) is not None
        assert session.scalar(select(PivotJob.state)) == "skipped"


class FakeCertStream:
    def __init__(self, messages: list[dict[str, Any]]):
        self.messages = iter(messages)

    async def __aenter__(self) -> FakeCertStream:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    def __aiter__(self) -> FakeCertStream:
        return self

    async def __anext__(self) -> str:
        import json

        try:
            return json.dumps(next(self.messages))
        except StopIteration as exc:
            raise StopAsyncIteration from exc


@pytest.mark.asyncio
async def test_certstream_stores_candidate_and_queues_configured_enrichment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(
        tmp_path,
        f"sqlite:///{tmp_path / 'radar.db'}",
        None,
        "127.0.0.1",
        8787,
        "http://127.0.0.1:8787",
        False,
        12,
        "wss://certstream.calidog.io/",
        urlscan_api_key="configured-key",
    )
    database = Database(settings)
    database.initialize()
    with database.session() as session:
        session.add(WatchTarget(name="Example", aliases=["example"], official_domains=[]))
        urlscan = session.scalar(select(Provider).where(Provider.kind == "urlscan"))
        assert urlscan is not None
        urlscan.enabled = True
    message = {
        "message_type": "certificate_update",
        "data": {"leaf_cert": {"all_domains": ["secure-example-login.test"]}},
    }
    monkeypatch.setattr(
        "open_domain_radar.providers.certstream.websockets.connect",
        lambda *_args, **_kwargs: FakeCertStream([message]),
    )
    stats = await CertStreamCollector(settings.certstream_url, database.session_factory, settings).collect(seconds=5)
    assert stats["matches"] == 1
    assert stats["pivots_queued"] == 1
    with database.session() as session:
        assert session.query(Candidate).count() == 1
        assert session.scalar(select(PivotJob.provider)) == "urlscan"
        assert session.scalar(select(CollectionRun.state)) == "success"


@pytest.mark.asyncio
async def test_urlscan_normalizes_existing_report_and_retries_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, request=request)
        return httpx.Response(
            200,
            request=request,
            json={
                "results": [
                    {
                        "page": {
                            "domain": "secure-example.test",
                            "url": "https://secure-example.test/login?token=private#form",
                            "ip": "192.0.2.10",
                            "country": "lt",
                            "status": 200,
                        },
                        "task": {"uuid": "11111111-1111-4111-8111-111111111111", "time": "2026-08-22T12:00:00Z"},
                    }
                ]
            },
        )

    original_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        "open_domain_radar.providers.passive.httpx.AsyncClient",
        lambda **kwargs: original_client(transport=transport, **kwargs),
    )

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr("open_domain_radar.providers.passive.asyncio.sleep", no_sleep)
    outcome = await URLScanAdapter().search("domain:secure-example.test", "api-key", 5)
    assert calls == 2
    assert outcome.status == "success"
    assert outcome.items[0]["observable"] == "secure-example.test"
    assert outcome.items[0]["reference"] == "https://urlscan.io/result/11111111-1111-4111-8111-111111111111/"
    assert "private" not in str(outcome.items)


@pytest.mark.asyncio
async def test_urlscan_transient_http_retry_budget_is_three(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, request=request)

    original_client = httpx.AsyncClient
    monkeypatch.setattr(
        "open_domain_radar.providers.passive.httpx.AsyncClient",
        lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs),
    )

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr("open_domain_radar.providers.passive.asyncio.sleep", no_sleep)
    with pytest.raises(httpx.HTTPStatusError):
        await URLScanAdapter().search("domain:secure-example.test", "api-key", 5)
    assert calls == 3


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "expected_error"),
    [
        (lambda request: httpx.Response(401, request=request), httpx.HTTPStatusError),
        (lambda request: httpx.Response(200, request=request, json=[]), ValueError),
    ],
)
async def test_urlscan_does_not_retry_terminal_provider_errors(
    monkeypatch: pytest.MonkeyPatch,
    response: Any,
    expected_error: type[Exception],
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return response(request)

    original_client = httpx.AsyncClient
    monkeypatch.setattr(
        "open_domain_radar.providers.passive.httpx.AsyncClient",
        lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    with pytest.raises(expected_error):
        await URLScanAdapter().search("domain:secure-example.test", "api-key", 5)
    assert calls == 1


@pytest.mark.asyncio
async def test_worker_does_not_stack_retries_after_adapter_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        tmp_path,
        f"sqlite:///{tmp_path / 'radar.db'}",
        None,
        "127.0.0.1",
        8787,
        "http://127.0.0.1:8787",
        False,
        12,
        "wss://certstream.calidog.io/",
        urlscan_api_key="configured-key",
    )
    database = Database(settings)
    database.initialize()
    with database.session() as session:
        target = WatchTarget(name="Example", aliases=["example"], official_domains=[])
        session.add(target)
        session.flush()
        candidate = ingest_observable(session, "secure-example.test", provider="certstream")
        assert candidate is not None
        provider = session.scalar(select(Provider).where(Provider.kind == "urlscan"))
        assert provider is not None
        provider.enabled = True
        session.add(PivotJob(candidate_id=candidate.id, provider="urlscan"))
    worker = RadarWorker(database, settings)
    calls = 0

    async def fail_pivot(*_args: object, **_kwargs: object) -> Any:
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(worker, "_pivot", fail_pivot)
    result = await worker.run_once()
    assert result["failed"] == 1
    assert (await worker.run_once())["processed"] == 0
    assert calls == 1
    with database.session() as session:
        job = session.scalar(select(PivotJob))
        assert job is not None
        assert job.state == "failed"
        assert job.last_error == "provider_timeout"
        assert job.attempts == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (ValueError("invalid provider response"), "provider_response_invalid"),
        (
            httpx.HTTPStatusError(
                "unauthorized",
                request=httpx.Request("GET", "https://urlscan.io/api/v1/search/"),
                response=httpx.Response(
                    401,
                    request=httpx.Request("GET", "https://urlscan.io/api/v1/search/"),
                ),
            ),
            "provider_auth_failed",
        ),
    ],
)
async def test_worker_treats_auth_and_validation_failures_as_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    expected_code: str,
) -> None:
    settings = Settings(
        tmp_path,
        f"sqlite:///{tmp_path / 'radar.db'}",
        None,
        "127.0.0.1",
        8787,
        "http://127.0.0.1:8787",
        False,
        12,
        "wss://certstream.calidog.io/",
        urlscan_api_key="configured-key",
    )
    database = Database(settings)
    database.initialize()
    with database.session() as session:
        target = WatchTarget(name="Example", aliases=["example"], official_domains=[])
        session.add(target)
        session.flush()
        candidate = ingest_observable(session, "secure-example.test", provider="certstream")
        assert candidate is not None
        provider = session.scalar(select(Provider).where(Provider.kind == "urlscan"))
        assert provider is not None
        provider.enabled = True
        session.add(PivotJob(candidate_id=candidate.id, provider="urlscan"))
    worker = RadarWorker(database, settings)
    calls = 0

    async def fail_pivot(*_args: object, **_kwargs: object) -> Any:
        nonlocal calls
        calls += 1
        raise error

    monkeypatch.setattr(worker, "_pivot", fail_pivot)
    assert (await worker.run_once())["failed"] == 1
    assert (await worker.run_once())["processed"] == 0
    assert calls == 1
    with database.session() as session:
        job = session.scalar(select(PivotJob))
        assert job is not None
        assert job.state == "failed"
        assert job.last_error == expected_code
        assert job.attempts == 1


def test_atomic_claim_allows_only_one_executor(tmp_path: Path) -> None:
    settings = Settings(
        tmp_path,
        f"sqlite:///{tmp_path / 'radar.db'}",
        None,
        "127.0.0.1",
        8787,
        "http://127.0.0.1:8787",
        False,
        12,
        "wss://certstream.calidog.io/",
        urlscan_api_key="configured-key",
    )
    database = Database(settings)
    database.initialize()
    with database.session() as session:
        target = WatchTarget(name="Example", aliases=["example"], official_domains=[])
        session.add(target)
        session.flush()
        candidate = ingest_observable(session, "secure-example.test", provider="certstream")
        assert candidate is not None
        provider = session.scalar(select(Provider).where(Provider.kind == "urlscan"))
        assert provider is not None
        provider.enabled = True
        job = PivotJob(candidate_id=candidate.id, provider="urlscan")
        session.add(job)
        session.flush()
        job_id = job.id

    worker = RadarWorker(database, settings)
    barrier = Barrier(2)

    def claim() -> object:
        barrier.wait(timeout=5)
        return worker._claim_job(job_id)

    with ThreadPoolExecutor(max_workers=2) as executor:
        claims = list(executor.map(lambda _value: claim(), range(2)))

    assert sum(item is not None for item in claims) == 1
    with database.session() as session:
        claimed_job = session.get(PivotJob, job_id)
        assert claimed_job is not None
        assert claimed_job.state == "running"
        assert claimed_job.attempts == 1


def test_worker_recovers_stale_running_job(tmp_path: Path) -> None:
    settings = Settings(
        tmp_path,
        f"sqlite:///{tmp_path / 'radar.db'}",
        None,
        "127.0.0.1",
        8787,
        "http://127.0.0.1:8787",
        False,
        12,
        "wss://certstream.calidog.io/",
    )
    database = Database(settings)
    database.initialize()
    with database.session() as session:
        target = WatchTarget(name="Example", aliases=["example"], official_domains=[])
        session.add(target)
        session.flush()
        candidate = ingest_observable(session, "secure-example.test", provider="certstream")
        assert candidate is not None
        session.add(
            PivotJob(
                candidate_id=candidate.id,
                provider="urlscan",
                state="running",
                attempts=1,
                started_at=datetime.now(UTC) - timedelta(minutes=30),
            )
        )
    RadarWorker(database, settings)._recover_stale_jobs()
    with database.session() as session:
        job = session.scalar(select(PivotJob))
        assert job is not None
        assert job.state == "failed"
        assert job.last_error == "worker_interrupted"
        assert job.finished_at is not None
