"""Synthetic operator workflows. No real provider keys, domains or network calls."""

from __future__ import annotations

import asyncio
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from open_domain_radar.api import create_app
from open_domain_radar.config import Settings
from open_domain_radar.db import restore_sqlite_backup, sqlite_backup
from open_domain_radar.models import Admin, Candidate, Observation, PivotJob, Provider
from open_domain_radar.providers.base import ProviderOutcome
from open_domain_radar.security import SecretBox, hash_password
from open_domain_radar.services import ingest_observable, queue_configured_pivots, set_provider_secret
from open_domain_radar.worker import RadarWorker


class OperatorWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.password = "synthetic-runtime-test-only"  # noqa: S105
        cls.password_hash = hash_password(cls.password)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="odr-runtime-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.settings = Settings(
            data_dir=self.root,
            database_url=f"sqlite:///{self.root / 'test.db'}",
            master_key=None,
            host="127.0.0.1",
            port=8787,
            public_origin="http://127.0.0.1:8787",
            embed_worker=False,
            session_hours=1,
            certstream_url="wss://certstream.calidog.io/",
        )
        self.app = create_app(self.settings)
        self.database = self.app.state.database
        self.addCleanup(self.database.engine.dispose)
        self.client = TestClient(self.app, base_url=self.settings.public_origin)
        self.addCleanup(self.client.close)
        SecretBox.load(self.settings, create=True)
        with self.database.session() as db:
            db.add(Admin(username="testoperator", password_hash=self.password_hash))

    def login(self) -> dict[str, str]:
        result = self.client.post("/api/admin/v1/login", json={"username": "testoperator", "password": self.password})
        self.assertEqual(result.status_code, 200, result.text)
        return {"X-CSRF-Token": self.client.cookies["odr_csrf"]}

    def seed(self) -> tuple[int, dict[str, str]]:
        headers = self.login()
        response = self.client.post(
            "/api/admin/v1/targets",
            headers=headers,
            json={"name": "Fixturebrand", "official_domains": ["fixturebrand.invalid"]},
        )
        self.assertEqual(response.status_code, 201, response.text)
        with self.database.session() as db:
            candidate = ingest_observable(
                db,
                "https://fixturebrand-login.invalid/path?token=must-not-publish#private",
                provider="certstream",
                observed_at=datetime(2026, 1, 1, tzinfo=UTC),
                payload={"private_fixture": "private-observation-only"},
            )
            self.assertIsNotNone(candidate)
            candidate_id = candidate.id
        return candidate_id, headers

    def queue_synthetic_pivot(self) -> int:
        candidate_id, _headers = self.seed()
        with self.database.session() as db:
            candidate = db.get(Candidate, candidate_id)
            provider = db.scalar(select(Provider).where(Provider.kind == "urlscan"))
            provider.enabled = True
            set_provider_secret(db, provider, "synthetic-worker-secret", SecretBox.load(self.settings))
            jobs, _ = queue_configured_pivots(db, candidate, self.settings, trigger="synthetic-worker-test")
            self.assertEqual(len(jobs), 1)
            return jobs[0].id

    def test_initialization_is_idempotent_and_public_surface_is_read_only(self) -> None:
        self.database.initialize()
        for route in ("/health/live", "/health/ready", "/api/public/v1/signals", "/api/public/v1/stats"):
            self.assertEqual(self.client.get(route).status_code, 200)
        self.assertEqual(self.client.get("/api/admin/v1/targets").status_code, 401)
        self.assertEqual(self.client.post("/api/public/v1/signals", json={}).status_code, 405)
        self.assertEqual(self.client.get("/api/public/v1/signals").json()["total"], 0)

    def test_authentication_csrf_origin_and_logout(self) -> None:
        login_data = {"username": "testoperator", "password": self.password}
        self.assertEqual(
            self.client.post(
                "/api/admin/v1/login", json=login_data, headers={"Origin": "https://other.invalid"}
            ).status_code,
            403,
        )
        login_data["password"] = "deliberately-incorrect-password"  # noqa: S105
        self.assertEqual(self.client.post("/api/admin/v1/login", json=login_data).status_code, 401)
        headers = self.login()
        self.assertTrue(self.client.get("/api/admin/v1/session").json()["authenticated"])
        payload = {"name": "Fixturebrand"}
        self.assertEqual(self.client.post("/api/admin/v1/targets", json=payload).status_code, 403)
        self.assertEqual(
            self.client.post("/api/admin/v1/targets", json=payload, headers={"X-CSRF-Token": "incorrect"}).status_code,
            403,
        )
        self.assertEqual(self.client.post("/api/admin/v1/logout", headers=headers).status_code, 204)
        self.assertEqual(self.client.get("/api/admin/v1/targets").status_code, 401)

    def test_secret_encryption_and_response_redaction(self) -> None:
        headers = self.login()
        secret = "synthetic-provider-secret-never-valid"  # noqa: S105
        response = self.client.put(
            "/api/admin/v1/providers/urlscan", headers=headers, json={"enabled": True, "api_key": secret}
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn(secret, response.text)
        self.assertNotIn(secret, self.client.get("/api/admin/v1/providers").text)
        with self.database.session() as db:
            provider = db.scalar(select(Provider).where(Provider.kind == "urlscan"))
            self.assertTrue(provider.secret_ciphertext)
            self.assertNotIn(secret, provider.secret_ciphertext)
        for route in ("/api/public/v1/signals", "/api/public/v1/stats", "/api/public/v1/health"):
            response = self.client.get(route)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertNotIn(secret, response.text)

    def test_worker_ingestion_and_optional_pivots_are_idempotent(self) -> None:
        candidate_id, _headers = self.seed()
        with self.database.session() as db:
            candidate = ingest_observable(
                db,
                "fixturebrand-login.invalid",
                provider="certstream",
                observed_at=datetime(2026, 1, 1, tzinfo=UTC),
                payload={"private_fixture": "private-observation-only"},
            )
            self.assertEqual(candidate.id, candidate_id)
            self.assertEqual(db.scalar(select(func.count()).select_from(Candidate)), 1)
            self.assertEqual(db.scalar(select(func.count()).select_from(Observation)), 1)
            queued, _ = queue_configured_pivots(db, candidate, self.settings, trigger="test")
            self.assertEqual(queued, [])
            provider = db.scalar(select(Provider).where(Provider.kind == "urlscan"))
            provider.enabled = True
            set_provider_secret(db, provider, "synthetic-queue-secret", SecretBox.load(self.settings))
            queued, _ = queue_configured_pivots(db, candidate, self.settings, trigger="test")
            self.assertEqual(len(queued), 1)
            repeated, _ = queue_configured_pivots(db, candidate, self.settings, trigger="test")
            self.assertEqual(repeated, [])
            self.assertIsNone(ingest_observable(db, "fixturebrand.invalid", provider="certstream"))
        public = self.client.get("/api/public/v1/signals")
        self.assertEqual(public.json()["total"], 1)
        for private_value in ("must-not-publish", "private-observation-only", "password_hash", "token_hash"):
            self.assertNotIn(private_value, public.text)

    def test_review_suppression_and_restore_are_auditable(self) -> None:
        candidate_id, headers = self.seed()
        route = f"/api/admin/v1/candidates/{candidate_id}"
        published = self.client.post(
            f"{route}/review",
            headers=headers,
            json={"decision": "publish", "note": "Synthetic positive review"},
        )
        self.assertEqual(published.status_code, 200, published.text)
        self.assertEqual(self.client.get("/api/public/v1/stats").json()["reviewed_published"], 1)
        response = self.client.post(
            f"{route}/review",
            headers=headers,
            json={"decision": "false_positive", "note": "Synthetic review note stays private", "suppress": True},
        )
        self.assertEqual(response.status_code, 200, response.text)
        public = self.client.get("/api/public/v1/signals")
        self.assertEqual(public.json()["total"], 0)
        self.assertNotIn("Synthetic review", public.text)
        with self.database.session() as db:
            self.assertIsNone(ingest_observable(db, "fixturebrand-login.invalid", provider="certstream"))
        response = self.client.post(f"{route}/restore", headers=headers, json={"reason": "Synthetic restore check"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.client.get("/api/public/v1/signals").json()["total"], 1)
        self.assertEqual(len(self.client.get(route).json()["review_events"]), 3)

    def test_worker_executes_a_queued_job_once_without_repeating_provider_work(self) -> None:
        job_id = self.queue_synthetic_pivot()
        worker = RadarWorker(self.database, self.settings)
        outcome = ProviderOutcome(
            provider="urlscan",
            status="success",
            items=[{"observable": "fixturebrand-account.invalid"}],
        )
        # Exercise the real claim, provider boundary and storage path. Only the
        # external provider call is replaced, so no network request is possible.
        with patch.object(worker, "_pivot", new_callable=AsyncMock, return_value=outcome) as pivot:
            first = asyncio.run(worker.run_once())
            self.assertEqual(first, {"processed": 1, "success": 1, "skipped": 0, "failed": 0, "discovered": 1})
            second = asyncio.run(worker.run_once())
            self.assertEqual(second, {"processed": 0, "success": 0, "skipped": 0, "failed": 0, "discovered": 0})
            pivot.assert_awaited_once()
            self.assertEqual(pivot.await_args.args[0:2], ("fixturebrand-login.invalid", "urlscan"))
        with self.database.session() as db:
            job = db.get(PivotJob, job_id)
            self.assertEqual((job.state, job.attempts), ("success", 1))
            self.assertIsNotNone(job.started_at)
            self.assertIsNotNone(job.finished_at)
            self.assertEqual(db.scalar(select(func.count()).select_from(Candidate)), 2)
            self.assertEqual(db.scalar(select(func.count()).select_from(PivotJob)), 1)

    def test_worker_failure_is_redacted_and_not_automatically_retried(self) -> None:
        job_id = self.queue_synthetic_pivot()
        worker = RadarWorker(self.database, self.settings)
        with patch.object(
            worker, "_pivot", new_callable=AsyncMock, side_effect=ValueError("synthetic-sensitive-provider-detail")
        ) as pivot:
            self.assertEqual(asyncio.run(worker.run_once())["failed"], 1)
            self.assertEqual(asyncio.run(worker.run_once())["processed"], 0)
            pivot.assert_awaited_once()
        with self.database.session() as db:
            job = db.get(PivotJob, job_id)
            provider = db.scalar(select(Provider).where(Provider.kind == "urlscan"))
            self.assertEqual((job.state, job.attempts, job.last_error), ("failed", 1, "provider_response_invalid"))
            self.assertEqual(provider.last_message, "provider_response_invalid")
            self.assertIsNotNone(job.finished_at)

    def test_worker_exclusive_claim_and_interrupted_job_do_not_repeat_provider_work(self) -> None:
        job_id = self.queue_synthetic_pivot()
        first_worker = RadarWorker(self.database, self.settings)
        second_worker = RadarWorker(self.database, self.settings)
        # Reproduce two workers reading the same due ID before either claims it.
        # The actual conditional database update must allow only the first claim.
        self.assertEqual(first_worker._due_job_ids(10), [job_id])
        self.assertEqual(second_worker._due_job_ids(10), [job_id])
        self.assertIsNotNone(first_worker._claim_job(job_id))
        self.assertIsNone(second_worker._claim_job(job_id))
        with self.database.session() as db:
            job = db.get(PivotJob, job_id)
            self.assertEqual((job.state, job.attempts), ("running", 1))
            job.started_at = datetime.now(UTC) - timedelta(minutes=16)
        with patch.object(second_worker, "_pivot", new_callable=AsyncMock) as pivot:
            self.assertEqual(asyncio.run(second_worker.run_once())["processed"], 0)
            self.assertEqual(asyncio.run(second_worker.run_once())["processed"], 0)
            pivot.assert_not_awaited()
        with self.database.session() as db:
            job = db.get(PivotJob, job_id)
            self.assertEqual((job.state, job.attempts, job.last_error), ("failed", 1, "worker_interrupted"))
            self.assertIsNotNone(job.finished_at)

    def test_worker_skips_a_provider_disabled_after_queueing(self) -> None:
        job_id = self.queue_synthetic_pivot()
        with self.database.session() as db:
            provider = db.scalar(select(Provider).where(Provider.kind == "urlscan"))
            provider.enabled = False
        worker = RadarWorker(self.database, self.settings)
        with patch.object(worker, "_pivot", new_callable=AsyncMock) as pivot:
            self.assertEqual(asyncio.run(worker.run_once())["skipped"], 1)
            self.assertEqual(asyncio.run(worker.run_once())["processed"], 0)
            pivot.assert_not_awaited()
        with self.database.session() as db:
            job = db.get(PivotJob, job_id)
            self.assertEqual((job.state, job.attempts), ("skipped", 1))
            self.assertEqual(job.last_error, "candidate_or_provider_unavailable")

    def test_online_backup_restores_and_rejects_overwrite(self) -> None:
        self.seed()
        backup = self.root / "backup.db"
        sqlite_backup(self.database.engine, str(backup))
        destination = self.root / "restored.db"
        restore_sqlite_backup(f"sqlite:///{destination}", backup)
        with closing(sqlite3.connect(destination)) as db:
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone(), ("ok",))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM candidates").fetchone(), (1,))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM admins").fetchone(), (1,))
        with self.assertRaises(FileExistsError):
            restore_sqlite_backup(f"sqlite:///{destination}", backup)


if __name__ == "__main__":
    unittest.main()
