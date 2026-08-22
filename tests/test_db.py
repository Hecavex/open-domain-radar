from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

from open_domain_radar.config import Settings
from open_domain_radar.db import Database, sqlite_backup
from open_domain_radar.models import Admin, Candidate, Observation, ReviewEvent, WatchTarget
from open_domain_radar.security import hash_password
from open_domain_radar.services import ingest_observable


def settings_for(path: Path) -> Settings:
    return Settings(
        data_dir=path,
        database_url=f"sqlite:///{path / 'radar.db'}",
        master_key=None,
        host="127.0.0.1",
        port=8787,
        public_origin="http://127.0.0.1:8787",
        embed_worker=False,
        session_hours=12,
        certstream_url="wss://certstream.calidog.io/",
    )


def test_schema_enables_wal_and_seeds_providers(tmp_path: Path) -> None:
    database = Database(settings_for(tmp_path))
    database.initialize()
    with database.engine.connect() as connection:
        assert connection.scalar(text("PRAGMA journal_mode")) == "wal"
        assert connection.scalar(text("PRAGMA foreign_keys")) == 1
        providers = connection.execute(text("SELECT kind FROM providers ORDER BY kind")).scalars().all()
    assert providers == ["certstream", "urlscan", "virustotal"]


def test_state_and_sqlite_permissions_are_hardened(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database_path = tmp_path / "radar.db"
    database_path.touch()
    calls: list[tuple[Path, int]] = []
    monkeypatch.setattr(
        "open_domain_radar.db.os.chmod",
        lambda path, mode: calls.append((Path(path), mode)),
    )
    database = Database(settings_for(tmp_path))
    database.initialize()

    assert (tmp_path, 0o700) in calls
    assert (database_path, 0o600) in calls


def test_review_events_are_append_only_at_database_layer(tmp_path: Path) -> None:
    database = Database(settings_for(tmp_path))
    database.initialize()
    with database.session() as session:
        admin = Admin(username="analyst", password_hash=hash_password("correct horse battery staple"))
        target = WatchTarget(name="Example", aliases=["example"], official_domains=["example.com"])
        session.add_all((admin, target))
        session.flush()
        candidate = Candidate(
            canonical_value="example-login.test",
            defanged_value="example-login[.]test",
            canonical_domain="example-login.test",
            target_id=target.id,
        )
        session.add(candidate)
        session.flush()
        event = ReviewEvent(
            candidate_id=candidate.id,
            admin_id=admin.id,
            action="confirm",
            previous_status="potential",
            new_status="confirmed",
            reason="manual evidence review",
        )
        session.add(event)
        session.flush()
        event_id = event.id

    with pytest.raises(DatabaseError, match="append-only"), database.session() as session:
        session.execute(text("UPDATE review_events SET reason='changed' WHERE id=:id"), {"id": event_id})
    with pytest.raises(DatabaseError, match="append-only"), database.session() as session:
        session.execute(text("DELETE FROM review_events WHERE id=:id"), {"id": event_id})


def test_online_backup_contains_committed_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database = Database(settings_for(tmp_path))
    database.initialize()
    with database.session() as session:
        session.add(WatchTarget(name="Example", aliases=["example"], official_domains=[]))
    destination = tmp_path / "backup.db"
    calls: list[tuple[Path, int]] = []
    monkeypatch.setattr(
        "open_domain_radar.db.os.chmod",
        lambda path, mode: calls.append((Path(path), mode)),
    )
    sqlite_backup(database.engine, str(destination))
    import sqlite3

    with sqlite3.connect(destination) as connection:
        assert connection.execute("SELECT COUNT(*) FROM watch_targets").fetchone()[0] == 1
    assert (destination, 0o600) in calls


def test_observations_are_append_only_and_distinct_by_source_time(tmp_path: Path) -> None:
    from datetime import UTC, datetime, timedelta

    database = Database(settings_for(tmp_path))
    database.initialize()
    first = datetime(2026, 8, 22, 10, 0, tzinfo=UTC)
    with database.session() as session:
        session.add(WatchTarget(name="Example", aliases=["example"], official_domains=[]))
        session.flush()
        assert ingest_observable(session, "example-login.test", provider="certstream", observed_at=first)
        assert ingest_observable(
            session,
            "example-login.test",
            provider="certstream",
            observed_at=first + timedelta(minutes=5),
        )
    with database.session() as session:
        observations = session.query(Observation).order_by(Observation.observed_at).all()
        assert len(observations) == 2
        observation_id = observations[0].id
    with pytest.raises(DatabaseError, match="append-only"), database.session() as session:
        session.execute(
            text("UPDATE observations SET provider='changed' WHERE id=:id"),
            {"id": observation_id},
        )
    with pytest.raises(DatabaseError, match="append-only"), database.session() as session:
        session.execute(text("DELETE FROM observations WHERE id=:id"), {"id": observation_id})


def test_non_sqlite_database_url_is_rejected_explicitly(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    unsupported = Settings(
        settings.data_dir,
        "postgresql://localhost/radar",
        settings.master_key,
        settings.host,
        settings.port,
        settings.public_origin,
        settings.embed_worker,
        settings.session_hours,
        settings.certstream_url,
    )
    with pytest.raises(ValueError, match="only SQLite"):
        Database(unsupported)
