"""SQLite engine setup, schema initialization and transaction helpers."""

from __future__ import annotations

import contextlib
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

from sqlalchemy import Connection, Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from .config import Settings
from .models import Base, Provider

APPEND_ONLY_TRIGGERS = (
    "CREATE TRIGGER IF NOT EXISTS review_events_no_update "
    "BEFORE UPDATE ON review_events BEGIN "
    "SELECT RAISE(ABORT, 'review events are append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS review_events_no_delete "
    "BEFORE DELETE ON review_events BEGIN "
    "SELECT RAISE(ABORT, 'review events are append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS observations_no_update "
    "BEFORE UPDATE ON observations BEGIN "
    "SELECT RAISE(ABORT, 'observations are append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS observations_no_delete "
    "BEFORE DELETE ON observations BEGIN "
    "SELECT RAISE(ABORT, 'observations are append-only'); END",
)


class Database:
    """Own the SQLite engine and provide transaction-scoped sessions."""

    def __init__(self, settings: Settings):
        self.settings = settings
        if not settings.database_url.startswith("sqlite"):
            raise ValueError("only SQLite database URLs are supported in this release")
        settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        _set_private_permissions(settings.data_dir, 0o700)
        connect_args = {"check_same_thread": False, "timeout": 15}
        self.engine = create_engine(settings.database_url, connect_args=connect_args, future=True)
        self._harden_sqlite_files()
        event.listen(self.engine, "connect", _configure_sqlite)
        self.session_factory = sessionmaker(self.engine, expire_on_commit=False, class_=Session)

    def initialize(self) -> None:
        """Create the schema, safety triggers and default provider records."""
        Base.metadata.create_all(self.engine)
        with self.engine.begin() as connection:
            _install_append_only_triggers(connection)
        self._seed_providers()
        self._harden_sqlite_files()

    def _seed_providers(self) -> None:
        with self.session() as session:
            existing = {row.kind for row in session.query(Provider).all()}
            for kind, enabled in (("certstream", True), ("urlscan", False), ("virustotal", False)):
                if kind not in existing:
                    session.add(Provider(kind=kind, enabled=enabled, config={}))

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Yield one session and commit it only when the caller succeeds."""
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
            self._harden_sqlite_files()

    def _harden_sqlite_files(self) -> None:
        database = self.engine.url.database
        if not database or database == ":memory:" or database.startswith("file:"):
            return
        database_path = Path(database).expanduser().resolve()
        for path in (database_path, Path(f"{database_path}-wal"), Path(f"{database_path}-shm")):
            if path.exists():
                _set_private_permissions(path, 0o600)


def _configure_sqlite(dbapi_connection: object, _connection_record: object) -> None:
    """Apply required SQLite settings to every pooled connection."""
    # SQLAlchemy's event callback is typed as object, but SQLite supplies a
    # standard DB-API connection with cursor().
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=15000")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


def _install_append_only_triggers(connection: Connection) -> None:
    """Protect evidence and analyst history from UPDATE and DELETE statements."""
    for statement in APPEND_ONLY_TRIGGERS:
        connection.execute(text(statement))


def sqlite_backup(engine: Engine, destination: str) -> None:
    """Create a consistent online backup, including data still held in WAL."""
    source = engine.raw_connection()
    try:
        target = sqlite3.connect(destination)
        try:
            # Apply restrictive permissions before copying and again after close.
            # The second call also covers platforms that replace file metadata.
            _set_private_permissions(Path(destination), 0o600)
            driver_connection = cast(sqlite3.Connection, source.driver_connection)
            driver_connection.backup(target)
        finally:
            target.close()
            _set_private_permissions(Path(destination), 0o600)
    finally:
        source.close()


def _set_private_permissions(path: Path, mode: int) -> None:
    """Tighten local state permissions on platforms that implement POSIX modes."""
    with contextlib.suppress(OSError, NotImplementedError):
        os.chmod(path, mode)
