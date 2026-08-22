"""SQLite engine setup, schema initialization and transaction helpers."""

from __future__ import annotations

import contextlib
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from .config import Settings
from .migrations import migrate, validate_restorable_schema
from .models import Provider


@dataclass(frozen=True, slots=True)
class RestoreResult:
    """Paths and schema information produced by a successful restore."""

    destination: Path
    schema_version: int
    rollback_backup: Path | None


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
        """Apply forward-only migrations and seed default provider records."""
        migrate(self.engine)
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


def restore_sqlite_backup(
    database_url: str,
    source_path: Path,
    *,
    force: bool = False,
) -> RestoreResult:
    """Validate and atomically restore a SQLite backup while the app is stopped.

    Replacing an existing database requires ``force`` and first creates a
    timestamped rollback copy.  SQLite's backup API is used for both copies so
    WAL content is included and the destination is never partially written.
    """
    destination = _database_path(database_url)
    source = source_path.expanduser().resolve()
    if not source.is_file():
        raise ValueError(f"backup does not exist: {source}")
    if source == destination:
        raise ValueError("backup source and database destination must differ")
    if destination.exists() and not force:
        raise FileExistsError("database already exists; stop the service and pass --force to replace it")

    schema = _validate_backup_file(source)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    rollback: Path | None = None
    if destination.exists():
        _require_stopped_database(destination)
        rollback = destination.with_name(
            f"{destination.stem}.before-restore-{datetime.now(UTC):%Y%m%dT%H%M%SZ}{destination.suffix}"
        )
        _copy_sqlite_file(destination, rollback)

    temporary = destination.with_name(f".{destination.name}.restore-{uuid4().hex}.tmp")
    try:
        _copy_sqlite_file(source, temporary)
        _validate_backup_file(temporary)
        try:
            os.replace(temporary, destination)
        except PermissionError as exc:
            raise ValueError("database is in use; stop the web and worker before restoring") from exc
        _set_private_permissions(destination, 0o600)
    finally:
        with contextlib.suppress(FileNotFoundError, PermissionError):
            temporary.unlink()
    return RestoreResult(destination, schema, rollback)


def _database_path(database_url: str) -> Path:
    url = make_url(database_url)
    if url.drivername != "sqlite" or not url.database or url.database == ":memory:" or url.database.startswith("file:"):
        raise ValueError("restore supports only file-backed SQLite databases")
    return Path(url.database).expanduser().resolve()


def _require_stopped_database(path: Path) -> None:
    """Checkpoint the live file and reject evidence of another open process."""
    try:
        with contextlib.closing(sqlite3.connect(path, timeout=1)) as connection:
            result = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if result and int(result[0]) != 0:
                raise ValueError("database is busy; stop the web and worker before restoring")
    except sqlite3.DatabaseError as exc:
        raise ValueError("existing database could not be checkpointed safely") from exc

    sidecars = [sidecar for sidecar in (Path(f"{path}-wal"), Path(f"{path}-shm")) if sidecar.exists()]
    if sidecars:
        raise ValueError("database still appears to be in use; stop the web and worker before restoring")


def _validate_backup_file(path: Path) -> int:
    uri = f"{path.as_uri()}?mode=ro"
    try:
        with contextlib.closing(sqlite3.connect(uri, uri=True)) as connection:
            result = connection.execute("PRAGMA quick_check").fetchone()
            if result != ("ok",):
                raise ValueError(f"SQLite integrity check failed: {result!r}")
            engine = create_engine(f"sqlite:///{path}", future=True)
            try:
                with engine.connect() as sqlalchemy_connection:
                    return validate_restorable_schema(sqlalchemy_connection)
            finally:
                engine.dispose()
    except sqlite3.DatabaseError as exc:
        raise ValueError("backup is not a valid SQLite database") from exc


def _copy_sqlite_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with (
        contextlib.closing(sqlite3.connect(source)) as source_connection,
        contextlib.closing(sqlite3.connect(destination)) as destination_connection,
    ):
        source_connection.backup(destination_connection)
    _set_private_permissions(destination, 0o600)


def _set_private_permissions(path: Path, mode: int) -> None:
    """Tighten local state permissions on platforms that implement POSIX modes."""
    with contextlib.suppress(OSError, NotImplementedError):
        os.chmod(path, mode)
