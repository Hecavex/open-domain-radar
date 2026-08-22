"""Small, forward-only schema migration ledger for the SQLite release line.

The project deliberately avoids a separate migration framework while its
schema is small.  Each released schema change gets an immutable, numbered
function in :data:`MIGRATIONS`.  New migrations may inspect the database and
must be safe to apply once; old migration functions must never be edited.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import Connection, Engine, inspect, text

from .models import Base

SCHEMA_LEDGER = "schema_migrations"
REQUIRED_V1_TABLES = {
    "admins",
    "admin_sessions",
    "candidates",
    "collection_runs",
    "observations",
    "pivot_jobs",
    "providers",
    "review_events",
    "suppressions",
    "watch_targets",
}

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


@dataclass(frozen=True, slots=True)
class Migration:
    """One immutable schema transition."""

    version: int
    name: str
    apply: Callable[[Connection], None]


def _create_v1_schema(connection: Connection) -> None:
    """Create the schema shipped by the 0.1 release line."""
    Base.metadata.create_all(connection)
    _install_append_only_triggers(connection)


MIGRATIONS = (Migration(1, "initial_0_1_schema", _create_v1_schema),)
CURRENT_SCHEMA_VERSION = MIGRATIONS[-1].version


def migrate(engine: Engine) -> int:
    """Bring a database forward to the newest schema known by this build.

    A database created by 0.1.0 predates the ledger.  Its exact table set is
    validated and then adopted as version 1 without rewriting evidence.  A
    schema newer than this binary is rejected to prevent accidental downgrade.
    """
    with engine.begin() as connection:
        _create_ledger(connection)
        applied = _applied_versions(connection)
        _validate_version_history(applied)

        if not applied and _has_legacy_tables(connection):
            _adopt_legacy_v1(connection)
            applied = {1}

        for migration in MIGRATIONS:
            if migration.version in applied:
                continue
            migration.apply(connection)
            _record_migration(connection, migration)

        _validate_v1_tables(connection)
        # Safety triggers are idempotent and also repair a manually dropped
        # trigger without pretending that a new schema migration occurred.
        _install_append_only_triggers(connection)
        connection.execute(text(f"PRAGMA user_version={CURRENT_SCHEMA_VERSION}"))
    return CURRENT_SCHEMA_VERSION


def schema_version(connection: Connection) -> int:
    """Return the recorded schema version, or zero for an unversioned file."""
    if SCHEMA_LEDGER not in inspect(connection).get_table_names():
        return 0
    value = connection.execute(text("SELECT MAX(version) FROM schema_migrations")).scalar_one_or_none()
    return int(value or 0)


def validate_restorable_schema(connection: Connection) -> int:
    """Reject a backup that this build cannot safely open."""
    tables = set(inspect(connection).get_table_names())
    if not tables:
        raise ValueError("backup contains no application schema")
    missing = REQUIRED_V1_TABLES - tables
    if missing:
        raise ValueError(f"backup is missing required tables: {', '.join(sorted(missing))}")
    if SCHEMA_LEDGER not in tables:
        return 1

    applied = {
        int(version)
        for version in connection.execute(text("SELECT version FROM schema_migrations ORDER BY version")).scalars()
    }
    if applied and applied != set(range(1, max(applied) + 1)):
        raise ValueError("backup schema migration history contains a gap")
    version = max(applied, default=0)
    if version > CURRENT_SCHEMA_VERSION:
        raise ValueError(f"backup schema version {version} is newer than supported version {CURRENT_SCHEMA_VERSION}")
    if version < 1:
        raise ValueError("backup has an empty or invalid schema migration history")
    return version


def _create_ledger(connection: Connection) -> None:
    connection.execute(
        text(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY, "
            "name TEXT NOT NULL UNIQUE, "
            "applied_at TEXT NOT NULL"
            ")"
        )
    )


def _applied_versions(connection: Connection) -> set[int]:
    rows = connection.execute(text("SELECT version FROM schema_migrations ORDER BY version")).scalars()
    return {int(version) for version in rows}


def _validate_version_history(applied: set[int]) -> None:
    known = {migration.version for migration in MIGRATIONS}
    unknown = sorted(applied - known)
    if unknown:
        raise RuntimeError(
            f"database schema version {unknown[-1]} is newer than this application "
            f"(supports {CURRENT_SCHEMA_VERSION}); upgrade the application"
        )
    if applied and applied != set(range(1, max(applied) + 1)):
        raise RuntimeError("database schema migration history contains a gap")


def _has_legacy_tables(connection: Connection) -> bool:
    tables = set(inspect(connection).get_table_names()) - {SCHEMA_LEDGER}
    return bool(tables)


def _adopt_legacy_v1(connection: Connection) -> None:
    _validate_v1_tables(connection)
    _install_append_only_triggers(connection)
    _record_migration(connection, MIGRATIONS[0], name_suffix="_adopted")


def _validate_v1_tables(connection: Connection) -> None:
    missing = REQUIRED_V1_TABLES - set(inspect(connection).get_table_names())
    if missing:
        raise RuntimeError("database is missing required tables: " + ", ".join(sorted(missing)))


def _record_migration(connection: Connection, migration: Migration, *, name_suffix: str = "") -> None:
    applied_at = datetime.now(UTC).isoformat()
    connection.execute(
        text("INSERT INTO schema_migrations (version, name, applied_at) VALUES (:version, :name, :applied_at)"),
        {"version": migration.version, "name": f"{migration.name}{name_suffix}", "applied_at": applied_at},
    )


def _install_append_only_triggers(connection: Connection) -> None:
    for statement in APPEND_ONLY_TRIGGERS:
        connection.execute(text(statement))
