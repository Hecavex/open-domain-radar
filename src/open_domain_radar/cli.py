"""Command-line lifecycle and worker entry points."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from datetime import UTC, datetime
from pathlib import Path

import uvicorn
from sqlalchemy import func, select

from .api import create_app
from .config import Settings
from .db import Database, sqlite_backup
from .models import Admin
from .security import hash_password, validate_username, write_master_key
from .worker import RadarWorker


def build_parser() -> argparse.ArgumentParser:
    """Define the intentionally small command-line interface."""
    parser = argparse.ArgumentParser(prog="open-domain-radar")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="serve the API and static UI")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    worker = commands.add_parser("worker", help="run collection and pivot jobs")
    worker.add_argument("--once", action="store_true", help="process one pivot batch and exit")
    worker.add_argument("--certstream", action="store_true", help="include one bounded CertStream collection")
    commands.add_parser("init", help="initialize the database and master key")
    create_admin = commands.add_parser("create-admin", help="create the single operator before remote deployment")
    create_admin.add_argument("--username", default="operator")
    create_admin.add_argument(
        "--password-stdin",
        action="store_true",
        help="read one password line from standard input instead of prompting",
    )
    keygen = commands.add_parser("keygen", help="create the provider-secret master key")
    keygen.add_argument("--force", action="store_true")
    backup = commands.add_parser("backup", help="create a consistent SQLite backup")
    backup.add_argument("destination", nargs="?")
    backup.add_argument("--output", dest="output")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one CLI command and return a process exit code."""
    args = build_parser().parse_args(argv)
    settings = Settings.from_env()
    if args.command == "serve":
        uvicorn.run(
            create_app(settings),
            host=args.host or settings.host,
            port=args.port or settings.port,
            proxy_headers=False,
        )
        return 0
    if args.command == "keygen":
        write_master_key(settings.master_key_path, force=args.force)
        print(settings.master_key_path)
        return 0
    database = Database(settings)
    if args.command == "init":
        return _initialize(database, settings)
    if args.command == "create-admin":
        return _create_admin(database, settings, args.username, args.password_stdin)
    database.initialize()
    if args.command == "worker":
        asyncio.run(_run_worker(database, settings, once=args.once, include_certstream=args.certstream))
        return 0
    if args.command == "backup":
        return _backup_database(database, settings, args.output or args.destination)
    return 2


def _initialize(database: Database, settings: Settings) -> int:
    """Create local state required by both the web process and worker."""
    write_master_key(settings.master_key_path)
    database.initialize()
    print(f"initialized {settings.database_url}")
    return 0


def _create_admin(database: Database, settings: Settings, username_input: str, password_stdin: bool) -> int:
    """Create the only operator account; remote HTTP bootstrap is not allowed."""
    write_master_key(settings.master_key_path)
    database.initialize()
    with database.session() as session:
        admin_count = session.scalar(select(func.count()).select_from(Admin)) or 0
        if admin_count > 0:
            raise SystemExit("an operator already exists")

        password = _read_new_password(password_stdin)
        try:
            username = validate_username(username_input)
            password_hash = hash_password(password)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        session.add(Admin(slot=1, username=username, password_hash=password_hash))

    print(f"created operator {username}")
    return 0


def _read_new_password(password_stdin: bool) -> str:
    """Read a password from a pipe or prompt for it twice on a terminal."""
    if password_stdin:
        return sys.stdin.readline().rstrip("\r\n")

    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("passwords do not match")
    return password


async def _run_worker(database: Database, settings: Settings, *, once: bool, include_certstream: bool) -> None:
    """Run the worker continuously or execute one bounded batch."""
    worker = RadarWorker(database, settings)
    if not once:
        await worker.loop()
        return

    if include_certstream:
        await worker.collect_certstream()
    await worker.run_once()


def _backup_database(database: Database, settings: Settings, requested_destination: str | None) -> int:
    """Write a timestamped backup unless the operator provided a path."""
    if not settings.database_url.startswith("sqlite"):
        raise SystemExit("backup currently supports SQLite databases only")

    default_destination = settings.data_dir / "backups" / f"radar-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.db"
    destination = Path(requested_destination).resolve() if requested_destination else default_destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    sqlite_backup(database.engine, str(destination))
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
