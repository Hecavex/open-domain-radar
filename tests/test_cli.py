from __future__ import annotations

import io
from pathlib import Path

import pytest
from sqlalchemy import select

from open_domain_radar.cli import main
from open_domain_radar.config import Settings
from open_domain_radar.db import Database
from open_domain_radar.models import Admin


def configure_environment(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv("ODR_DATA_DIR", str(path))
    monkeypatch.setenv("ODR_PUBLIC_ORIGIN", "http://127.0.0.1:8787")
    monkeypatch.delenv("ODR_DATABASE_URL", raising=False)
    monkeypatch.delenv("ODR_MASTER_KEY", raising=False)
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)


def test_cli_initializes_bootstraps_runs_once_and_backs_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    configure_environment(monkeypatch, tmp_path)
    assert main(["init"]) == 0
    monkeypatch.setattr("sys.stdin", io.StringIO("correct horse battery staple\n"))
    assert main(["create-admin", "--username", "operator", "--password-stdin"]) == 0
    assert main(["worker", "--once"]) == 0
    backup = tmp_path / "backup.sqlite3"
    assert main(["backup", "--output", str(backup)]) == 0
    assert backup.is_file()
    settings = Settings.from_env()
    with Database(settings).session() as session:
        assert session.scalar(select(Admin.username)) == "operator"


def test_cli_rejects_invalid_operator_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    configure_environment(monkeypatch, tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO("correct horse battery staple\n"))
    with pytest.raises(SystemExit, match="username"):
        main(["create-admin", "--username", "invalid user", "--password-stdin"])
