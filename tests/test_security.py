from __future__ import annotations

from pathlib import Path

import pytest

from open_domain_radar.config import Settings
from open_domain_radar.db import Database
from open_domain_radar.models import Admin, AdminSession
from open_domain_radar.security import (
    LoginThrottle,
    SecretBox,
    authenticate_session,
    create_session,
    defang,
    hash_password,
    normalize_observable,
    validate_csrf,
    validate_username,
    verify_password,
    write_master_key,
)


def settings_for(path: Path, *, certstream_url: str = "wss://certstream.calidog.io/") -> Settings:
    return Settings(
        path,
        f"sqlite:///{path / 'radar.db'}",
        None,
        "127.0.0.1",
        8787,
        "http://127.0.0.1:8787",
        False,
        12,
        certstream_url,
    )


def test_argon2_password_hash_and_verification() -> None:
    encoded = hash_password("correct horse battery staple")
    assert encoded.startswith("$argon2")
    assert verify_password(encoded, "correct horse battery staple")
    assert not verify_password(encoded, "wrong password")


def test_master_key_file_encrypts_without_plaintext(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    write_master_key(settings.master_key_path)
    box = SecretBox.load(settings)
    encrypted = box.encrypt("top-secret-api-key")
    assert "top-secret-api-key" not in encrypted
    assert box.decrypt(encrypted) == "top-secret-api-key"


def test_existing_master_key_permissions_are_rehardened(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = settings_for(tmp_path)
    key = write_master_key(settings.master_key_path)
    calls: list[tuple[Path, int]] = []
    monkeypatch.setattr(
        "open_domain_radar.security.os.chmod",
        lambda path, mode: calls.append((Path(path), mode)),
    )

    assert write_master_key(settings.master_key_path) == key
    assert (settings.master_key_path.parent, 0o700) in calls
    assert (settings.master_key_path, 0o600) in calls

    calls.clear()
    SecretBox.load(settings)
    assert (settings.master_key_path.parent, 0o700) in calls
    assert (settings.master_key_path, 0o600) in calls


def test_session_tokens_are_only_stored_as_hashes(tmp_path: Path) -> None:
    database = Database(settings_for(tmp_path))
    database.initialize()
    with database.session() as session:
        admin = Admin(username="analyst", password_hash=hash_password("correct horse battery staple"))
        session.add(admin)
        session.flush()
        tokens = create_session(session, admin, 12)
        stored = session.query(AdminSession).one()
        assert tokens.session_token not in stored.token_hash
        assert tokens.csrf_token not in stored.csrf_hash
        assert validate_csrf(stored, tokens.csrf_token, tokens.csrf_token)
        assert not validate_csrf(stored, "wrong", tokens.csrf_token)
        assert authenticate_session(session, tokens.session_token) is not None


def test_observables_are_normalized_and_defanged() -> None:
    canonical, kind, host = normalize_observable(
        "HTTPS://Login.Example.TEST/path?email=user@example.test&token=private#fragment"
    )
    assert canonical == "login.example.test"
    assert kind == "domain"
    assert host == "login.example.test"
    rendered = defang(canonical)
    assert rendered == "login[.]example[.]test"
    assert "https://" not in rendered


def test_remote_public_origin_requires_https_and_bare_origin(tmp_path: Path) -> None:
    values = (
        "http://radar.example",
        "https://user:pass@radar.example",
        "https://radar.example/path",
        "https://radar.example?debug=true",
    )
    for origin in values:
        with pytest.raises(ValueError, match="ODR_PUBLIC_ORIGIN"):
            Settings(
                tmp_path,
                f"sqlite:///{tmp_path / 'radar.db'}",
                None,
                "127.0.0.1",
                8787,
                origin,
                False,
                12,
                "wss://certstream.calidog.io/",
            )


@pytest.mark.parametrize(
    "value",
    (
        "ws://certstream.calidog.io/",
        "wss://operator@certstream.calidog.io/",
        "wss://certstream.calidog.io:444/",
        "wss://certstream.calidog.io/feed",
        "wss://certstream.calidog.io/?token=secret",
        "wss://certstream.calidog.io/?",
        "wss://certstream.calidog.io/#fragment",
        "wss://certstream.calidog.io",
        "wss://certstream.calidog.io.evil.example/",
        "wss://[certstream.calidog.io/",
    ),
)
def test_certstream_url_is_restricted_to_approved_endpoint(tmp_path: Path, value: str) -> None:
    with pytest.raises(ValueError, match="ODR_CERTSTREAM_URL"):
        settings_for(tmp_path, certstream_url=value)


def test_certstream_url_accepts_explicit_standard_tls_port(tmp_path: Path) -> None:
    settings = settings_for(tmp_path, certstream_url="wss://certstream.calidog.io:443/")
    assert settings.certstream_url == "wss://certstream.calidog.io:443/"


def test_login_throttle_is_bounded_and_evicts_stale_peers(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [1_000.0]
    monkeypatch.setattr("open_domain_radar.security.time.monotonic", lambda: clock[0])
    throttle = LoginThrottle(attempts=3, window_seconds=10, lock_seconds=20, max_entries=2)

    throttle.record_failure("peer-a")
    clock[0] += 1
    throttle.record_failure("peer-b")
    clock[0] += 1
    throttle.record_failure("peer-c")

    assert throttle.tracked_entries == 2
    assert throttle.retry_after("peer-a") == 0

    clock[0] += 11
    assert throttle.retry_after("unseen-peer") == 0
    assert throttle.tracked_entries == 0


def test_login_throttle_releases_expired_locks_globally(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [2_000.0]
    monkeypatch.setattr("open_domain_radar.security.time.monotonic", lambda: clock[0])
    throttle = LoginThrottle(attempts=2, window_seconds=10, lock_seconds=20, max_entries=4)

    throttle.record_failure("peer-a")
    throttle.record_failure("peer-a")
    assert throttle.retry_after("peer-a") == 20
    clock[0] += 20
    assert throttle.retry_after("another-peer") == 0
    assert throttle.tracked_entries == 0


def test_username_validation_matches_browser_contract() -> None:
    assert validate_username(" operator.name ") == "operator.name"
    with pytest.raises(ValueError, match="username"):
        validate_username("invalid user")
