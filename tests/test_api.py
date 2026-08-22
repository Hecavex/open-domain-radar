from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from open_domain_radar.api import CSRF_COOKIE, create_app
from open_domain_radar.config import Settings
from open_domain_radar.models import Admin
from open_domain_radar.providers.base import ProviderOutcome
from open_domain_radar.security import hash_password
from open_domain_radar.services import ingest_observable


def settings_for(path: Path) -> Settings:
    return Settings(
        path,
        f"sqlite:///{path / 'radar.db'}",
        None,
        "127.0.0.1",
        8787,
        "http://127.0.0.1:8787",
        False,
        12,
        "wss://certstream.calidog.io/",
    )


def csrf_headers(client: TestClient) -> dict[str, str]:
    token = client.cookies.get(CSRF_COOKIE)
    assert token
    return {"X-CSRF-Token": token}


def authenticated_client(settings: Settings) -> tuple[TestClient, object]:
    app = create_app(settings)
    with app.state.database.session() as session:
        session.add(Admin(slot=1, username="analyst", password_hash=hash_password("correct horse battery staple")))
    client = TestClient(app)
    response = client.post(
        "/api/admin/v1/login",
        json={"username": "analyst", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    return client, app


def setup_client(tmp_path: Path) -> tuple[TestClient, object]:
    return authenticated_client(settings_for(tmp_path))


def test_first_run_authentication_and_csrf(tmp_path: Path) -> None:
    client, _app = setup_client(tmp_path)
    assert client.get("/api/admin/v1/session").json()["authenticated"] is True
    blocked = client.post(
        "/api/admin/v1/targets",
        json={"name": "Example", "aliases": ["example"], "official_domains": ["example.com"]},
    )
    assert blocked.status_code == 403
    created = client.post(
        "/api/admin/v1/targets",
        headers=csrf_headers(client),
        json={"name": "Example", "aliases": ["example"], "official_domains": ["example.com"]},
    )
    assert created.status_code == 201
    assert created.json()["official_domains"] == ["example.com"]
    assert (
        client.post(
            "/api/admin/v1/setup", json={"username": "second", "password": "another secure password"}
        ).status_code
        == 404
    )


def test_public_api_returns_only_defanged_observables(tmp_path: Path) -> None:
    client, app = setup_client(tmp_path)
    target = client.post(
        "/api/admin/v1/targets",
        headers=csrf_headers(client),
        json={"name": "Example", "aliases": ["example"], "official_domains": ["example.com"]},
    )
    assert target.status_code == 201
    with app.state.database.session() as session:
        candidate = ingest_observable(session, "https://example-login.test/verify", provider="certstream")
        assert candidate is not None
    response = client.get("/api/public/v1/signals")
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["observable"] == "example-login[.]test"
    assert "canonical_value" not in item
    assert "https://" not in response.text
    assert client.get("/api/public/v1/stats").json()["signals"] == 1
    assert client.get("/api/public/v1/health").json()["database"] == "available"


def test_provider_secret_is_write_only_and_optional(tmp_path: Path) -> None:
    client, app = setup_client(tmp_path)
    from open_domain_radar.security import write_master_key

    write_master_key(app.state.settings.master_key_path)
    response = client.put(
        "/api/admin/v1/providers/urlscan",
        headers=csrf_headers(client),
        json={"enabled": True, "config": {"result_limit": 25}, "api_key": "secret-value"},
    )
    assert response.status_code == 200
    assert response.json()["credential_configured"] is True
    assert "secret-value" not in response.text
    listing = client.get("/api/admin/v1/providers")
    assert "secret-value" not in listing.text
    assert "api_key" not in listing.text


def test_review_restore_pivot_and_suppression_workflow(tmp_path: Path) -> None:
    client, app = setup_client(tmp_path)
    client.post(
        "/api/admin/v1/targets",
        headers=csrf_headers(client),
        json={"name": "Example", "aliases": ["example"], "official_domains": []},
    )
    with app.state.database.session() as session:
        candidate = ingest_observable(session, "example-login.test", provider="certstream")
        assert candidate is not None
        candidate_id = candidate.id
    review = client.post(
        f"/api/admin/v1/candidates/{candidate_id}/review",
        headers=csrf_headers(client),
        json={"action": "false_positive", "reason": "known controlled test", "suppress": True},
    )
    assert review.status_code == 200
    assert review.json()["new_status"] == "false_positive"
    assert len(client.get("/api/admin/v1/suppressions").json()) == 1
    restore = client.post(
        f"/api/admin/v1/candidates/{candidate_id}/restore",
        headers=csrf_headers(client),
        json={"reason": "suppression was too broad"},
    )
    assert restore.status_code == 200
    pivot = client.post(
        "/api/admin/v1/pivots",
        headers=csrf_headers(client),
        json={"candidate_id": candidate_id, "provider": "urlscan"},
    )
    assert pivot.status_code == 200
    assert pivot.json()["outcome"] == "no_provider_job"
    assert pivot.json()["queued"] == []
    assert pivot.json()["skipped_providers"] == ["urlscan"]


def test_auth_origin_is_restricted(tmp_path: Path) -> None:
    app = create_app(settings_for(tmp_path))
    with app.state.database.session() as session:
        session.add(Admin(slot=1, username="analyst", password_hash=hash_password("correct horse battery staple")))
    with TestClient(app) as client:
        response = client.post(
            "/api/admin/v1/login",
            headers={"Origin": "https://attacker.invalid"},
            json={"username": "analyst", "password": "correct horse battery staple"},
        )
    assert response.status_code == 403


def test_first_run_session_and_packaged_pages(tmp_path: Path) -> None:
    app = create_app(settings_for(tmp_path))
    with TestClient(app) as client:
        session = client.get("/api/admin/v1/session")
        assert session.status_code == 200
        assert session.json() == {"authenticated": False, "setup_required": True, "setup_allowed": False}
        assert client.get("/").status_code == 200
        assert client.get("/admin").status_code == 200
        assert client.get("/static/styles.css").status_code == 200
        setup = client.post(
            "/api/admin/v1/setup",
            json={"username": "analyst", "password": "correct horse battery staple"},
        )
        assert setup.status_code == 404


def test_public_query_contract_and_target_update_alias(tmp_path: Path) -> None:
    client, app = setup_client(tmp_path)
    created = client.post(
        "/api/admin/v1/targets",
        headers=csrf_headers(client),
        json={"name": "Example", "aliases": ["example"], "official_domains": ["example.com"]},
    ).json()
    updated = client.put(
        f"/api/admin/v1/targets/{created['id']}",
        headers=csrf_headers(client),
        json={"keywords": ["webmail", "identity"]},
    )
    assert updated.status_code == 200
    assert updated.json()["keywords"] == ["identity", "webmail"]
    with app.state.database.session() as session:
        assert ingest_observable(session, "example-login.test", provider="certstream") is not None
    response = client.get(
        "/api/public/v1/signals",
        params={
            "query": "example-login",
            "status": "potential",
            "source": "certstream",
            "target": "Example",
            "page": 1,
            "page_size": 10,
        },
    )
    payload = response.json()
    assert response.status_code == 200
    assert {"page", "pageSize", "total", "pages"} <= payload.keys()
    assert payload["pageSize"] == 10
    assert payload["total"] == 1


def test_public_facets_do_not_disclose_targets_without_visible_signals(tmp_path: Path) -> None:
    client, app = setup_client(tmp_path)
    client.post(
        "/api/admin/v1/targets",
        headers=csrf_headers(client),
        json={"name": "Visible Example", "aliases": ["visible-example"], "official_domains": []},
    )
    client.post(
        "/api/admin/v1/targets",
        headers=csrf_headers(client),
        json={"name": "Private Watch", "aliases": ["private-watch"], "official_domains": []},
    )
    with app.state.database.session() as session:
        assert ingest_observable(session, "visible-example-login.test", provider="certstream") is not None
    stats = client.get("/api/public/v1/stats").json()
    assert stats["targets"] == 1
    assert stats["targets_list"] == ["Visible Example"]


def test_admin_candidate_queue_defaults_to_open_and_reports_real_pagination(tmp_path: Path) -> None:
    client, app = setup_client(tmp_path)
    client.post(
        "/api/admin/v1/targets",
        headers=csrf_headers(client),
        json={"name": "Example", "aliases": ["example"], "official_domains": []},
    )
    with app.state.database.session() as session:
        first = ingest_observable(session, "example-login-one.test", provider="certstream")
        second = ingest_observable(session, "example-login-two.test", provider="certstream")
        assert first is not None and second is not None
        second.status = "closed"
    default = client.get("/api/admin/v1/candidates", params={"limit": 1}).json()
    assert default["total"] == 1
    assert default["open_count"] == 1
    assert default["pages"] == 1
    assert default["items"][0]["status"] == "potential"
    closed = client.get("/api/admin/v1/candidates", params={"status": "closed", "limit": 1}).json()
    assert closed["total"] == 1
    assert closed["open_count"] == 1


def test_ui_review_contract_deactivates_linked_suppression(tmp_path: Path) -> None:
    client, app = setup_client(tmp_path)
    client.post(
        "/api/admin/v1/targets",
        headers=csrf_headers(client),
        json={"name": "Example", "aliases": ["example"], "official_domains": []},
    )
    with app.state.database.session() as session:
        candidate = ingest_observable(session, "example-login.test", provider="certstream")
        assert candidate is not None
        candidate_id = candidate.id
    false_positive = client.post(
        f"/api/admin/v1/candidates/{candidate_id}/review",
        headers=csrf_headers(client),
        json={"decision": "false_positive", "note": "controlled domain"},
    )
    assert false_positive.json()["new_status"] == "false_positive"
    suppression = client.get("/api/admin/v1/suppressions").json()[0]
    assert suppression["candidate_id"] == candidate_id
    assert suppression["enabled"] is True
    restored = client.post(
        f"/api/admin/v1/candidates/{candidate_id}/review",
        headers=csrf_headers(client),
        json={"decision": "restore", "note": "assessment corrected"},
    )
    assert restored.json()["new_status"] == "potential"
    assert client.get("/api/admin/v1/suppressions").json()[0]["enabled"] is False


def test_provider_management_and_domain_pivot_contract(tmp_path: Path) -> None:
    client, app = setup_client(tmp_path)
    from open_domain_radar.security import write_master_key

    write_master_key(app.state.settings.master_key_path)
    client.post(
        "/api/admin/v1/targets",
        headers=csrf_headers(client),
        json={"name": "Example", "aliases": ["example"], "official_domains": []},
    )
    configured = client.put(
        "/api/admin/v1/providers/urlscan",
        headers=csrf_headers(client),
        json={"enabled": True, "api_key": "fake-passive-key"},
    )
    assert configured.json()["name"] == "urlscan"
    assert configured.json()["configured"] is True
    missing_key_test = client.post(
        "/api/admin/v1/providers/virustotal/test",
        headers=csrf_headers(client),
        json={},
    )
    assert missing_key_test.status_code == 200
    assert missing_key_test.json()["status"] == "skipped"
    pivot = client.post(
        "/api/admin/v1/pivots",
        headers=csrf_headers(client),
        json={
            "domain": "secure-example-login.test",
            "providers": ["urlscan", "virustotal", "dns"],
            "note": "manual analyst pivot",
        },
    )
    assert pivot.status_code == 201
    assert pivot.json()["queued_providers"] == ["urlscan"]
    assert pivot.json()["skipped_providers"] == ["virustotal", "dns"]
    assert "[.]" in pivot.json()["domain"]
    removed = client.delete(
        "/api/admin/v1/providers/urlscan/secret",
        headers=csrf_headers(client),
    )
    assert removed.status_code == 204
    urlscan = next(row for row in client.get("/api/admin/v1/providers").json() if row["name"] == "urlscan")
    assert urlscan["configured"] is False


def test_process_health_routes(tmp_path: Path) -> None:
    client = TestClient(create_app(settings_for(tmp_path)))
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").json() == {"status": "ready", "database": "available"}


def test_remote_first_run_requires_cli_bootstrap(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    remote = Settings(
        settings.data_dir,
        settings.database_url,
        settings.master_key,
        settings.host,
        settings.port,
        "https://radar.example",
        settings.embed_worker,
        settings.session_hours,
        settings.certstream_url,
    )
    with TestClient(create_app(remote), base_url="https://radar.example") as client:
        session = client.get("/api/admin/v1/session").json()
        assert session["setup_required"] is True
        assert session["setup_allowed"] is False
        response = client.post(
            "/api/admin/v1/setup",
            headers={"Origin": "https://radar.example"},
            json={"username": "operator", "password": "correct horse battery staple"},
        )
    assert response.status_code == 404


def test_login_failures_are_throttled_without_user_enumeration(tmp_path: Path) -> None:
    client, _app = setup_client(tmp_path)
    client.post("/api/admin/v1/logout", headers=csrf_headers(client), json={})
    for _attempt in range(5):
        response = client.post(
            "/api/admin/v1/login",
            json={"username": "missing-user", "password": "wrong password value"},
        )
        assert response.status_code == 401
    blocked = client.post(
        "/api/admin/v1/login",
        json={"username": "missing-user", "password": "wrong password value"},
    )
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0


def test_login_throttle_cannot_be_bypassed_by_rotating_usernames(tmp_path: Path) -> None:
    client, _app = setup_client(tmp_path)
    client.post("/api/admin/v1/logout", headers=csrf_headers(client), json={})
    for attempt in range(5):
        response = client.post(
            "/api/admin/v1/login",
            json={"username": f"missing-{attempt}", "password": "wrong password value"},
        )
        assert response.status_code == 401
    assert (
        client.post(
            "/api/admin/v1/login",
            json={"username": "another-missing-user", "password": "wrong password value"},
        ).status_code
        == 429
    )


def test_login_rejects_oversized_request_body(tmp_path: Path) -> None:
    client = TestClient(create_app(settings_for(tmp_path)))
    response = client.post(
        "/api/admin/v1/login",
        content=b"x" * 16_385,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_candidate_detail_exposes_private_history_not_public_notes(tmp_path: Path) -> None:
    client, app = setup_client(tmp_path)
    client.post(
        "/api/admin/v1/targets",
        headers=csrf_headers(client),
        json={"name": "Example", "aliases": ["example"], "official_domains": []},
    )
    with app.state.database.session() as session:
        candidate = ingest_observable(
            session,
            "https://example-login.test/verify?victim=user@example.test&token=private",
            provider="certstream",
            payload={
                "certificate_name": "example-login.test",
                "observable": "https://example-login.test/reset/user@example.test/secret-token",
                "analyst_note": "private provider payload field",
            },
        )
        assert candidate is not None
        candidate_id = candidate.id
    client.post(
        f"/api/admin/v1/candidates/{candidate_id}/review",
        headers=csrf_headers(client),
        json={"decision": "publish", "note": "independently reviewed evidence"},
    )
    detail = client.get(f"/api/admin/v1/candidates/{candidate_id}").json()
    assert detail["observations"][0]["payload"]["certificate_name"] == "example-login[.]test"
    assert detail["observations"][0]["payload"]["observable"] == "example-login[.]test"
    assert "secret-token" not in str(detail)
    assert "private provider payload field" not in str(detail)
    assert detail["review_events"][0]["reason"] == "independently reviewed evidence"
    assert "token=private" not in str(detail)
    public = client.get("/api/public/v1/signals").text
    assert "independently reviewed evidence" not in public
    assert "token=private" not in public


def test_provider_config_is_preserved_and_environment_source_is_explicit(tmp_path: Path) -> None:
    settings = settings_for(tmp_path)
    settings = Settings(
        settings.data_dir,
        settings.database_url,
        settings.master_key,
        settings.host,
        settings.port,
        settings.public_origin,
        settings.embed_worker,
        settings.session_hours,
        settings.certstream_url,
        urlscan_api_key="environment-key",
    )
    client, _app = authenticated_client(settings)
    configured = client.put(
        "/api/admin/v1/providers/urlscan",
        headers=csrf_headers(client),
        json={"enabled": True, "config": {"result_limit": 17}},
    ).json()
    assert configured["credential_source"] == "environment"
    client.put(
        "/api/admin/v1/providers/urlscan",
        headers=csrf_headers(client),
        json={"enabled": False},
    )
    row = next(item for item in client.get("/api/admin/v1/providers").json() if item["name"] == "urlscan")
    assert row["config"] == {"result_limit": 17}
    assert row["status"] == "disabled"


def test_provider_test_failure_is_persisted_as_controlled_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = settings_for(tmp_path)
    settings = Settings(
        settings.data_dir,
        settings.database_url,
        settings.master_key,
        settings.host,
        settings.port,
        settings.public_origin,
        settings.embed_worker,
        settings.session_hours,
        settings.certstream_url,
        urlscan_api_key="environment-key",
    )
    client, _app = authenticated_client(settings)
    client.put(
        "/api/admin/v1/providers/urlscan",
        headers=csrf_headers(client),
        json={"enabled": True},
    )

    async def fail_search(*_args: object, **_kwargs: object) -> ProviderOutcome:
        request = httpx.Request("GET", "https://urlscan.io/api/v1/search/")
        raise httpx.ConnectError("controlled test failure", request=request)

    monkeypatch.setattr("open_domain_radar.api.URLScanAdapter.search", fail_search)
    failed = client.post("/api/admin/v1/providers/urlscan/test", headers=csrf_headers(client), json={})
    assert failed.status_code == 502
    assert failed.json()["message"] == "provider_connection_failed"
    row = next(item for item in client.get("/api/admin/v1/providers").json() if item["name"] == "urlscan")
    assert row["last_status"] == "failed"
    assert row["last_message"] == "provider_connection_failed"
