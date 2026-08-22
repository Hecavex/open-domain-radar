from __future__ import annotations

from pathlib import Path

import pytest

from open_domain_radar.config import Settings
from open_domain_radar.db import Database
from open_domain_radar.models import Admin, Candidate, Suppression, WatchTarget
from open_domain_radar.security import hash_password
from open_domain_radar.services import restore_candidate, review_candidate


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


def records(database: Database) -> tuple[int, int]:
    with database.session() as session:
        admin = Admin(username="analyst", password_hash=hash_password("correct horse battery staple"))
        target = WatchTarget(name="Example", aliases=["example"], official_domains=[])
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
        return admin.id, candidate.id


def test_false_positive_review_can_add_suppression_and_restore(tmp_path: Path) -> None:
    database = Database(settings_for(tmp_path))
    database.initialize()
    admin_id, candidate_id = records(database)
    with database.session() as session:
        candidate = session.get(Candidate, candidate_id)
        assert candidate is not None
        event = review_candidate(
            session,
            candidate,
            admin_id=admin_id,
            action="false_positive",
            reason="official campaign microsite",
            suppress=True,
        )
        assert event.previous_status == "potential"
        assert event.new_status == "false_positive"
        assert session.query(Suppression).one().target_id == candidate.target_id
    with database.session() as session:
        candidate = session.get(Candidate, candidate_id)
        assert candidate is not None
        event = restore_candidate(session, candidate, admin_id=admin_id, reason="new evidence changed assessment")
        assert event.action == "restore"
        assert candidate.status == "potential"


def test_reviewed_away_candidate_must_be_restored_before_publish(tmp_path: Path) -> None:
    database = Database(settings_for(tmp_path))
    database.initialize()
    admin_id, candidate_id = records(database)
    with database.session() as session:
        candidate = session.get(Candidate, candidate_id)
        assert candidate is not None
        review_candidate(
            session,
            candidate,
            admin_id=admin_id,
            action="false_positive",
            reason="known legitimate infrastructure",
            suppress=True,
        )
    with pytest.raises(ValueError, match="restore reviewed-away"), database.session() as session:
        candidate = session.get(Candidate, candidate_id)
        assert candidate is not None
        review_candidate(
            session,
            candidate,
            admin_id=admin_id,
            action="publish",
            reason="attempted direct republication",
        )


def test_confirm_cannot_create_false_positive_suppression(tmp_path: Path) -> None:
    database = Database(settings_for(tmp_path))
    database.initialize()
    admin_id, candidate_id = records(database)
    with pytest.raises(ValueError, match="false-positive"), database.session() as session:
        candidate = session.get(Candidate, candidate_id)
        assert candidate is not None
        review_candidate(
            session, candidate, admin_id=admin_id, action="confirm", reason="verified evidence", suppress=True
        )


def test_closed_candidate_can_restore_only_under_current_matching_policy(tmp_path: Path) -> None:
    database = Database(settings_for(tmp_path))
    database.initialize()
    admin_id, candidate_id = records(database)
    with database.session() as session:
        candidate = session.get(Candidate, candidate_id)
        assert candidate is not None
        review_candidate(session, candidate, admin_id=admin_id, action="close", reason="not actionable today")
    with database.session() as session:
        candidate = session.get(Candidate, candidate_id)
        assert candidate is not None
        event = restore_candidate(session, candidate, admin_id=admin_id, reason="new reporting justifies review")
        assert event.previous_status == "closed"
    with database.session() as session:
        candidate = session.get(Candidate, candidate_id)
        assert candidate is not None
        review_candidate(session, candidate, admin_id=admin_id, action="close", reason="pause this candidate")
        target = session.get(WatchTarget, candidate.target_id)
        assert target is not None
        target.enabled = False
    with pytest.raises(ValueError, match="current matching policy"), database.session() as session:
        candidate = session.get(Candidate, candidate_id)
        assert candidate is not None
        restore_candidate(session, candidate, admin_id=admin_id, reason="attempt after target disabled")
