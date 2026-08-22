"""Transactional application services shared by API and workers."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .matching import MatchDecision, match_domain
from .models import (
    Candidate,
    Observation,
    PivotJob,
    Provider,
    ReviewEvent,
    Suppression,
    WatchTarget,
)
from .security import SecretBox, defang, normalize_observable

PIVOT_PROVIDERS = ("urlscan", "virustotal")
REVIEW_STATUS_BY_ACTION = {
    "confirm": "published",
    "publish": "published",
    "false_positive": "false_positive",
    "dismiss": "closed",
    "close": "closed",
}


def active_targets(db: Session) -> list[WatchTarget]:
    # Disabled targets are excluded from scoring by the matcher but their
    # official domains remain a global legitimate-domain boundary.
    return list(db.scalars(select(WatchTarget).order_by(WatchTarget.name)))


def active_suppressions(db: Session) -> list[Suppression]:
    return list(db.scalars(select(Suppression).where(Suppression.enabled.is_(True))))


def ingest_observable(
    db: Session,
    observable: str,
    *,
    provider: str,
    observed_at: datetime | None = None,
    payload: dict[str, Any] | None = None,
    reference: str | None = None,
    decision: MatchDecision | None = None,
) -> Candidate | None:
    """Store one observation when it passes the current matching policy.

    URL paths, query strings, and fragments are discarded by
    ``normalize_observable``. A candidate's identity is the normalized domain,
    which prevents victim tokens or other URL secrets from entering storage.
    """
    canonical, value_type, domain = normalize_observable(observable)
    match = decision or match_domain(domain, active_targets(db), active_suppressions(db))
    if not match.accepted:
        return None

    timestamp = observed_at or datetime.now(UTC)
    candidate = _find_candidate(db, canonical, match.target_id)
    if candidate is None:
        candidate = _new_candidate(canonical, value_type, domain, provider, timestamp, match)
        db.add(candidate)
        db.flush()
    else:
        _merge_candidate(candidate, provider, timestamp, match)

    observation_payload = _bounded_payload(payload or {})
    fingerprint = _observation_fingerprint(
        candidate.id,
        provider,
        canonical,
        reference,
        timestamp,
        observation_payload,
    )
    exists = db.scalar(select(Observation.id).where(Observation.fingerprint == fingerprint))
    if exists is None:
        db.add(
            Observation(
                candidate_id=candidate.id,
                provider=provider,
                fingerprint=fingerprint,
                reference=(reference or "")[:512] or None,
                payload=observation_payload,
                observed_at=timestamp,
            )
        )
    return candidate


def queue_configured_pivots(
    db: Session,
    candidate: Candidate,
    settings: Settings,
    *,
    trigger: str,
    cooldown_hours: int = 24,
) -> tuple[list[PivotJob], list[str]]:
    """Queue one bounded passive enrichment pass for each configured provider.

    Missing optional keys are a normal skip. The cooldown prevents repeated
    certificate sightings from continuously spending provider quotas.
    """
    queued: list[PivotJob] = []
    skipped: list[str] = []
    cutoff = datetime.now(UTC) - timedelta(hours=min(max(cooldown_hours, 1), 168))
    environment_secrets = {
        "urlscan": settings.urlscan_api_key,
        "virustotal": settings.virustotal_api_key,
    }
    for kind in PIVOT_PROVIDERS:
        provider = db.scalar(select(Provider).where(Provider.kind == kind))
        if provider is None or not provider.enabled:
            continue
        if not (environment_secrets[kind] or provider.secret_ciphertext):
            skipped.append(kind)
            continue

        recent = db.scalar(
            select(PivotJob.id).where(
                PivotJob.candidate_id == candidate.id,
                PivotJob.provider == kind,
                PivotJob.created_at >= cutoff,
                PivotJob.state.in_(["queued", "running", "success"]),
            )
        )
        if recent is not None:
            skipped.append(kind)
            continue
        job = PivotJob(
            candidate_id=candidate.id,
            provider=kind,
            parameters={"trigger": trigger[:40], "depth": 0},
        )
        db.add(job)
        queued.append(job)
    if queued:
        db.flush()
    return queued, skipped


def review_candidate(
    db: Session,
    candidate: Candidate,
    *,
    admin_id: int,
    action: str,
    reason: str,
    suppress: bool = False,
    suppression_scope: str = "target",
) -> ReviewEvent:
    """Apply an analyst disposition and append its audit event."""
    reason = _validated_reason(reason, "review")
    if action not in REVIEW_STATUS_BY_ACTION:
        raise ValueError("unsupported review action")
    if suppress and action != "false_positive":
        raise ValueError("suppression can only accompany a false-positive review")
    if candidate.status in {"false_positive", "closed"}:
        raise ValueError("restore reviewed-away candidates before applying another disposition")

    if action in {"confirm", "publish"}:
        # A signal may have aged past the current policy. Re-checking here keeps
        # stale or newly suppressed candidates out of the public view.
        current_decision = match_domain(candidate.canonical_domain, active_targets(db), active_suppressions(db))
        if not current_decision.accepted or current_decision.target_id != candidate.target_id:
            raise ValueError("candidate does not meet the current matching and suppression policy")

    previous_status = candidate.status
    candidate.status = REVIEW_STATUS_BY_ACTION[action]
    candidate.reviewed_at = datetime.now(UTC)
    event = ReviewEvent(
        candidate_id=candidate.id,
        admin_id=admin_id,
        action=action,
        previous_status=previous_status,
        new_status=candidate.status,
        reason=reason,
    )
    db.add(event)
    if suppress:
        target_id = candidate.target_id if suppression_scope == "target" else None
        db.add(
            Suppression(
                pattern=candidate.canonical_domain,
                match_type="exact",
                target_id=target_id,
                candidate_id=candidate.id,
                reason=reason,
                created_by=admin_id,
            )
        )
    db.flush()
    return event


def restore_candidate(db: Session, candidate: Candidate, *, admin_id: int, reason: str) -> ReviewEvent:
    """Return a reviewed-away candidate to the potential review queue."""
    if candidate.status not in {"false_positive", "closed"}:
        raise ValueError("only reviewed-away candidates can be restored")
    reason = _validated_reason(reason, "restore")
    linked_suppressions = list(
        db.scalars(
            select(Suppression).where(
                Suppression.candidate_id == candidate.id,
                Suppression.enabled.is_(True),
            )
        )
    )
    for suppression in linked_suppressions:
        suppression.enabled = False

    # SQLAlchemy auto-flushes the disabled suppressions before this query. If
    # matching fails, the caller's transaction rolls all of these changes back.
    decision = match_domain(candidate.canonical_domain, active_targets(db), active_suppressions(db))
    if not decision.accepted:
        raise ValueError(f"candidate no longer meets current matching policy: {decision.rejected_reason}")
    previous = candidate.status
    candidate.target_id = decision.target_id
    candidate.confidence = decision.score
    candidate.reasons = list(decision.reasons)
    candidate.status = "potential"
    candidate.reviewed_at = datetime.now(UTC)
    event = ReviewEvent(
        candidate_id=candidate.id,
        admin_id=admin_id,
        action="restore",
        previous_status=previous,
        new_status="potential",
        reason=reason,
    )
    db.add(event)
    db.flush()
    return event


def set_provider_secret(db: Session, provider: Provider, secret: str, box: SecretBox) -> None:
    if len(secret) > 4096:
        raise ValueError("provider secret is too long")
    provider.secret_ciphertext = box.encrypt(secret) if secret else None


def get_provider_secret(provider: Provider, box: SecretBox, env_override: str | None = None) -> str | None:
    """Prefer an environment secret, then decrypt the stored value if present."""
    if env_override:
        return env_override
    return box.decrypt(provider.secret_ciphertext) if provider.secret_ciphertext else None


def _find_candidate(db: Session, canonical: str, target_id: int | None) -> Candidate | None:
    return db.scalar(
        select(Candidate).where(
            Candidate.canonical_value == canonical,
            Candidate.target_id == target_id,
        )
    )


def _new_candidate(
    canonical: str,
    value_type: str,
    domain: str,
    provider: str,
    timestamp: datetime,
    decision: MatchDecision,
) -> Candidate:
    return Candidate(
        canonical_value=canonical,
        value_type=value_type,
        defanged_value=defang(canonical),
        canonical_domain=domain,
        target_id=decision.target_id,
        confidence=decision.score,
        reasons=list(decision.reasons),
        sources=[provider],
        first_seen_at=timestamp,
        last_seen_at=timestamp,
    )


def _merge_candidate(
    candidate: Candidate,
    provider: str,
    timestamp: datetime,
    decision: MatchDecision,
) -> None:
    candidate.first_seen_at = min(_aware(candidate.first_seen_at), _aware(timestamp))
    candidate.last_seen_at = max(_aware(candidate.last_seen_at), _aware(timestamp))
    candidate.confidence = max(candidate.confidence, decision.score)
    candidate.reasons = sorted(set(candidate.reasons) | set(decision.reasons))
    candidate.sources = sorted(set(candidate.sources) | {provider})


def _observation_fingerprint(
    candidate_id: int,
    provider: str,
    canonical: str,
    reference: str | None,
    timestamp: datetime,
    payload: dict[str, Any],
) -> str:
    # The observation timestamp is part of the fingerprint, so a later sighting
    # remains useful history while an exact replay stays idempotent.
    timestamp_utc = _aware(timestamp).astimezone(UTC).isoformat()
    fingerprint_fields = [candidate_id, provider, canonical, reference or "", timestamp_utc, payload]
    serialized = json.dumps(fingerprint_fields, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _validated_reason(reason: str, action_name: str) -> str:
    clean_reason = reason.strip()
    if len(clean_reason) < 3 or len(clean_reason) > 500:
        raise ValueError(f"{action_name} reason must contain 3 to 500 characters")
    return clean_reason


def _bounded_payload(payload: dict[str, Any]) -> dict[str, Any]:
    # Provider responses are evidence, not an unbounded document store. Large
    # payloads are represented by a digest so analysts can still correlate them.
    encoded = json.dumps(payload, default=str)
    if len(encoded) <= 16_384:
        return cast(dict[str, Any], json.loads(encoded))
    return {"truncated": True, "sha256": hashlib.sha256(encoded.encode()).hexdigest()}


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)
