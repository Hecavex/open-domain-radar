"""Relational data model for collection, review and public presentation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Return a timezone-aware timestamp for SQLAlchemy defaults."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Declarative base shared by every persisted model."""


class Admin(Base):
    """The single operator account created through the local CLI."""

    __tablename__ = "admins"

    id: Mapped[int] = mapped_column(primary_key=True)
    # A unique fixed slot enforces the one-operator design in the database too.
    slot: Mapped[int] = mapped_column(Integer, unique=True, default=1)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    sessions: Mapped[list[AdminSession]] = relationship(back_populates="admin", cascade="all, delete-orphan")


class AdminSession(Base):
    """A revocable operator session containing hashes, never raw tokens."""

    __tablename__ = "admin_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    admin_id: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    admin: Mapped[Admin] = relationship(back_populates="sessions")


class WatchTarget(Base):
    """An organization or product name that candidate domains may resemble."""

    __tablename__ = "watch_targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    keywords: Mapped[list[str]] = mapped_column(JSON, default=list)
    official_domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    minimum_score: Mapped[int] = mapped_column(Integer, default=65)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Provider(Base):
    """Collection-provider configuration and its latest operational status."""

    __tablename__ = "providers"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    secret_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_message: Mapped[str | None] = mapped_column(String(240), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Candidate(Base):
    """One normalized domain matched to one watch target."""

    __tablename__ = "candidates"
    __table_args__ = (
        # The same domain may legitimately be tracked for different targets.
        UniqueConstraint("canonical_value", "target_id", name="uq_candidate_value_target"),
        Index("ix_candidates_public", "status", "last_seen_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    canonical_value: Mapped[str] = mapped_column(String(2048))
    value_type: Mapped[str] = mapped_column(String(16), default="domain")
    defanged_value: Mapped[str] = mapped_column(String(2200))
    canonical_domain: Mapped[str] = mapped_column(String(253), index=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("watch_targets.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="potential", index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    target: Mapped[WatchTarget | None] = relationship()
    observations: Mapped[list[Observation]] = relationship(back_populates="candidate", cascade="all, delete-orphan")
    review_events: Mapped[list[ReviewEvent]] = relationship(back_populates="candidate")


class Observation(Base):
    """Provider evidence attached to a candidate.

    Database triggers make observations append-only after insertion.
    """

    __tablename__ = "observations"
    __table_args__ = (UniqueConstraint("fingerprint", name="uq_observation_fingerprint"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    candidate_id: Mapped[int] = mapped_column(ForeignKey("candidates.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    reference: Mapped[str | None] = mapped_column(String(512), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    candidate: Mapped[Candidate] = relationship(back_populates="observations")


class PivotJob(Base):
    """A queued passive-provider lookup for one candidate."""

    __tablename__ = "pivot_jobs"
    __table_args__ = (Index("ix_pivot_queue", "state", "not_before"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    candidate_id: Mapped[int] = mapped_column(ForeignKey("candidates.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(24), default="queued")
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    candidate: Mapped[Candidate] = relationship()


class ReviewEvent(Base):
    """Append-only audit record for an analyst status decision."""

    __tablename__ = "review_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    candidate_id: Mapped[int] = mapped_column(ForeignKey("candidates.id", ondelete="RESTRICT"), index=True)
    admin_id: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    action: Mapped[str] = mapped_column(String(32))
    previous_status: Mapped[str] = mapped_column(String(32))
    new_status: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    candidate: Mapped[Candidate] = relationship(back_populates="review_events")


class Suppression(Base):
    """A target-specific or global rule that rejects matching domains."""

    __tablename__ = "suppressions"

    id: Mapped[int] = mapped_column(primary_key=True)
    pattern: Mapped[str] = mapped_column(String(253))
    match_type: Mapped[str] = mapped_column(String(16), default="exact")
    target_id: Mapped[int | None] = mapped_column(ForeignKey("watch_targets.id", ondelete="CASCADE"), nullable=True)
    candidate_id: Mapped[int | None] = mapped_column(ForeignKey("candidates.id", ondelete="SET NULL"), nullable=True)
    reason: Mapped[str] = mapped_column(String(500))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("admins.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollectionRun(Base):
    """Summary and outcome of one bounded provider collection attempt."""

    __tablename__ = "collection_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    state: Mapped[str] = mapped_column(String(24), default="running", index=True)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
