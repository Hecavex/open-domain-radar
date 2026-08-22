"""FastAPI application exposing a read-only public surface and a guarded admin API."""

# FastAPI intentionally evaluates Depends() in endpoint signatures.
# ruff: noqa: B008

from __future__ import annotations

import re
import threading
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import String, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.sql.elements import ColumnElement
from starlette.templating import Jinja2Templates

from .config import Settings
from .db import Database
from .matching import match_domain
from .models import (
    Admin,
    AdminSession,
    Candidate,
    CollectionRun,
    PivotJob,
    Provider,
    ReviewEvent,
    Suppression,
    WatchTarget,
)
from .providers import URLScanAdapter, VirusTotalAdapter
from .providers.base import provider_error_code
from .security import (
    LoginThrottle,
    SecretBox,
    authenticate_session,
    create_session,
    defang,
    normalize_domain,
    normalize_observable,
    validate_csrf,
    verify_password,
)
from .services import (
    active_suppressions,
    active_targets,
    get_provider_secret,
    ingest_observable,
    restore_candidate,
    review_candidate,
    set_provider_secret,
)

SESSION_COOKIE = "odr_session"
CSRF_COOKIE = "odr_csrf"
ALLOWED_PROVIDERS = {"certstream", "urlscan", "virustotal"}
PASSIVE_PIVOT_PROVIDERS = {"urlscan", "virustotal"}
PUBLIC_CANDIDATE_STATUSES = {"potential", "published"}
PUBLIC_SOURCES = {"certstream", "urlscan", "virustotal", "manual"}
MAX_LOGIN_BODY_BYTES = 16_384
PASSWORD_CHECK_SLOTS = 2


class LoginInput(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=512)


class TargetInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    aliases: list[str] = Field(default_factory=list, max_length=50)
    keywords: list[str] = Field(default_factory=list, max_length=50)
    official_domains: list[str] = Field(default_factory=list, max_length=100)
    country: str | None = Field(default=None, min_length=2, max_length=2)
    minimum_score: int = Field(default=65, ge=55, le=100)
    enabled: bool = True


class TargetPatch(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    aliases: list[str] | None = Field(default=None, max_length=50)
    keywords: list[str] | None = Field(default=None, max_length=50)
    official_domains: list[str] | None = Field(default=None, max_length=100)
    country: str | None = Field(default=None, min_length=2, max_length=2)
    minimum_score: int | None = Field(default=None, ge=55, le=100)
    enabled: bool | None = None


class ProviderInput(BaseModel):
    enabled: bool
    config: dict[str, Any] | None = None
    api_key: str | None = Field(default=None, max_length=4096)
    clear_secret: bool = False


class ReviewInput(BaseModel):
    decision: Literal["publish", "false_positive", "restore", "close"] | None = None
    note: str | None = Field(default=None, max_length=500)
    action: Literal["confirm", "publish", "false_positive", "dismiss", "close"] | None = None
    reason: str | None = Field(default=None, max_length=500)
    suppress: bool | None = None
    suppression_scope: Literal["target", "global"] = "target"


class RestoreInput(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class PivotInput(BaseModel):
    candidate_id: int | None = None
    provider: Literal["urlscan", "virustotal"] | None = None
    domain: str | None = Field(default=None, min_length=1, max_length=253)
    providers: list[str] = Field(default_factory=list, max_length=5)
    note: str | None = Field(default=None, max_length=500)


class SuppressionInput(BaseModel):
    pattern: str = Field(min_length=1, max_length=253)
    match_type: Literal["exact", "suffix", "glob"] = "exact"
    target_id: int | None = None
    reason: str = Field(min_length=3, max_length=500)


@dataclass(slots=True)
class AuthContext:
    """Authenticated database records made available to admin endpoints."""

    session: AdminSession
    admin: Admin


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create a fully initialized web application for the supplied settings."""
    settings = settings or Settings.from_env()
    database = Database(settings)
    database.initialize()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        worker_task = None
        if settings.embed_worker:
            import asyncio

            from .worker import RadarWorker

            worker_task = asyncio.create_task(RadarWorker(database, settings).loop())
        yield
        if worker_task:
            worker_task.cancel()
            with suppress(BaseException):
                await worker_task

    app = FastAPI(
        title="Open Domain Radar",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.login_throttle = LoginThrottle()
    # Argon2 is intentionally expensive. Limit concurrent checks so a short
    # login burst cannot consume every worker thread in this single-process app.
    app.state.password_checks = threading.BoundedSemaphore(value=PASSWORD_CHECK_SLOTS)

    @app.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.url.path == "/api/admin/v1/login":
            rejection = await _read_bounded_login_body(request)
            if rejection is not None:
                return _apply_security_headers(rejection, request, settings)
        response = await call_next(request)
        return _apply_security_headers(response, request, settings)

    register_public_routes(app)
    register_admin_routes(app)
    register_frontend(app)
    return app


async def _read_bounded_login_body(request: Request) -> Response | None:
    """Buffer a small login body so FastAPI can parse it after size checks."""
    content_length = request.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > MAX_LOGIN_BODY_BYTES:
                return Response("request body too large", status_code=413, media_type="text/plain")
        except ValueError:
            return Response("invalid content length", status_code=400, media_type="text/plain")

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_LOGIN_BODY_BYTES:
            return Response("request body too large", status_code=413, media_type="text/plain")

    # Starlette normally caches request bytes in this attribute. Because this
    # helper consumed the stream, restore that cache for FastAPI's JSON parser.
    request._body = bytes(body)  # noqa: SLF001
    return None


def _apply_security_headers(response: Response, request: Request, settings: Settings) -> Response:
    """Apply browser policy headers to normal and early-error responses."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'self'",
    )
    if request.url.path.startswith("/api/admin/"):
        response.headers["Cache-Control"] = "no-store"
    if settings.cookie_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


def get_db(request: Request) -> Iterator[Session]:
    """Provide one request transaction and always close its session."""
    session = request.app.state.database.session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def require_admin(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    """Reject requests without an active operator session."""
    authenticated = authenticate_session(db, request.cookies.get(SESSION_COOKIE))
    if authenticated is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    return AuthContext(authenticated[0], authenticated[1])


def require_csrf(request: Request, context: AuthContext = Depends(require_admin)) -> AuthContext:
    """Require the session-bound double-submit token on state changes."""
    if not validate_csrf(
        context.session,
        request.headers.get("X-CSRF-Token"),
        request.cookies.get(CSRF_COOKIE),
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid CSRF token")
    return context


def register_public_routes(app: FastAPI) -> None:
    """Register routes that never require an operator account."""

    @app.get("/health/live")
    def liveness() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready")
    def readiness(db: Session = Depends(get_db)) -> dict[str, str]:
        db.scalar(select(func.count()).select_from(Provider))
        return {"status": "ready", "database": "available"}

    @app.get("/api/public/v1/signals")
    def public_signals(
        q: str | None = Query(default=None, max_length=120),
        query: str | None = Query(default=None, max_length=120),
        status_filter: str | None = Query(default=None, alias="status", max_length=32),
        source: str | None = Query(default=None, max_length=32),
        target: str | None = Query(default=None, max_length=160),
        page: int = Query(default=1, ge=1, le=10_000),
        page_size: int = Query(default=25, ge=1, le=100),
        limit: int | None = Query(default=None, ge=1, le=100),
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        page_size = limit or page_size
        if status_filter and status_filter not in PUBLIC_CANDIDATE_STATUSES:
            raise HTTPException(status_code=422, detail="unsupported public status")
        conditions: list[ColumnElement[bool]] = (
            [Candidate.status == status_filter] if status_filter else [Candidate.status.in_(PUBLIC_CANDIDATE_STATUSES)]
        )
        search_value = query or q
        if search_value:
            safe_q = search_value.replace("%", "\\%").replace("_", "\\_")
            conditions.append(
                or_(
                    Candidate.canonical_domain.ilike(f"%{safe_q}%", escape="\\"),
                    Candidate.target.has(WatchTarget.name.ilike(f"%{safe_q}%", escape="\\")),
                )
            )
        if source:
            if source not in PUBLIC_SOURCES:
                raise HTTPException(status_code=422, detail="unsupported source")
            conditions.append(Candidate.sources.cast(String).like(f'%"{source}"%'))
        if target:
            if target.isdigit():
                conditions.append(Candidate.target_id == int(target))
            else:
                conditions.append(Candidate.target.has(WatchTarget.name == target))
        total = db.scalar(select(func.count()).select_from(Candidate).where(*conditions)) or 0
        rows = db.scalars(
            select(Candidate)
            .options(selectinload(Candidate.target))
            .where(*conditions)
            .order_by(Candidate.last_seen_at.desc(), Candidate.id.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
        pages = (total + page_size - 1) // page_size
        return {
            "items": [_public_candidate(row) for row in rows],
            "page": page,
            "pageSize": page_size,
            "total": total,
            "pages": pages,
            "pagination": {"page": page, "page_size": page_size, "total": total, "pages": pages},
        }

    @app.get("/api/public/v1/stats")
    def public_stats(db: Session = Depends(get_db)) -> dict[str, Any]:
        counts: dict[str, int] = {
            row[0]: row[1]
            for row in db.execute(select(Candidate.status, func.count(Candidate.id)).group_by(Candidate.status)).all()
        }
        visible = ["potential", "published"]
        source_rows = db.scalars(select(Candidate.sources).where(Candidate.status.in_(visible))).all()
        sources = sorted({source for row in source_rows for source in row})
        target_names = list(
            db.scalars(
                select(WatchTarget.name)
                .join(Candidate, Candidate.target_id == WatchTarget.id)
                .where(Candidate.status.in_(visible))
                .distinct()
                .order_by(WatchTarget.name)
            )
        )
        return {
            "signals": sum(counts.get(key, 0) for key in visible),
            "published": counts.get("published", 0),
            "reviewed_published": counts.get("published", 0),
            "potential": counts.get("potential", 0),
            "observed_24h": db.scalar(
                select(func.count())
                .select_from(Candidate)
                .where(Candidate.status.in_(visible), Candidate.last_seen_at >= datetime.now(UTC) - timedelta(hours=24))
            )
            or 0,
            "targets": len(target_names),
            "targets_list": target_names,
            "sources": sources,
            "last_observed_at": _iso(
                db.scalar(select(func.max(Candidate.last_seen_at)).where(Candidate.status.in_(visible)))
            ),
            "last_collection": _iso(
                db.scalar(select(func.max(CollectionRun.finished_at)).where(CollectionRun.provider == "certstream"))
            ),
        }

    @app.get("/api/public/v1/health")
    def public_health(db: Session = Depends(get_db)) -> dict[str, Any]:
        db.scalar(select(func.count()).select_from(Candidate))
        latest = db.scalar(
            select(CollectionRun)
            .where(CollectionRun.provider == "certstream")
            .order_by(CollectionRun.started_at.desc())
            .limit(1)
        )
        health_status = "unknown"
        freshness = "no_collection_runs"
        if latest is not None:
            reference = latest.finished_at or latest.started_at
            stale = _aware(reference) < datetime.now(UTC) - timedelta(minutes=20)
            if latest.state == "skipped":
                health_status = "unknown"
            else:
                health_status = "degraded" if latest.state == "failed" or stale else "ok"
            freshness = "stale" if stale else "current"
        return {
            "status": health_status,
            "database": "available",
            "freshness": freshness,
            "latest_collection": None
            if latest is None
            else {"provider": latest.provider, "state": latest.state, "finished_at": _iso(latest.finished_at)},
        }


def register_admin_routes(app: FastAPI) -> None:
    """Register authenticated configuration, review and pivot routes."""

    @app.post("/api/admin/v1/login")
    def login(
        payload: LoginInput, request: Request, response: Response, db: Session = Depends(get_db)
    ) -> dict[str, Any]:
        _enforce_auth_origin(request)
        throttle: LoginThrottle = request.app.state.login_throttle
        # Proxy headers are disabled in uvicorn, so this is the TCP peer. A
        # reverse proxy should enforce its own client-IP rate limit as well.
        client = request.client.host if request.client else "unknown"
        throttle_key = f"peer:{client}"
        retry_after = throttle.retry_after(throttle_key)
        if retry_after:
            raise HTTPException(
                status_code=429,
                detail="too many login attempts",
                headers={"Retry-After": str(retry_after)},
            )
        password_checks: threading.BoundedSemaphore = request.app.state.password_checks
        if not password_checks.acquire(blocking=False):
            raise HTTPException(
                status_code=429,
                detail="password verification capacity reached",
                headers={"Retry-After": "2"},
            )
        try:
            admin = db.scalar(select(Admin).where(Admin.username == payload.username))
            valid_password = verify_password(admin.password_hash if admin and admin.active else None, payload.password)
        finally:
            password_checks.release()
        if admin is None or not admin.active or not valid_password:
            throttle.record_failure(throttle_key)
            raise HTTPException(status_code=401, detail="invalid credentials")
        throttle.reset(throttle_key)
        return _issue_login(response, request.app.state.settings, db, admin)

    @app.get("/api/admin/v1/session")
    def session_status(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
        authenticated = authenticate_session(db, request.cookies.get(SESSION_COOKIE))
        if authenticated is None:
            setup_required = (db.scalar(select(func.count()).select_from(Admin)) or 0) == 0
            return {
                "authenticated": False,
                "setup_required": setup_required,
                "setup_allowed": False,
            }
        session_record, admin = authenticated
        csrf_token = request.cookies.get(CSRF_COOKIE)
        if not csrf_token or not validate_csrf(session_record, csrf_token, csrf_token):
            csrf_token = None
        return {
            "authenticated": True,
            "username": admin.username,
            "expires_at": _iso(session_record.expires_at),
            "csrf_token": csrf_token,
        }

    @app.post("/api/admin/v1/logout", status_code=204)
    def logout(response: Response, context: AuthContext = Depends(require_csrf)) -> None:
        context.session.revoked_at = datetime.now(UTC)
        response.delete_cookie(SESSION_COOKIE, path="/api/admin/v1")
        response.delete_cookie(CSRF_COOKIE, path="/")

    @app.get("/api/admin/v1/targets")
    def targets(db: Session = Depends(get_db), _context: AuthContext = Depends(require_admin)) -> list[dict[str, Any]]:
        return [_target(row) for row in db.scalars(select(WatchTarget).order_by(WatchTarget.name))]

    @app.post("/api/admin/v1/targets", status_code=201)
    def add_target(
        payload: TargetInput, db: Session = Depends(get_db), _context: AuthContext = Depends(require_csrf)
    ) -> dict[str, Any]:
        target = WatchTarget(**_validated_target(payload))
        try:
            db.add(target)
            db.flush()
        except IntegrityError as exc:
            raise HTTPException(status_code=409, detail="watch target name already exists") from exc
        return _target(target)

    @app.put("/api/admin/v1/targets/{target_id}")
    @app.patch("/api/admin/v1/targets/{target_id}")
    def patch_target(
        target_id: int,
        payload: TargetPatch,
        db: Session = Depends(get_db),
        _context: AuthContext = Depends(require_csrf),
    ) -> dict[str, Any]:
        target = _required(db, WatchTarget, target_id)
        updates = _model_dump(payload, exclude_unset=True)
        if "official_domains" in updates:
            updates["official_domains"] = _domains(updates["official_domains"])
        if "aliases" in updates:
            updates["aliases"] = _aliases(updates["aliases"])
        if "keywords" in updates:
            updates["keywords"] = _aliases(updates["keywords"])
        if updates.get("country"):
            updates["country"] = updates["country"].upper()
        for key, value in updates.items():
            setattr(target, key, value)
        db.flush()
        return _target(target)

    @app.delete("/api/admin/v1/targets/{target_id}", status_code=204)
    def disable_target(
        target_id: int, db: Session = Depends(get_db), _context: AuthContext = Depends(require_csrf)
    ) -> None:
        target = _required(db, WatchTarget, target_id)
        target.enabled = False

    @app.get("/api/admin/v1/providers")
    def providers(
        request: Request, db: Session = Depends(get_db), _context: AuthContext = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        settings: Settings = request.app.state.settings
        return [_provider(row, settings) for row in db.scalars(select(Provider).order_by(Provider.kind))]

    @app.put("/api/admin/v1/providers/{kind}")
    def configure_provider(
        kind: str,
        payload: ProviderInput,
        request: Request,
        db: Session = Depends(get_db),
        _context: AuthContext = Depends(require_csrf),
    ) -> dict[str, Any]:
        if kind not in ALLOWED_PROVIDERS:
            raise HTTPException(status_code=404, detail="unknown provider")
        provider = db.scalar(select(Provider).where(Provider.kind == kind))
        if provider is None:
            provider = Provider(kind=kind)
            db.add(provider)
        provider.enabled = payload.enabled
        if payload.config is not None:
            provider.config = _validated_provider_config(kind, payload.config)
        if payload.api_key is not None or payload.clear_secret:
            try:
                box = SecretBox.load(request.app.state.settings, create=False)
                set_provider_secret(db, provider, "" if payload.clear_secret else (payload.api_key or ""), box)
            except (RuntimeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        db.flush()
        return _provider(provider, request.app.state.settings)

    @app.delete("/api/admin/v1/providers/{kind}/secret", status_code=204)
    def delete_provider_secret(
        kind: str,
        db: Session = Depends(get_db),
        _context: AuthContext = Depends(require_csrf),
    ) -> None:
        if kind not in ALLOWED_PROVIDERS:
            raise HTTPException(status_code=404, detail="unknown provider")
        provider = db.scalar(select(Provider).where(Provider.kind == kind))
        if provider is None:
            raise HTTPException(status_code=404, detail="provider not found")
        provider.secret_ciphertext = None

    @app.post("/api/admin/v1/providers/{kind}/test")
    async def test_provider(
        kind: str,
        request: Request,
        response: Response,
        db: Session = Depends(get_db),
        _context: AuthContext = Depends(require_csrf),
    ) -> dict[str, Any]:
        if kind not in ALLOWED_PROVIDERS:
            raise HTTPException(status_code=404, detail="unknown provider")
        provider = db.scalar(select(Provider).where(Provider.kind == kind))
        if provider is None:
            raise HTTPException(status_code=404, detail="provider not found")
        if kind == "certstream":
            outcome_status: str = "ready"
            message: str | None = "bounded collector configured"
            count = 0
        else:
            settings: Settings = request.app.state.settings
            env_secret = _provider_environment_secret(kind, settings)
            try:
                box = SecretBox.load(settings) if provider.secret_ciphertext else None
                secret = get_provider_secret(provider, box, env_secret) if box is not None else env_secret
                outcome = (
                    await URLScanAdapter().search("domain:example.invalid", secret, 1)
                    if kind == "urlscan"
                    else await VirusTotalAdapter().domain_relationships("example.invalid", secret, 1)
                )
                outcome_status, message, count = outcome.status, outcome.message, len(outcome.items)
            except Exception as exc:
                # Persist a small, controlled error code. Raw provider errors can
                # contain request details and must not reach the UI or database.
                error_code = provider_error_code(exc)
                outcome_status, message, count = "failed", error_code, 0
                response.status_code = status.HTTP_502_BAD_GATEWAY
        provider.last_status = outcome_status
        provider.last_message = message
        provider.last_run_at = datetime.now(UTC)
        return {"kind": kind, "status": outcome_status, "message": message, "items": count}

    @app.get("/api/admin/v1/candidates")
    def candidates(
        query: str | None = Query(default=None, max_length=120),
        status_filter: str | None = Query(default=None, alias="status", max_length=32),
        page: int = Query(default=1, ge=1, le=10_000),
        limit: int = Query(default=50, ge=1, le=100),
        db: Session = Depends(get_db),
        _context: AuthContext = Depends(require_admin),
    ) -> dict[str, Any]:
        allowed_statuses = {"potential", "published", "false_positive", "closed"}
        if status_filter and status_filter not in allowed_statuses:
            raise HTTPException(status_code=422, detail="unsupported candidate status")
        conditions: list[ColumnElement[bool]] = [Candidate.status == (status_filter or "potential")]
        if query:
            safe_query = query.replace("%", "\\%").replace("_", "\\_")
            conditions.append(
                or_(
                    Candidate.canonical_domain.ilike(f"%{safe_query}%", escape="\\"),
                    Candidate.target.has(WatchTarget.name.ilike(f"%{safe_query}%", escape="\\")),
                )
            )
        total = db.scalar(select(func.count()).select_from(Candidate).where(*conditions)) or 0
        rows = db.scalars(
            select(Candidate)
            .options(selectinload(Candidate.target))
            .where(*conditions)
            .order_by(Candidate.last_seen_at.desc())
            .offset((page - 1) * limit)
            .limit(limit)
        ).all()
        pages = (total + limit - 1) // limit
        open_count = db.scalar(select(func.count()).select_from(Candidate).where(Candidate.status == "potential")) or 0
        return {
            "items": [_admin_candidate(row) for row in rows],
            "total": total,
            "open_count": open_count,
            "page": page,
            "limit": limit,
            "pages": pages,
        }

    @app.post("/api/admin/v1/candidates/{candidate_id}/review")
    def review(
        candidate_id: int,
        payload: ReviewInput,
        db: Session = Depends(get_db),
        context: AuthContext = Depends(require_csrf),
    ) -> dict[str, Any]:
        candidate = _required(db, Candidate, candidate_id)
        decision = payload.decision or {
            "confirm": "publish",
            "publish": "publish",
            "false_positive": "false_positive",
            "dismiss": "close",
            "close": "close",
        }.get(payload.action or "")
        if decision is None:
            raise HTTPException(status_code=422, detail="review decision is required")
        note = (payload.note or payload.reason or "").strip()
        try:
            if decision == "restore":
                event = restore_candidate(
                    db,
                    candidate,
                    admin_id=context.admin.id,
                    reason=note or "Restored by analyst",
                )
                return _review_event(event)
            event = review_candidate(
                db,
                candidate,
                admin_id=context.admin.id,
                action=decision,
                reason=note or f"{decision.replace('_', ' ').title()} by analyst",
                suppress=payload.suppress if payload.suppress is not None else decision == "false_positive",
                suppression_scope=payload.suppression_scope,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return _review_event(event)

    @app.get("/api/admin/v1/candidates/{candidate_id}")
    def candidate_detail(
        candidate_id: int,
        db: Session = Depends(get_db),
        _context: AuthContext = Depends(require_admin),
    ) -> dict[str, Any]:
        candidate = db.scalar(
            select(Candidate)
            .options(
                selectinload(Candidate.target),
                selectinload(Candidate.observations),
                selectinload(Candidate.review_events),
            )
            .where(Candidate.id == candidate_id)
        )
        if candidate is None:
            raise HTTPException(status_code=404, detail="candidate not found")
        payload = _admin_candidate(candidate)
        payload["observations"] = [
            {
                "provider": row.provider,
                "observed_at": _iso(row.observed_at),
                "reference": _safe_provider_reference(row.reference),
                "payload": _admin_evidence(row.payload),
            }
            for row in sorted(candidate.observations, key=lambda item: item.observed_at, reverse=True)[:100]
        ]
        payload["review_events"] = [
            _review_event(row)
            for row in sorted(candidate.review_events, key=lambda item: item.created_at, reverse=True)[:100]
        ]
        payload["suppressions"] = [
            _suppression(row)
            for row in db.scalars(
                select(Suppression)
                .where(Suppression.candidate_id == candidate.id)
                .order_by(Suppression.created_at.desc())
            )
        ]
        return payload

    @app.post("/api/admin/v1/candidates/{candidate_id}/restore")
    def restore(
        candidate_id: int,
        payload: RestoreInput,
        db: Session = Depends(get_db),
        context: AuthContext = Depends(require_csrf),
    ) -> dict[str, Any]:
        try:
            event = restore_candidate(
                db, _required(db, Candidate, candidate_id), admin_id=context.admin.id, reason=payload.reason
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return _review_event(event)

    @app.get("/api/admin/v1/pivots")
    def pivots(db: Session = Depends(get_db), _context: AuthContext = Depends(require_admin)) -> list[dict[str, Any]]:
        rows = db.scalars(select(PivotJob).order_by(PivotJob.created_at.desc()).limit(250))
        return [_pivot(row) for row in rows]

    @app.post("/api/admin/v1/pivots", status_code=201)
    def queue_pivot(
        payload: PivotInput,
        request: Request,
        response: Response,
        db: Session = Depends(get_db),
        _context: AuthContext = Depends(require_csrf),
    ) -> dict[str, Any]:
        if payload.domain:
            try:
                domain = normalize_domain(payload.domain)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            decision = match_domain(domain, active_targets(db), active_suppressions(db))
            if not decision.accepted:
                raise HTTPException(status_code=422, detail=f"domain rejected: {decision.rejected_reason}")
            candidate = ingest_observable(
                db,
                domain,
                provider="manual",
                payload={"analyst_note": (payload.note or "")[:500]},
                decision=decision,
            )
            if candidate is None:
                raise HTTPException(status_code=422, detail="domain did not match exactly one watch target")
        elif payload.candidate_id is not None:
            candidate = _required(db, Candidate, payload.candidate_id)
        else:
            raise HTTPException(status_code=422, detail="domain or candidate_id is required")

        selected = payload.providers or ([payload.provider] if payload.provider else [])
        # Keep user order while removing duplicate provider names.
        selected = list(dict.fromkeys(selected))[:5]
        if not selected:
            raise HTTPException(status_code=422, detail="select at least one passive provider")
        settings: Settings = request.app.state.settings
        jobs: list[PivotJob] = []
        skipped: list[str] = []
        for kind in selected:
            if kind not in PASSIVE_PIVOT_PROVIDERS:
                skipped.append(kind)
                continue
            provider = db.scalar(select(Provider).where(Provider.kind == kind))
            configured = bool(
                provider
                and provider.enabled
                and (provider.secret_ciphertext or _provider_environment_secret(kind, settings))
            )
            if not configured:
                skipped.append(kind)
                continue
            existing = db.scalar(
                select(PivotJob.id).where(
                    PivotJob.candidate_id == candidate.id,
                    PivotJob.provider == kind,
                    PivotJob.state.in_(["queued", "running"]),
                )
            )
            if existing is not None:
                skipped.append(kind)
                continue
            job = PivotJob(
                candidate_id=candidate.id,
                provider=kind,
                parameters={"analyst_note": (payload.note or "")[:500]},
            )
            db.add(job)
            jobs.append(job)
        db.flush()
        if not jobs:
            response.status_code = status.HTTP_200_OK
        return {
            "candidate_id": candidate.id,
            "domain": candidate.defanged_value,
            "queued": [_pivot(job) for job in jobs],
            "queued_providers": [job.provider for job in jobs],
            "skipped_providers": skipped,
            "outcome": "queued" if jobs else "no_provider_job",
        }

    @app.get("/api/admin/v1/runs")
    def runs(db: Session = Depends(get_db), _context: AuthContext = Depends(require_admin)) -> list[dict[str, Any]]:
        rows = db.scalars(select(CollectionRun).order_by(CollectionRun.started_at.desc()).limit(250))
        return [
            {
                "id": row.id,
                "provider": row.provider,
                "state": row.state,
                "stats": row.stats,
                "error": row.error,
                "started_at": _iso(row.started_at),
                "finished_at": _iso(row.finished_at),
            }
            for row in rows
        ]

    @app.get("/api/admin/v1/suppressions")
    def suppressions(
        db: Session = Depends(get_db), _context: AuthContext = Depends(require_admin)
    ) -> list[dict[str, Any]]:
        return [_suppression(row) for row in db.scalars(select(Suppression).order_by(Suppression.created_at.desc()))]

    @app.post("/api/admin/v1/suppressions", status_code=201)
    def add_suppression(
        payload: SuppressionInput,
        db: Session = Depends(get_db),
        context: AuthContext = Depends(require_csrf),
    ) -> dict[str, Any]:
        if payload.target_id is not None:
            _required(db, WatchTarget, payload.target_id)
        pattern = payload.pattern.lower().strip()
        if payload.match_type != "glob":
            try:
                pattern = normalize_domain(pattern)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        elif not set(pattern) <= set("abcdefghijklmnopqrstuvwxyz0123456789-*?."):
            raise HTTPException(status_code=422, detail="glob contains unsupported characters")
        item = Suppression(
            pattern=pattern,
            match_type=payload.match_type,
            target_id=payload.target_id,
            reason=payload.reason,
            created_by=context.admin.id,
        )
        db.add(item)
        db.flush()
        return _suppression(item)

    @app.delete("/api/admin/v1/suppressions/{suppression_id}", status_code=204)
    def disable_suppression(
        suppression_id: int,
        db: Session = Depends(get_db),
        _context: AuthContext = Depends(require_csrf),
    ) -> None:
        item = _required(db, Suppression, suppression_id)
        item.enabled = False


def register_frontend(app: FastAPI) -> None:
    """Serve the dependency-free public and operator pages from the package."""
    package_dir = Path(__file__).resolve().parent
    template_dir = package_dir / "templates"
    static_dir = package_dir / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
    templates = Jinja2Templates(directory=template_dir) if template_dir.is_dir() else None

    @app.get("/", include_in_schema=False)
    def public_page(request: Request) -> Response:
        if templates is None or not (template_dir / "index.html").is_file():
            return Response("Open Domain Radar UI is not installed", media_type="text/plain", status_code=503)
        return templates.TemplateResponse(request, "index.html", {"product_name": "Open Domain Radar"})

    @app.get("/admin", include_in_schema=False)
    def admin_page(request: Request) -> Response:
        if templates is None or not (template_dir / "admin.html").is_file():
            return Response("Operator UI is not installed", media_type="text/plain", status_code=503)
        return templates.TemplateResponse(request, "admin.html", {"product_name": "Open Domain Radar"})


def _enforce_auth_origin(request: Request) -> None:
    """Allow login only from the configured origin or local CLI-style clients."""
    origin = request.headers.get("Origin")
    expected = request.app.state.settings.public_origin
    if origin and origin.rstrip("/") != expected:
        raise HTTPException(status_code=403, detail="origin rejected")
    if not origin:
        # Browsers send Origin for the admin login request. The exception keeps
        # local health tests and loopback tools usable without opening a remote
        # no-Origin login path.
        host = request.client.host if request.client else ""
        if host not in {"127.0.0.1", "::1", "localhost", "testclient"}:
            raise HTTPException(status_code=403, detail="Origin header required")


def _issue_login(response: Response, settings: Settings, db: Session, admin: Admin) -> dict[str, Any]:
    """Create a session and attach its strict cookies to the login response."""
    tokens = create_session(db, admin, settings.session_hours)
    # JavaScript never needs the session token; limiting its path and marking it
    # HttpOnly reduces exposure. The CSRF token must be readable so the UI can
    # copy it into the X-CSRF-Token header for double-submit validation.
    response.set_cookie(
        SESSION_COOKIE,
        tokens.session_token,
        max_age=settings.session_hours * 3600,
        path="/api/admin/v1",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )
    response.set_cookie(
        CSRF_COOKIE,
        tokens.csrf_token,
        max_age=settings.session_hours * 3600,
        path="/",
        secure=settings.cookie_secure,
        httponly=False,
        samesite="strict",
    )
    return {
        "authenticated": True,
        "username": admin.username,
        "expires_at": _iso(tokens.expires_at),
        "csrf_token": tokens.csrf_token,
    }


def _validated_target(payload: TargetInput) -> dict[str, Any]:
    return {
        "name": payload.name.strip(),
        "aliases": _aliases(payload.aliases),
        "keywords": _aliases(payload.keywords),
        "official_domains": _domains(payload.official_domains),
        "country": payload.country.upper() if payload.country else None,
        "minimum_score": payload.minimum_score,
        "enabled": payload.enabled,
    }


def _aliases(values: list[str]) -> list[str]:
    stripped_values = {value.strip() for value in values if value.strip()}
    if any(not 2 <= len(value) <= 100 for value in stripped_values):
        raise HTTPException(status_code=422, detail="aliases must contain 2 to 100 characters")
    return sorted(stripped_values)


def _domains(values: list[str]) -> list[str]:
    try:
        return sorted({normalize_domain(value) for value in values})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _validated_provider_config(kind: str, config: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "certstream": {"collection_seconds": (5, 900)},
        "urlscan": {"result_limit": (1, 100)},
        "virustotal": {"result_limit": (1, 40)},
    }[kind]
    if set(config) - set(allowed):
        raise HTTPException(status_code=422, detail="provider config contains unsupported fields")
    output: dict[str, int] = {}
    for key, value in config.items():
        low, high = allowed[key]
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise HTTPException(status_code=422, detail=f"{key} must be between {low} and {high}")
        output[key] = value
    return output


def _provider_environment_secret(kind: str, settings: Settings) -> str | None:
    """Return an optional environment credential for a passive provider."""
    if kind == "urlscan":
        return settings.urlscan_api_key
    if kind == "virustotal":
        return settings.virustotal_api_key
    return None


def _provider(provider: Provider, settings: Settings) -> dict[str, Any]:
    env_key = _provider_environment_secret(provider.kind, settings)
    credential_configured = bool(env_key or provider.secret_ciphertext)
    configured = provider.kind == "certstream" or credential_configured
    credential_source = "environment" if env_key else "stored" if provider.secret_ciphertext else "none"
    if not provider.enabled:
        status_value = "disabled"
    elif provider.kind == "certstream":
        status_value = provider.last_status or "ready"
    elif not credential_configured:
        status_value = "needs_key"
    else:
        status_value = provider.last_status or "ready"
    return {
        "name": provider.kind,
        "kind": provider.kind,
        "enabled": provider.enabled,
        "config": provider.config,
        "configured": configured,
        "has_secret": credential_configured,
        "credential_configured": credential_configured,
        "credential_source": credential_source,
        "status": status_value,
        "last_status": provider.last_status,
        "message": provider.last_message,
        "last_message": provider.last_message,
        "last_run": _iso(provider.last_run_at),
        "last_run_at": _iso(provider.last_run_at),
    }


def _target(row: WatchTarget) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "aliases": row.aliases,
        "keywords": row.keywords,
        "official_domains": row.official_domains,
        "country": row.country,
        "minimum_score": row.minimum_score,
        "enabled": row.enabled,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
    }


def _public_candidate(row: Candidate) -> dict[str, Any]:
    first_seen = _iso(row.first_seen_at)
    last_seen = _iso(row.last_seen_at)
    # A few aliases remain for clients built against the early preview API.
    # They all carry the same defanged domain and timestamps.
    return {
        "id": row.id,
        "observable": row.defanged_value,
        "domain": row.defanged_value,
        "type": row.value_type,
        "target": row.target.name if row.target else None,
        "status": row.status,
        "confidence": row.confidence,
        "score": row.confidence,
        "reasons": row.reasons,
        "sources": row.sources,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "firstSeen": first_seen,
        "lastSeen": last_seen,
    }


def _admin_candidate(row: Candidate) -> dict[str, Any]:
    # Even the admin UI receives defanged observables to prevent accidental navigation.
    return _public_candidate(row)


_EVIDENCE_FIELDS = {
    "all_domains",
    "certificate_name",
    "country",
    "date",
    "domain",
    "host_name",
    "ip_address",
    "observable",
    "observed_at",
    "resolution_id",
    "scan_id",
    "sha256",
    "status_code",
    "truncated",
}
_DOMAIN_EVIDENCE_FIELDS = {"all_domains", "certificate_name", "domain", "host_name", "observable"}


def _admin_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a bounded, defanged projection instead of arbitrary provider payloads."""
    projected: dict[str, Any] = {}
    for key in sorted(_EVIDENCE_FIELDS & set(payload)):
        value = payload[key]
        if key in _DOMAIN_EVIDENCE_FIELDS:
            projected[key] = _defanged_evidence_domains(value)
        elif key == "ip_address" and isinstance(value, str):
            projected[key] = value[:64].replace(".", "[.]")
        elif isinstance(value, (str, int, float, bool)) or value is None:
            projected[key] = value[:500] if isinstance(value, str) else value
    return projected


def _defanged_evidence_domains(value: Any) -> str | list[str] | None:
    """Normalize and defang at most 100 domains from one evidence field."""
    input_was_list = isinstance(value, list)
    input_values = value if input_was_list else [value]
    safe_values: list[str] = []
    for item in input_values[:100]:
        if not isinstance(item, str):
            continue
        try:
            _canonical, _value_type, domain = normalize_observable(item.removeprefix("*."))
        except ValueError:
            continue
        safe_values.append(defang(domain))

    if input_was_list:
        return safe_values
    return safe_values[0] if safe_values else None


def _safe_provider_reference(value: str | None) -> str | None:
    """Allow only canonical URLScan result pages as clickable references."""
    if not value:
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme == "https"
        and parsed.hostname == "urlscan.io"
        and port is None
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
        and re.fullmatch(r"/result/[A-Za-z0-9-]{12,80}/", parsed.path)
    ):
        return value
    return None


def _review_event(row: ReviewEvent) -> dict[str, Any]:
    return {
        "id": row.id,
        "candidate_id": row.candidate_id,
        "action": row.action,
        "previous_status": row.previous_status,
        "new_status": row.new_status,
        "reason": row.reason,
        "created_at": _iso(row.created_at),
    }


def _pivot(row: PivotJob) -> dict[str, Any]:
    return {
        "id": row.id,
        "candidate_id": row.candidate_id,
        "provider": row.provider,
        "domain": row.candidate.defanged_value,
        "state": row.state,
        "attempts": row.attempts,
        "last_error": row.last_error,
        "created_at": _iso(row.created_at),
        "finished_at": _iso(row.finished_at),
    }


def _suppression(row: Suppression) -> dict[str, Any]:
    return {
        "id": row.id,
        "pattern": row.pattern,
        "match_type": row.match_type,
        "target_id": row.target_id,
        "candidate_id": row.candidate_id,
        "reason": row.reason,
        "enabled": row.enabled,
        "expires_at": _iso(row.expires_at),
    }


def _required(db: Session, model: type[Any], identifier: int) -> Any:
    """Load a model by primary key or return the API's generic 404."""
    row = db.get(model, identifier)
    if row is None:
        raise HTTPException(status_code=404, detail="record not found")
    return row


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.isoformat().replace("+00:00", "Z")


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _model_dump(model: BaseModel, **kwargs: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(**kwargs)
    return model.dict(**kwargs)
