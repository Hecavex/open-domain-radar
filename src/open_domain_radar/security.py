"""Authentication, secret encryption, validation and safe public rendering."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import math
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .models import Admin, AdminSession

_HOST_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,80}$")
_PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
# Unknown users still run one real Argon2 verification. This keeps the login
# response from revealing whether an account name exists through timing alone.
_DUMMY_PASSWORD_HASH = _PASSWORD_HASHER.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    """Validate and hash an operator password with the project Argon2 policy."""
    if len(password) < 12 or len(password) > 512:
        raise ValueError("password must contain 12 to 512 characters")
    return _PASSWORD_HASHER.hash(password)


def validate_username(username: str) -> str:
    value = username.strip()
    if not _USERNAME_RE.fullmatch(value):
        raise ValueError("username must contain 3 to 80 letters, digits, dots, underscores or hyphens")
    return value


def verify_password(encoded: str | None, password: str) -> bool:
    """Verify a password without taking a faster path for unknown usernames."""
    try:
        return _PASSWORD_HASHER.verify(encoded or _DUMMY_PASSWORD_HASH, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def token_hash(value: str) -> str:
    """Create the one-way value stored for session and CSRF tokens."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_domain(value: str) -> str:
    """Return one lowercase ASCII hostname, or reject malformed input."""
    candidate = value.strip().lower().rstrip(".")
    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or ""
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid internationalized domain") from exc
    if not _HOST_RE.fullmatch(candidate) or ".." in candidate:
        raise ValueError("invalid domain")
    return candidate


def normalize_observable(value: str) -> tuple[str, str, str]:
    """Reduce an HTTP(S) URL or hostname to its domain-only candidate identity."""
    value = value.strip()
    if len(value) > 2048:
        raise ValueError("observable is too long")
    if any(character in value for character in "\r\n\t"):
        raise ValueError("observable contains control characters")
    if "://" not in value:
        domain = normalize_domain(value.removeprefix("*."))
        return domain, "domain", domain
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("only HTTP(S) observables are accepted")
    if parsed.username or parsed.password:
        raise ValueError("credentials are not accepted in observables")
    domain = normalize_domain(parsed.hostname)
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("observable contains an invalid port") from exc
    if parsed_port not in {None, 80, 443}:
        raise ValueError("non-default ports are not accepted in observables")
    # Paths, queries, and fragments commonly contain credentials, victim
    # identifiers, reset tokens, and campaign entropy. Candidate identity is
    # therefore always the normalized domain.
    return domain, "domain", domain


def defang(value: str) -> str:
    """Make a domain or URL non-clickable for safe display."""
    safe = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return safe.replace(".", "[.]").replace("://", "[:]//")


class SecretBox:
    """Encrypt provider credentials before they are stored in the database."""

    def __init__(self, key: bytes):
        self._fernet = Fernet(key)

    @classmethod
    def load(cls, settings: Settings, *, create: bool = False) -> SecretBox:
        """Load the master key from the environment or its private state file."""
        if settings.master_key:
            key = _coerce_fernet_key(settings.master_key)
        elif settings.master_key_path.exists():
            _set_private_permissions(settings.master_key_path.parent, 0o700)
            _set_private_permissions(settings.master_key_path, 0o600)
            key = settings.master_key_path.read_bytes().strip()
        elif create:
            key = write_master_key(settings.master_key_path)
        else:
            raise RuntimeError("master key is missing; run `open-domain-radar keygen` or set ODR_MASTER_KEY")
        try:
            return cls(key)
        except (ValueError, TypeError) as exc:
            raise RuntimeError("invalid master key") from exc

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        try:
            return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise RuntimeError("encrypted provider secret cannot be decrypted") from exc


def _coerce_fernet_key(value: str) -> bytes:
    raw = value.strip().encode("ascii")
    try:
        decoded = base64.urlsafe_b64decode(raw)
    except Exception as exc:
        raise RuntimeError("ODR_MASTER_KEY must be URL-safe base64") from exc
    if len(decoded) != 32:
        raise RuntimeError("ODR_MASTER_KEY must encode exactly 32 bytes")
    return raw


def write_master_key(path: Path, *, force: bool = False) -> bytes:
    """Create a private Fernet key file without replacing it by accident."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _set_private_permissions(path.parent, 0o700)
    if path.exists() and not force:
        _set_private_permissions(path, 0o600)
        return path.read_bytes().strip()
    key = Fernet.generate_key()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(key + b"\n")
    _set_private_permissions(path, 0o600)
    return key


def _set_private_permissions(path: Path, mode: int) -> None:
    """Tighten local state permissions on platforms that implement POSIX modes."""
    with contextlib.suppress(OSError, NotImplementedError):
        os.chmod(path, mode)


@dataclass(frozen=True, slots=True)
class SessionTokens:
    """Raw login tokens returned once to the browser."""

    session_token: str
    csrf_token: str
    expires_at: datetime


class LoginThrottle:
    """Bound login attempts for the supported single-web-process deployment.

    This is deliberately in memory: deployment supports one web process, while
    the reverse proxy provides the first per-client rate-limit layer. The LRU
    bound prevents random peer identifiers from growing memory indefinitely.
    """

    def __init__(
        self,
        *,
        attempts: int = 5,
        window_seconds: int = 300,
        lock_seconds: int = 900,
        max_entries: int = 4096,
    ):
        if min(attempts, window_seconds, lock_seconds, max_entries) < 1:
            raise ValueError("login throttle limits must be positive")
        self.attempts = attempts
        self.window_seconds = window_seconds
        self.lock_seconds = lock_seconds
        self.max_entries = max_entries
        self._failures: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._last_seen: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def retry_after(self, key: str) -> int:
        """Return whole seconds until a peer may try again, or zero."""
        now = time.monotonic()
        with self._lock:
            self._evict_stale(now)
            locked_until = self._locked_until.get(key, 0.0)
            if locked_until <= now:
                return 0
            self._touch(key, now)
            return max(1, math.ceil(locked_until - now))

    def record_failure(self, key: str) -> None:
        """Record a failed login and lock the peer after the configured limit."""
        now = time.monotonic()
        with self._lock:
            self._evict_stale(now)
            self._prune(key, now)
            failures = self._failures.setdefault(key, [])
            failures.append(now)
            if len(failures) >= self.attempts:
                self._locked_until[key] = now + self.lock_seconds
                failures.clear()
            self._touch(key, now)
            self._enforce_bound()

    def reset(self, key: str) -> None:
        """Forget throttle state after a successful login."""
        with self._lock:
            self._drop(key)

    @property
    def tracked_entries(self) -> int:
        """Return the bounded number of peers carrying current throttle state."""
        now = time.monotonic()
        with self._lock:
            self._evict_stale(now)
            return len(self._last_seen)

    def _prune(self, key: str, now: float) -> None:
        cutoff = now - self.window_seconds
        current = [recorded for recorded in self._failures.get(key, []) if recorded >= cutoff]
        if current:
            self._failures[key] = current
        else:
            self._failures.pop(key, None)

    def _evict_stale(self, now: float) -> None:
        # Iterate over a copy because _drop() mutates the OrderedDict.
        for key in list(self._last_seen):
            self._prune(key, now)
            if self._locked_until.get(key, 0.0) <= now:
                self._locked_until.pop(key, None)
            if key not in self._failures and key not in self._locked_until:
                self._drop(key)

    def _touch(self, key: str, now: float) -> None:
        self._last_seen[key] = now
        self._last_seen.move_to_end(key)

    def _enforce_bound(self) -> None:
        while len(self._last_seen) > self.max_entries:
            key, _last_seen = self._last_seen.popitem(last=False)
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)

    def _drop(self, key: str) -> None:
        self._failures.pop(key, None)
        self._locked_until.pop(key, None)
        self._last_seen.pop(key, None)


def create_session(db: Session, admin: Admin, hours: int) -> SessionTokens:
    """Create a session while storing only hashes of browser-visible tokens."""
    session_token = secrets.token_urlsafe(48)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(hours=hours)
    db.add(
        AdminSession(
            admin_id=admin.id,
            token_hash=token_hash(session_token),
            csrf_hash=token_hash(csrf_token),
            expires_at=expires_at,
        )
    )
    db.flush()
    return SessionTokens(session_token, csrf_token, expires_at)


def authenticate_session(db: Session, raw_token: str | None) -> tuple[AdminSession, Admin] | None:
    """Resolve an active session token and its active operator account."""
    if not raw_token:
        return None
    record = db.scalar(select(AdminSession).where(AdminSession.token_hash == token_hash(raw_token)))
    now = datetime.now(UTC)
    if record is None or record.revoked_at is not None or _aware(record.expires_at) <= now:
        return None
    admin = db.get(Admin, record.admin_id)
    if admin is None or not admin.active:
        return None
    return record, admin


def validate_csrf(record: AdminSession, header_token: str | None, cookie_token: str | None) -> bool:
    """Validate the double-submit token and its server-side session binding."""
    # The readable cookie must match the explicit request header, then its hash
    # must match the value bound to the authenticated session in SQLite.
    if not header_token or not cookie_token or not hmac.compare_digest(header_token, cookie_token):
        return False
    return hmac.compare_digest(record.csrf_hash, token_hash(header_token))


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)
