"""Runtime configuration with deliberately small, explicit environment surface."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import ParseResult, urlparse


def _truthy(value: str | None, default: bool = False) -> bool:
    """Parse the small set of values accepted for boolean environment flags."""
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _bounded_integer(name: str, default: int, minimum: int, maximum: int) -> int:
    """Read an integer setting and keep it inside the supported range."""
    raw_value = os.getenv(name, str(default))
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    return min(max(value, minimum), maximum)


def _is_loopback_host(host: str) -> bool:
    """Return whether a hostname or IP address refers to this machine."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated runtime settings loaded from environment variables."""

    data_dir: Path
    database_url: str
    master_key: str | None
    host: str
    port: int
    public_origin: str
    embed_worker: bool
    session_hours: int
    certstream_url: str
    urlscan_api_key: str | None = None
    virustotal_api_key: str | None = None

    def __post_init__(self) -> None:
        _validate_public_origin(self.public_origin)
        _validate_certstream_url(self.certstream_url)

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from the documented ODR environment variables."""
        data_dir = Path(os.getenv("ODR_DATA_DIR", "./.state")).expanduser().resolve()
        database_url = os.getenv("ODR_DATABASE_URL", f"sqlite:///{data_dir / 'radar.db'}")
        port = _bounded_integer("ODR_PORT", 8787, 1, 65535)
        hours = _bounded_integer("ODR_SESSION_HOURS", 12, 1, 168)
        certstream_url = os.getenv("ODR_CERTSTREAM_URL", "wss://certstream.calidog.io/")
        return cls(
            data_dir=data_dir,
            database_url=database_url,
            master_key=os.getenv("ODR_MASTER_KEY") or None,
            host=os.getenv("ODR_HOST", "127.0.0.1"),
            port=port,
            public_origin=os.getenv("ODR_PUBLIC_ORIGIN", f"http://127.0.0.1:{port}").rstrip("/"),
            embed_worker=_truthy(os.getenv("ODR_EMBED_WORKER")),
            session_hours=hours,
            certstream_url=certstream_url,
            urlscan_api_key=os.getenv("URLSCAN_API_KEY") or None,
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY") or None,
        )

    @property
    def master_key_path(self) -> Path:
        return self.data_dir / "master.key"

    @property
    def cookie_secure(self) -> bool:
        return urlparse(self.public_origin).scheme == "https"

    @property
    def loopback_origin(self) -> bool:
        host = urlparse(self.public_origin).hostname or ""
        return _is_loopback_host(host)


def _parsed_url(value: str, setting_name: str) -> ParseResult:
    """Parse a URL and turn malformed ports into a useful configuration error."""
    parsed = urlparse(value)
    try:
        # Accessing ``port`` performs validation that urlparse itself delays.
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"{setting_name} contains an invalid port") from exc
    return parsed


def _validate_public_origin(value: str) -> None:
    parsed = _parsed_url(value, "ODR_PUBLIC_ORIGIN")
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("ODR_PUBLIC_ORIGIN must be a bare HTTP(S) origin")
    if parsed.scheme != "https" and not _is_loopback_host(parsed.hostname):
        raise ValueError("ODR_PUBLIC_ORIGIN must use HTTPS outside loopback development")


def _validate_certstream_url(value: str) -> None:
    try:
        parsed = _parsed_url(value, "ODR_CERTSTREAM_URL")
        port = parsed.port
    except ValueError as exc:
        raise ValueError("ODR_CERTSTREAM_URL must use the approved CertStream WSS endpoint") from exc
    # This is an SSRF boundary, not a general-purpose WebSocket setting. Keep the
    # scheme, authority, port and upstream path fixed and reject URL decorations.
    if (
        value != value.strip()
        or any(ord(character) < 0x20 or character == "\x7f" for character in value)
        or parsed.scheme != "wss"
        or parsed.hostname != "certstream.calidog.io"
        or parsed.netloc.lower() not in {"certstream.calidog.io", "certstream.calidog.io:443"}
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.path != "/"
        or parsed.params
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
    ):
        raise ValueError("ODR_CERTSTREAM_URL must use the approved CertStream WSS endpoint")
