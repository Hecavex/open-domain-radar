"""Check release files, browser safety rules and accidental secret exposure."""

from __future__ import annotations

import re
import subprocess
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "open_domain_radar"

pytestmark = pytest.mark.release

REQUIRED = (
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "DATA-LICENSE.md",
    "THIRD-PARTY-NOTICES.md",
    "docs/ARCHITECTURE.md",
    "docs/DETECTION.md",
    "docs/PROVIDERS.md",
    "docs/RELEASE-REHEARSAL.md",
    "docs/SECURITY-MODEL.md",
    "docs/images/integrations.png",
    "docs/images/public-dashboard.png",
    "docs/images/review-workflow.png",
    "docs/images/watch-target-editor.png",
    "src/open_domain_radar/templates/index.html",
    "src/open_domain_radar/templates/admin.html",
    "src/open_domain_radar/static/styles.css",
    "src/open_domain_radar/static/public.js",
    "src/open_domain_radar/static/admin.js",
)
FORBIDDEN_RUNTIME = ("hecavex", "swedbank", "lithuania", "hecavex.com")
SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(
        r"(?i)(?:api.?key|access.?token|secret)\s*[:=]\s*['\"]?"
        r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    ),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
TEXT_SUFFIXES = {".css", ".html", ".js", ".json", ".md", ".py", ".toml", ".txt", ".yaml", ".yml"}
MOJIBAKE_SEQUENCES = (
    # These byte sequences are common signs that UTF-8 text was decoded twice.
    "".join(chr(value) for value in (0xE2, 0x20AC, 0xA6)),
    "".join(chr(value) for value in (0xC2, 0xB7)),
)


class DocumentAudit(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: set[str] = set()
        self.errors: list[str] = []
        self.has_main = False
        self.has_title = False
        self.has_lang = False
        self.inline_script_depth = 0
        self.inline_script_text = ""
        self.inline_style_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        identifier = values.get("id")
        if identifier:
            if identifier in self.ids:
                self.errors.append(f"duplicate id: {identifier}")
            self.ids.add(identifier)
        if any(name.lower().startswith("on") for name in values):
            self.errors.append(f"inline event handler on <{tag}>")
        if "style" in values:
            self.errors.append(f"inline style on <{tag}>")
        if tag == "html":
            self.has_lang = bool(values.get("lang"))
        elif tag == "main":
            self.has_main = True
        elif tag == "title":
            self.has_title = True
        elif tag == "script" and not values.get("src"):
            self.inline_script_depth += 1
        elif tag == "style":
            self.inline_style_depth += 1
        if tag == "a":
            href = values.get("href") or ""
            parsed = urlsplit(href)
            if parsed.scheme in {"http", "https"} and "candidate" in (values.get("class") or ""):
                self.errors.append("candidate link must not be live")

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self.inline_script_depth:
            self.inline_script_depth -= 1
        elif tag == "style" and self.inline_style_depth:
            self.inline_style_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.inline_script_depth and data.strip():
            self.inline_script_text += data


def fail(message: str) -> None:
    raise AssertionError(message)


def read_text(path: Path) -> str:
    try:
        value = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        fail(f"not UTF-8: {path.relative_to(ROOT)}: {exc}")
    if "\ufffd" in value or any(sequence in value for sequence in MOJIBAKE_SEQUENCES):
        fail(f"encoding damage: {path.relative_to(ROOT)}")
    return value


def test_required_project_files() -> None:
    missing = [path for path in REQUIRED if not (ROOT / path).is_file()]
    if missing:
        fail(f"required project files missing: {', '.join(missing)}")


def test_runtime_identity_is_brand_neutral() -> None:
    for root in (PACKAGE / "templates", PACKAGE / "static"):
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            lowered = read_text(path).lower()
            hits = [token for token in FORBIDDEN_RUNTIME if token in lowered]
            if hits:
                fail(f"brand-specific runtime text in {path.relative_to(ROOT)}: {hits}")


def test_html_documents_preserve_safety_and_accessibility_boundaries() -> None:
    for path in (PACKAGE / "templates").glob("*.html"):
        parser = DocumentAudit()
        parser.feed(read_text(path))
        errors = list(parser.errors)
        if not parser.has_lang:
            errors.append("missing html lang")
        if not parser.has_title:
            errors.append("missing title")
        if not parser.has_main:
            errors.append("missing main")
        if parser.inline_script_text.strip():
            errors.append("inline script violates CSP")
        if parser.inline_style_depth:
            errors.append("inline style block violates CSP")
        if errors:
            fail(f"{path.relative_to(ROOT)}: {'; '.join(errors)}")


def test_javascript_avoids_unsafe_runtime_patterns() -> None:
    for path in (PACKAGE / "static").glob("*.js"):
        value = read_text(path)
        for pattern in (r"\beval\s*\(", r"\bFunction\s*\(", r"document\.write\s*\("):
            if re.search(pattern, value):
                fail(f"unsafe JavaScript pattern {pattern!r} in {path.relative_to(ROOT)}")
        if re.search(r"(?:local|session)Storage\.setItem\([^\n]*(?:api.?key|secret|token)", value, re.IGNORECASE):
            fail(f"browser storage receives secret-like material in {path.relative_to(ROOT)}")


def repository_files() -> list[Path]:
    """Return source material while excluding ignored local state.

    Git is the source of truth in normal development and CI. The fallback is
    useful when the tests are copied outside a checkout, such as during a
    source-package inspection.
    """

    try:
        result = subprocess.run(  # noqa: S603 - fixed git command over this checkout
            ["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        ignored_parts = {
            ".git",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".state",
            ".venv",
            "__pycache__",
            "backups",
            "build",
            "dist",
            "exports",
            "htmlcov",
            "instance",
            "screenshots",
            "secrets",
        }
        return [
            path
            for path in ROOT.rglob("*")
            if path.is_file() and not any(part in ignored_parts for part in path.relative_to(ROOT).parts)
        ]

    return [ROOT / relative for relative in result.stdout.split("\0") if relative]


def test_repository_material_contains_no_runtime_state_or_obvious_secrets() -> None:
    """Reject runtime state and obvious credentials before a commit is published."""

    for path in repository_files():
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if path.suffix.lower() in {".db", ".key", ".pem", ".sqlite", ".sqlite3"}:
            fail(f"runtime secret/state file present: {relative}")
        if path.stat().st_size > 512 * 1024 and path.suffix.lower() in TEXT_SUFFIXES:
            fail(f"unexpected oversized source file: {relative}")
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {"NOTICE", "LICENSE"}:
            text = read_text(path)
            for pattern in SECRET_PATTERNS:
                if pattern.search(text):
                    fail(f"credential/private-key pattern in {relative}")
