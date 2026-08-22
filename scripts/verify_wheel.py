"""Build in a clean directory and smoke-test the installed wheel."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_MEMBERS = {
    "open_domain_radar/templates/index.html",
    "open_domain_radar/templates/admin.html",
    "open_domain_radar/static/styles.css",
    "open_domain_radar/static/public.js",
    "open_domain_radar/static/admin.js",
    "open_domain_radar/static/mark.svg",
}


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="open-domain-radar-wheel-") as directory:
        output = Path(directory)
        source = output / "source"
        # Building from a copy catches files that only work from the checkout.
        shutil.copytree(
            ROOT,
            source,
            ignore=shutil.ignore_patterns(
                ".git",
                ".venv",
                ".state",
                ".coverage",
                ".mypy_cache",
                ".pytest_cache",
                ".ruff_cache",
                "__pycache__",
                "*.egg-info",
                "build",
                "dist",
                "screenshots",
            ),
        )
        subprocess.run(  # noqa: S603 - controlled interpreter/module argv
            [sys.executable, "-m", "build", "--wheel", "--outdir", str(output)],
            cwd=source,
            check=True,
            capture_output=True,
            text=True,
        )
        wheels = list(output.glob("*.whl"))
        if len(wheels) != 1:
            raise AssertionError(f"expected one wheel, found {len(wheels)}")
        with zipfile.ZipFile(wheels[0]) as archive:
            members = set(archive.namelist())
        missing = sorted(REQUIRED_MEMBERS - members)
        if missing:
            raise AssertionError(f"wheel is missing packaged UI assets: {', '.join(missing)}")

        installed = output / "installed"
        # Install without dependencies so imports must come from this wheel.
        subprocess.run(  # noqa: S603 - controlled interpreter/module argv
            [sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(installed), str(wheels[0])],
            cwd=output,
            check=True,
            capture_output=True,
            text=True,
        )
        smoke_state = output / "smoke-state"
        smoke_code = """
from fastapi.testclient import TestClient
from open_domain_radar.api import create_app
from open_domain_radar.config import Settings

client = TestClient(create_app(Settings.from_env()))
for path in ('/', '/admin', '/static/styles.css', '/static/public.js', '/static/admin.js', '/static/mark.svg'):
    response = client.get(path)
    assert response.status_code == 200, (path, response.status_code)
"""
        environment = os.environ.copy()
        environment.update(
            {
                "ODR_DATA_DIR": str(smoke_state),
                "ODR_PUBLIC_ORIGIN": "http://127.0.0.1:8787",
                "PYTHONPATH": str(installed),
            }
        )
        subprocess.run(  # noqa: S603 - controlled interpreter argv
            [sys.executable, "-c", smoke_code],
            cwd=output,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
    print(f"Wheel verification passed ({len(REQUIRED_MEMBERS)} packaged UI assets and 6 smoke routes).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
