"""Regenerate reviewed Python 3.12 locks with an explicitly pinned resolver."""

import argparse
import hashlib
import importlib.metadata
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UV_VERSION = "0.12.5"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    manifest_path = ROOT / "requirements" / "lock-manifest.json"
    files = ["pyproject.toml", "requirements/runtime-py312.lock", "requirements/dev-py312.lock"]
    if args.check:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for name in files:
            normalized = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
            if hashlib.sha256(normalized).hexdigest() != manifest["files"].get(name):
                raise SystemExit(f"Dependency lock drift: {name}; regenerate and review the full set")
        print("Dependency sources and both normalized locks match the reviewed manifest.")
        return
    if importlib.metadata.version("uv") != UV_VERSION:
        raise SystemExit(f"Install uv=={UV_VERSION} before regenerating locks")
    for name, extra in (("runtime", []), ("dev", ["--extra", "dev"])):
        subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-m",
                "uv",
                "pip",
                "compile",
                "pyproject.toml",
                "--python-version",
                "3.12",
                "--universal",
                "--generate-hashes",
                *extra,
                "--custom-compile-command",
                "python scripts/lock_dependencies.py (uv 0.12.5; Python 3.12)",
                "--output-file",
                f"requirements/{name}-py312.lock",
                "--quiet",
            ],
            cwd=ROOT,
            check=True,
        )
    manifest = {
        "python": "3.12",
        "resolver": f"uv {UV_VERSION}",
        "files": {
            name: hashlib.sha256((ROOT / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest() for name in files
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
