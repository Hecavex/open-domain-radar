$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath ".venv")) {
    python -m venv .venv
}

.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\open-domain-radar init
.\.venv\Scripts\open-domain-radar serve
