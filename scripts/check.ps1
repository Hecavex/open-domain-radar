$ErrorActionPreference = "Stop"

python -m ruff check .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -m ruff format --check .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -m mypy
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -m pytest --cov=open_domain_radar --cov-report=term-missing
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python scripts/verify_project.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python scripts/verify_wheel.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python scripts/test_responsive.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Open Domain Radar verification passed."
