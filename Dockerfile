FROM python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ODR_DATA_DIR=/data

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE THIRD-PARTY-NOTICES.md ./
COPY src ./src
COPY requirements ./requirements
RUN python -m pip install --no-cache-dir --require-hashes -r requirements/dev-py312.lock && \
    python -m pip wheel --no-deps --no-build-isolation --wheel-dir /tmp/wheels . && \
    python -m venv /opt/radar && \
    /opt/radar/bin/pip install --no-cache-dir --require-hashes -r requirements/runtime-py312.lock && \
    /opt/radar/bin/pip install --no-deps /tmp/wheels/*.whl
ENV PATH="/opt/radar/bin:$PATH"

FROM python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ODR_DATA_DIR=/data \
    PATH="/opt/radar/bin:$PATH"
COPY --from=builder /opt/radar /opt/radar
RUN addgroup --system radar && adduser --system --ingroup radar --home /app radar
WORKDIR /app
RUN mkdir /data && chown radar:radar /data
USER radar

EXPOSE 8787
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/health/ready', timeout=3)"]

CMD ["open-domain-radar", "serve", "--host", "0.0.0.0", "--port", "8787"]
