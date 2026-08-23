FROM python:3.14.7-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ODR_DATA_DIR=/data

RUN addgroup --system radar && adduser --system --ingroup radar --home /app radar

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE THIRD-PARTY-NOTICES.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

RUN mkdir /data && chown radar:radar /data
USER radar

EXPOSE 8787
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/health/ready', timeout=3)"]

CMD ["open-domain-radar", "serve", "--host", "0.0.0.0", "--port", "8787"]
