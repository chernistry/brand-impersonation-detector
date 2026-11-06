# syntax=docker/dockerfile:1

# Build wheels for the package and every dependency in a throwaway stage, so
# the runtime image carries no compiler, no source tree and no pip cache.
FROM python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54 AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY bid ./bid
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[console]"

FROM python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    BID_DATA_DIR=/data
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install --no-index --find-links /wheels "brand-impersonation-detector[console]" \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin bid \
 && mkdir -p /data \
 && chown 10001 /data

# All runtime state (stores, caches, journals) lives in /data; the root
# filesystem can be mounted read-only.
USER 10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/', timeout=2)" || exit 1
ENTRYPOINT ["bid"]
# Listening beyond loopback needs BID_CONSOLE_TOKEN; the console refuses to start without it.
CMD ["console", "--host", "0.0.0.0", "--port", "8000", "--no-open"]
