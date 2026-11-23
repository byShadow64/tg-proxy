# syntax=docker/dockerfile:1.7

# Multi-architecture digest from the Docker Official Images publication.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv

WORKDIR /app
COPY docker-requirements.lock helper_registry_requirements.txt ./
RUN python -m venv "$VIRTUAL_ENV" \
    && "$VIRTUAL_ENV/bin/pip" install --only-binary=:all: --require-hashes -r docker-requirements.lock \
    && "$VIRTUAL_ENV/bin/pip" check

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    TG_WS_PROXY_HOST=0.0.0.0 \
    TG_WS_PROXY_PORT=1443 \
    TG_WS_PROXY_SECRET=""  \
    TG_WS_PROXY_SECRET_FILE="" \
    TG_WS_PROXY_DC_IPS="2:149.154.167.220 4:149.154.167.220" \
    TG_WS_PROXY_CF_WORKER=""

RUN apt-get update \
    && apt-get install -y --no-install-recommends tini ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home --home-dir /home/app app

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY proxy ./proxy
COPY utils ./utils
COPY docs/README.md LICENSE ./

USER app

EXPOSE 1443/tcp

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/venv/bin/python", "-m", "proxy.docker_entrypoint"]
CMD []
