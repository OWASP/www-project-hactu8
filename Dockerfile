# HACTU8: the API, the 46 labs and the built console in one image (H-50).
# See docs/deploy.md. Nothing here bakes in a secret: keys arrive at run time
# through an env_file kept outside the repo.
#
#   docker compose up --build          # API and console on http://127.0.0.1:8000
#
# Targets: runtime (default, last) and dev (the devcontainer, H-51).

ARG PYTHON_IMAGE=python:3.14.10-slim-trixie
ARG NODE_IMAGE=node:24.22.3-trixie-slim

# Console: Vite + React build. "/" makes it call the API on its own origin.
FROM ${NODE_IMAGE} AS console
WORKDIR /console
COPY spikes/iac-prototype/iac-host/package.json spikes/iac-prototype/iac-host/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY spikes/iac-prototype/iac-host/ ./
ARG VITE_HACTU8_API_URL=/
RUN VITE_HACTU8_API_URL=${VITE_HACTU8_API_URL} npm run build

# Base: Python, pinned dependencies in /opt/venv, an unprivileged user.
FROM ${PYTHON_IMAGE} AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app \
    HACTU8_ROOT=/app
COPY docker/requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
    && pip install -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt \
    && useradd --create-home --uid 10001 --shell /bin/bash hactu8 \
    && mkdir -p /app /data \
    && chown hactu8:hactu8 /data
WORKDIR /app

# Dev: adds Node for the console, git, and sudo for the devcontainer's setup.
# The workspace is bind-mounted at /app, so no source is copied.
FROM base AS dev
COPY --from=console /usr/local/bin/node /usr/local/bin/node
COPY --from=console /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && apt-get update \
    && apt-get install -y --no-install-recommends git sudo \
    && rm -rf /var/lib/apt/lists/* \
    && echo "hactu8 ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/hactu8 \
    && chmod 0440 /etc/sudoers.d/hactu8 \
    && chown -R hactu8:hactu8 /opt/venv
USER hactu8

# Runtime: source and console. Core is read-only to the app user; the labs keep
# per-run state in their own folders, so demos/ is theirs. Results go to /data.
FROM base AS runtime
COPY pyproject.toml README.md branding.yaml hactu8.yaml ./
COPY hactu8/ hactu8/
COPY --chown=hactu8:hactu8 demos/ demos/
COPY tests/ tests/
COPY scripts/ scripts/
COPY --from=console /console/dist/ console/
ENV HACTU8_HOME=/data \
    HACTU8_CONSOLE_DIR=/app/console \
    OLLAMA_HOST=http://host.docker.internal:11434
USER hactu8
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"]
# 0.0.0.0 inside the container's own network namespace, so Docker can forward
# to it; compose publishes it on the host's 127.0.0.1 only.
CMD ["python", "-m", "uvicorn", "hactu8.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
