# syntax=docker/dockerfile:1
# Base image is pinned by digest so upstream tags can never silently change
# under us (supply-chain hardening). To bump: docker pull python:3.13-slim,
# copy the new RepoDigests value, update this line, and run the CI Trivy scan.
FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Pull current Debian security updates. The pinned base tag lags the archive
# between rebuilds, so this keeps the CI Trivy HIGH/CRITICAL gate green by
# actually patching packages rather than suppressing findings.
RUN apt-get update \
    && apt-get -y upgrade \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY bastionfw/pyproject.toml bastionfw/README.md ./
COPY bastionfw/requirements.lock ./requirements.lock
COPY bastionfw/ed_bt_ade ./ed_bt_ade

# Install from the hash-pinned lock file: every artifact is verified against
# its recorded sha256 before installation (pip refuses mismatches), then the
# application itself is installed without re-resolving dependencies.
# pip is build-time only; the dashboard runs from source with no pip call.
# Removing it drops pip's vendored msgpack/urllib3/setuptools (flagged by
# Trivy) and shrinks the runtime attack surface.
RUN pip install --no-cache-dir --require-hashes -r requirements.lock \
    && pip install --no-cache-dir --no-deps . \
    && rm -rf /usr/local/lib/python3.13/site-packages/pip \
              /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
              /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13 \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin bastionfw \
    && mkdir -p /var/lib/bastionfw \
    && chown -R bastionfw:bastionfw /app /var/lib/bastionfw

COPY bastionfw/config.container.json ./config.container.json

USER bastionfw
EXPOSE 8080 9109

ENTRYPOINT ["python", "-m", "ed_bt_ade.dashboard"]
CMD ["--config", "/app/config.container.json", "--host", "0.0.0.0", "--port", "8080"]
