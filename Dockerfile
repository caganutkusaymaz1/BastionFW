# syntax=docker/dockerfile:1
# Base image is pinned by digest so upstream tags can never silently change
# under us (supply-chain hardening). To bump: docker pull python:3.13-slim,
# copy the new RepoDigests value, update this line, and run the CI Trivy scan.
FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY bastionfw/pyproject.toml bastionfw/README.md ./
COPY bastionfw/requirements.lock ./requirements.lock
COPY bastionfw/ed_bt_ade ./ed_bt_ade

# Install from the hash-pinned lock file: every artifact is verified against
# its recorded sha256 before installation (pip refuses mismatches), then the
# application itself is installed without re-resolving dependencies.
RUN pip install --no-cache-dir --require-hashes -r requirements.lock \
    && pip install --no-cache-dir --no-deps . \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin bastionfw \
    && mkdir -p /var/lib/bastionfw \
    && chown -R bastionfw:bastionfw /app /var/lib/bastionfw

COPY bastionfw/config.container.json ./config.container.json

USER bastionfw
EXPOSE 8080 9109

ENTRYPOINT ["python", "-m", "ed_bt_ade.dashboard"]
CMD ["--config", "/app/config.container.json", "--host", "0.0.0.0", "--port", "8080"]
