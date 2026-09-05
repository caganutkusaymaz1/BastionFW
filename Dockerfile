FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY bastionfw/pyproject.toml bastionfw/README.md ./
COPY bastionfw/ed_bt_ade ./ed_bt_ade

RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin bastionfw \
    && mkdir -p /var/lib/bastionfw \
    && chown -R bastionfw:bastionfw /app /var/lib/bastionfw

COPY bastionfw/config.container.json ./config.container.json

USER bastionfw
EXPOSE 8080 9109

ENTRYPOINT ["python", "-m", "ed_bt_ade.dashboard"]
CMD ["--config", "/app/config.container.json", "--host", "0.0.0.0", "--port", "8080"]
