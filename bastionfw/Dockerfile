FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ED_BT_ADE_DRY_RUN=true

WORKDIR /app
COPY . /app

RUN useradd --create-home --uid 10001 bastionfw \
    && mkdir -p /var/lib/bastionfw \
    && chown -R bastionfw:bastionfw /app /var/lib/bastionfw

USER bastionfw
EXPOSE 8080 9109

CMD ["python", "-m", "ed_bt_ade.dashboard", "--config", "/app/config.container.json", "--host", "0.0.0.0", "--port", "8080"]