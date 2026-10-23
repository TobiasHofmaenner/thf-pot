# syntax=docker/dockerfile:1.7

# DB-IP Lite geolocation (CC BY 4.0, attribution on the map). Fetched at build time so the pods
# need no egress; GEO_MONTH is passed by CI so the layer is rebuilt once a month, not cached forever.
FROM debian:trixie-slim AS geo
ARG GEO_MONTH=unset
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN set -e; mkdir -p /geo; \
    for m in $(date -u +%Y-%m) $(date -u -d "$(date -u +%Y-%m-15) -1 month" +%Y-%m); do \
      if curl -fsSL "https://download.db-ip.com/free/dbip-city-lite-$m.mmdb.gz" | gunzip > /geo/dbip-city-lite.mmdb \
      && curl -fsSL "https://download.db-ip.com/free/dbip-asn-lite-$m.mmdb.gz" | gunzip > /geo/dbip-asn-lite.mmdb; then \
        echo "$m" > /geo/VERSION; break; fi; done; \
    test -s /geo/dbip-city-lite.mmdb && test -s /geo/dbip-asn-lite.mmdb && echo "geo: $(cat /geo/VERSION) ($GEO_MONTH)"

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --uid 10001 --user-group --system --shell /usr/sbin/nologin hub
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
COPY --from=geo /geo /app/geo
ARG APP_VERSION=dev
ENV APP_VERSION=$APP_VERSION DJANGO_SETTINGS_MODULE=hub.settings
# Static files are baked in (whitenoise serves them); no DB is touched here.
RUN DJANGO_COLLECTSTATIC=1 python manage.py collectstatic --noinput

USER 10001
EXPOSE 8000
CMD ["gunicorn", "hub.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--access-logfile", "-"]
