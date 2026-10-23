# syntax=docker/dockerfile:1.7
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --uid 10001 --user-group --system --shell /usr/sbin/nologin hub
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
ARG APP_VERSION=dev
ENV APP_VERSION=$APP_VERSION DJANGO_SETTINGS_MODULE=hub.settings
# Static files are baked in (whitenoise serves them); no DB is touched here.
RUN DJANGO_COLLECTSTATIC=1 python manage.py collectstatic --noinput

USER 10001
EXPOSE 8000
CMD ["gunicorn", "hub.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--access-logfile", "-"]
