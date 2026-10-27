"""Settings come from the environment only. The same image runs web, worker and beat."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def env(key, default=None):
    v = os.environ.get(key)
    return v if v not in (None, "") else default


def env_bool(key, default=False):
    return str(env(key, "1" if default else "0")).lower() in ("1", "true", "yes", "on")


def env_list(key, default=""):
    return [x.strip() for x in str(env(key, default)).split(",") if x.strip()]


DEBUG = env_bool("DJANGO_DEBUG")
SECRET_KEY = env("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    if DEBUG or env("DJANGO_COLLECTSTATIC"):
        SECRET_KEY = "insecure-dev-key"
    else:
        raise RuntimeError("DJANGO_SECRET_KEY is required")

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS") or (["*"] if DEBUG else [])
CSRF_TRUSTED_ORIGINS = env_list("CSRF_TRUSTED_ORIGINS")
APP_VERSION = env("APP_VERSION", "dev")

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.postgres",
    "apps.core",
    "apps.nodes",
    "apps.sensors",  # migration history only (the server row moved to apps.nodes)
    "apps.events",
    "apps.rules",
]

# Node batches: up to 500 records / 1 MiB per POST, except that one record may carry a full-size
# body (MAX_READ_BYTES on the node, 64 MiB, ~86 MiB as base64) and then ships alone. The ingress
# allows 96m to match (thf-infra, ingress-ingest.yaml).
DATA_UPLOAD_MAX_MEMORY_SIZE = 96 * 1024 * 1024
# Storage and retention (apps/events/retention.py): by storage, oldest first. The database cannot see
# its own volume, so the capacity is told to it; the default is the CNPG volume size in thf-infra.
STORAGE_CAPACITY_BYTES = int(env("STORAGE_CAPACITY_BYTES", 20 * 1024**3))
RETENTION_HIGH_WATER = float(env("RETENTION_HIGH_WATER", 0.80))  # above this share of the volume the oldest requests go
RETENTION_LOW_WATER = float(env("RETENTION_LOW_WATER", 0.70))  # ... until the hub holds this much
# What one request is counted as on disk without its body: the row, its indexes, and the values the
# answer handed out. Measured 1.6-2.2 KiB per row on real data; counted generously so the file
# settles under the mark, not over it.
EVENT_ROW_BYTES = int(env("EVENT_ROW_BYTES", 3072))
# Optional time rules on top, off by default (0).
RETENTION_EVENT_DAYS = int(env("RETENTION_EVENT_DAYS", 0))  # events older than this are deleted
RETENTION_BODY_DAYS = int(env("RETENTION_BODY_DAYS", 0))  # bodies of older events are released (hash + size stay)
# What the node page tells a new node to run and where to report.
SENSOR_IMAGE = env("SENSOR_IMAGE", "ghcr.io/tobiashofmaenner/thf-pot-node:main")
HUB_PUBLIC_URL = env("HUB_PUBLIC_URL")  # default: derived from the request

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "hub.urls"
WSGI_APPLICATION = "hub.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# Postgres from the CNPG-generated app secret (host/port/username/password/dbname).
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": env("POSTGRES_HOST", "localhost"),
        "PORT": env("POSTGRES_PORT", "5432"),
        "NAME": env("POSTGRES_DB", "thf_pot"),
        "USER": env("POSTGRES_USER", "thf_pot"),
        "PASSWORD": env("POSTGRES_PASSWORD", ""),
        "CONN_MAX_AGE": 60,
        "OPTIONS": {"connect_timeout": 5},
    }
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

_cache_location = env("CACHE_LOCATION")
CACHES = {
    "default": (
        {"BACKEND": "django.core.cache.backends.redis.RedisCache", "LOCATION": _cache_location}
        if _cache_location
        else {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    )
}

CELERY_BROKER_URL = env("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = env("CELERY_RESULT_BACKEND", CELERY_BROKER_URL)
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_TIME_LIMIT = 300
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_BEAT_SCHEDULE = {
    "heartbeat": {"task": "apps.core.tasks.heartbeat", "schedule": 60.0},
    "geo-sweep": {"task": "apps.events.tasks.enrich_pending", "schedule": 60.0},
    "classify-sweep": {"task": "apps.rules.tasks.classify_pending", "schedule": 60.0},
    "retention-sweep": {"task": "apps.events.tasks.retention_sweep", "schedule": 3600.0},
}

# DB-IP Lite databases baked into the image (see Dockerfile); absent = no geo, never an error.
GEOIP_DIR = env("GEOIP_DIR", str(BASE_DIR / "geo"))

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

# Behind the cluster ingress: Cloudflare terminates TLS, nginx forwards the scheme.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True
SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT")
SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE")
CSRF_COOKIE_SECURE = env_bool("CSRF_COOKIE_SECURE")
X_FRAME_OPTIONS = "DENY"

LANGUAGE_CODE = "en-gb"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"plain": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "plain"}},
    "root": {"handlers": ["console"], "level": env("LOG_LEVEL", "INFO")},
}
