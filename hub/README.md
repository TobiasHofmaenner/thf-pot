# thf-pot hub

Django + django-ninja + htmx on the web side, Celery (worker + beat) on Redis, Postgres for
state. One image runs all three roles; the command decides. Right now it serves a "hi" page whose
status table proves every part of the stack is wired: Postgres, Redis, and a task round-trip
through a worker.

| Path | What |
|---|---|
| `/` | the page; htmx pulls `/_status` on load and every 10 s |
| `/api/v1/status` | the same checks as JSON (`/api/v1/docs` for the OpenAPI page) |
| `/healthz` | liveness, no dependencies |
| `/readyz` | readiness: DB + cache, 503 when either is down |

## Run locally

```sh
docker compose -f docker-compose.dev.yml up --build
open http://127.0.0.1:8000
```

## Configuration

| Variable | Meaning |
|---|---|
| `DJANGO_SECRET_KEY` | required outside `DJANGO_DEBUG=1` |
| `DJANGO_ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS` | comma-separated |
| `POSTGRES_HOST/PORT/DB/USER/PASSWORD` | the CNPG app-secret keys map 1:1 |
| `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`, `CACHE_LOCATION` | Redis URLs |
| `SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE` | `1` behind the ingress |
| `APP_VERSION` | baked in at build; shown on the page |

Cluster manifests: `thf-infra/clusters/thf-k8s-01/kubernetes/apps/internal/thf-pot/`.
