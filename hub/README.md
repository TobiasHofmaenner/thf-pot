# thf-pot hub

Django + django-ninja + htmx on the web side, Celery (worker + beat) on Redis, Postgres for
state. One image runs all three roles; the command decides. Right now it serves a "hi" page whose
status table proves every part of the stack is wired: Postgres, Redis, and a task round-trip
through a worker.

| Path | What |
|---|---|
| `/` | the page; htmx pulls `/_status` on load and every 10 s |
| `/nodes/` | sensor nodes: add one (mints its token, renders `docker run` / compose / `.env`), rotate, revoke; deploy phases refresh every 5 s |
| `/api/v1/ingest` | sensor batches (bearer token; see `docs/PROTOCOL.md`) |
| `/api/v1/heartbeat` | sensor state + the address the hub saw it from |
| `/api/v1/status` | stack checks as JSON (`/api/v1/docs` for the OpenAPI page) |
| `/api/v1/storage` | database size against the volume, events, distinct bodies, retention policy, last sweep (also the gauge in the dashboard header and the card on `/status`) |
| `/api/v1/events/{id}/body` | the stored request body, byte for byte; 410 once retention released it |
| `/healthz` | liveness, no dependencies |
| `/readyz` | readiness: DB + cache, 503 when either is down |

`manage.py add_node --domains a.example,b.example` does the same as the button from a shell.
Tokens are stored as SHA-256 only. The two sensor endpoints must be reachable without the
ingress basic auth (second Ingress in thf-infra); the hub derives the node's public address from
`CF-Connecting-IP` / `X-Forwarded-For`, which only the ingress can set.

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
| `STORAGE_CAPACITY_BYTES` | size of the Postgres volume (default 20 GiB); the gauge and the marks are measured against it |
| `RETENTION_HIGH_WATER`, `RETENTION_LOW_WATER` | retention by storage: above the high mark (default 0.80 of the volume) the oldest requests are deleted until the low mark (0.70) is held |
| `EVENT_ROW_BYTES` | what one request is counted as on disk without its body, indexes included (default 2560; measured 1.6–2.2 KiB on real data) |
| `RETENTION_EVENT_DAYS`, `RETENTION_BODY_DAYS` | optional time rules, off by default (0): delete events older than X days; release bodies of events older than Y days, the event keeps hash and size |

Request bodies are stored once per sha256 (`events.Body`); events point at the row, so a payload
posted twenty times or seen again next month costs one copy and the detail view says how often it
was seen. Retention is by storage, oldest first, hourly in the worker (`apps/events/retention.py`).
Postgres reuses freed pages rather than shrinking the file, so the hub counts what it holds itself
(bodies exactly, requests at `EVENT_ROW_BYTES`) and the on-disk figure settles at the high mark.

Cluster manifests: `thf-infra/clusters/thf-k8s-01/kubernetes/apps/internal/thf-pot/`.
