"""How full the hub is. Postgres answers for bytes on disk; the capacity is what the volume was given
(STORAGE_CAPACITY_BYTES), because the database cannot see its own filesystem."""

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.db.models import Count, Sum
from django.db.models.functions import Coalesce

from .models import Body, Event

CACHE_KEY = "thf-pot:storage"
LAST_SWEEP_KEY = "thf-pot:retention:last"
WARN_PCT, CRITICAL_PCT = 75, 90


def human(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def _iso(dt):
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z") if dt else None


def usage(fresh: bool = False) -> dict:
    if not fresh:
        hit = cache.get(CACHE_KEY)
        if hit:
            return hit
    with connection.cursor() as cur:
        cur.execute(
            "select pg_database_size(current_database()), pg_total_relation_size('events_body'), pg_total_relation_size('events_event')"
        )
        db_bytes, bodies_disk, events_disk = cur.fetchone()
    b = Body.objects.aggregate(n=Count("sha256"), size=Coalesce(Sum("size"), 0))
    refs = Event.objects.filter(body__isnull=False).count()
    events = Event.objects.count()
    oldest = Event.objects.order_by("ts").values_list("ts", flat=True).first()
    cap = settings.STORAGE_CAPACITY_BYTES
    pct = round(100 * db_bytes / cap, 1) if cap else None
    level = "ok" if pct is None else "critical" if pct >= CRITICAL_PCT else "warn" if pct >= WARN_PCT else "ok"
    out = {
        "capacity_bytes": cap,
        "db_bytes": db_bytes,
        "pct": pct,
        "level": level,
        "events": {"count": events, "disk_bytes": events_disk, "oldest_ts": _iso(oldest)},
        "bodies": {"count": b["n"], "bytes": int(b["size"]), "disk_bytes": bodies_disk, "refs": refs,
                   "budget_bytes": int(cap * settings.RETENTION_BODY_BUDGET)},
        "retention": {"event_days": settings.RETENTION_EVENT_DAYS, "body_days": settings.RETENTION_BODY_DAYS,
                      "body_budget": settings.RETENTION_BODY_BUDGET},
        "last_sweep": cache.get(LAST_SWEEP_KEY),
    }
    cache.set(CACHE_KEY, out, 30)
    return out
