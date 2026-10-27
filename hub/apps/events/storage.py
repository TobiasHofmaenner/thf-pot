"""How full the hub is, and how much it holds.

Postgres reports bytes on disk, but it never gives space back after a delete: freed pages are reused
for new rows. So "how much do we hold" is counted by the hub itself: the body bytes it stores plus a
deliberately generous per-request estimate (EVENT_ROW_BYTES) for the row and its indexes. Retention
works on that count against marks on the volume; the on-disk figure settles just under the high mark
and stays there, which is the intended steady state, not a leak."""

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.db.models import Sum
from django.db.models.functions import Coalesce

from .models import Body, Event

CACHE_KEY = "thf-pot:storage"
LAST_SWEEP_KEY = "thf-pot:retention:last"
CRITICAL_PCT = 95


def human(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def _iso(dt):
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z") if dt else None


def db_size() -> int:
    with connection.cursor() as cur:
        cur.execute("select pg_database_size(current_database())")
        return int(cur.fetchone()[0])


def held() -> tuple[int, int, int]:
    """(events, body bytes, what the hub counts itself holding)."""
    n = Event.objects.count()
    b = int(Body.objects.aggregate(size=Coalesce(Sum("size"), 0))["size"])
    return n, b, n * settings.EVENT_ROW_BYTES + b


def marks() -> dict:
    cap = settings.STORAGE_CAPACITY_BYTES
    return {
        "capacity_bytes": cap,
        "high_water_bytes": int(cap * settings.RETENTION_HIGH_WATER),
        "low_water_bytes": int(cap * settings.RETENTION_LOW_WATER),
    }


def usage(fresh: bool = False) -> dict:
    if not fresh:
        hit = cache.get(CACHE_KEY)
        if hit:
            return hit
    with connection.cursor() as cur:
        cur.execute(
            "select pg_database_size(current_database()), pg_total_relation_size('events_body'), pg_total_relation_size('events_event')"
        )
        db_bytes, bodies_disk, events_disk = (int(x) for x in cur.fetchone())
    events, body_bytes, live = held()
    bodies = Body.objects.count()
    refs = Event.objects.filter(body__isnull=False).count()
    oldest = Event.objects.order_by("ts").values_list("ts", flat=True).first()
    m = marks()
    cap = m["capacity_bytes"]
    pct = round(100 * db_bytes / cap, 1) if cap else None
    high_pct = settings.RETENTION_HIGH_WATER * 100
    # The disk figure is expected to sit at the high mark; only a figure well past it, which the
    # sweep should have prevented, is a warning.
    level = "ok" if pct is None or pct < high_pct + 5 else "warn" if pct < CRITICAL_PCT else "critical"
    out = {
        **m,
        "db_bytes": db_bytes,
        "pct": pct,
        "level": level,
        "held_bytes": live,
        "held_pct": round(100 * live / cap, 1) if cap else None,
        "events": {"count": events, "disk_bytes": events_disk, "oldest_ts": _iso(oldest)},
        "bodies": {"count": bodies, "bytes": body_bytes, "disk_bytes": bodies_disk, "refs": refs},
        "retention": {"high_water": settings.RETENTION_HIGH_WATER, "low_water": settings.RETENTION_LOW_WATER,
                      "event_row_bytes": settings.EVENT_ROW_BYTES,
                      "event_days": settings.RETENTION_EVENT_DAYS, "body_days": settings.RETENTION_BODY_DAYS},
        "last_sweep": cache.get(LAST_SWEEP_KEY),
    }
    cache.set(CACHE_KEY, out, 30)
    return out
