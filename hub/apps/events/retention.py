"""What the hub lets go of, and when: by storage, oldest first.

Nothing is deleted while the hub holds less than RETENTION_HIGH_WATER of the volume (by its own
count, see storage.py). Above it, the oldest requests go, each body with them once nothing else
points at it, until the count is down to RETENTION_LOW_WATER. A payload that keeps coming back is
referenced by newer requests and so outlives the old ones.

Postgres reuses the freed pages instead of shrinking the file, so the on-disk size settles at the
high mark. The sweep watches that file too: if it is still growing at 90 % of the volume, the hub's
own count must be off, and the growth is evicted twice over so the file stops.

Two optional time rules remain for operators who want them (RETENTION_EVENT_DAYS, RETENTION_BODY_DAYS;
0 = off, the default): events older than X days are deleted; bodies of events older than Y days are
released, the event keeping hash and size. Hourly in the worker; chunked; idempotent."""

import logging
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.utils import timezone

from . import storage
from .models import Body, Event
from .storage import CACHE_KEY, LAST_SWEEP_KEY, _iso

log = logging.getLogger(__name__)
CHUNK = 2000
EVICT_CHUNK = 200  # oldest events deleted per step under storage pressure
LAST_DB_KEY = "thf-pot:retention:db-size"
VALVE_SHARE = 0.90


def _delete_events(qs) -> int:
    n = 0
    while True:
        ids = list(qs.order_by("id").values_list("id", flat=True)[:CHUNK])
        if not ids:
            break
        n += Event.objects.filter(pk__in=ids).delete()[0]
    return n


def _release(qs) -> int:
    """Null the body pointer on the events in qs (which must select body__isnull=False)."""
    n = 0
    while True:
        ids = list(qs.order_by("ts").values_list("id", flat=True)[:CHUNK])
        if not ids:
            break
        n += Event.objects.filter(pk__in=ids).update(body=None)
    return n


def _drop_orphans(shas=None) -> tuple[int, int]:
    """Delete bodies nothing points at (all of them, or only the given hashes). Returns (rows, bytes)."""
    qs = Body.objects.filter(events__isnull=True)
    if shas is not None:
        qs = qs.filter(sha256__in=list(shas))
    n = freed = 0
    while True:
        rows = list(qs.values_list("sha256", "size")[:CHUNK])
        if not rows:
            break
        n += Body.objects.filter(sha256__in=[h for h, _ in rows]).delete()[0]
        freed += sum(s for _, s in rows)
    return n, freed


def _evict(need: int) -> tuple[int, int, int]:
    """Delete the oldest requests until `need` bytes (by the hub's count) are freed.
    Returns (events deleted, bodies dropped, bytes freed)."""
    row = settings.EVENT_ROW_BYTES
    events = bodies = freed = 0
    while freed < need:
        rows = list(Event.objects.order_by("ts", "id").values_list("id", "body_id")[:EVICT_CHUNK])
        if not rows:
            break
        n = Event.objects.filter(pk__in=[i for i, _ in rows]).delete()[0]
        events += n
        freed += n * row
        d, f = _drop_orphans({h for _, h in rows if h})
        bodies += d
        freed += f
    return events, bodies, freed


def _by_storage() -> dict:
    cap = settings.STORAGE_CAPACITY_BYTES
    out = {"held_before": 0, "need": 0, "pressure": False, "valve": False, "events_deleted": 0, "bodies_deleted": 0, "bytes_freed": 0}
    if not cap:
        return out
    m = storage.marks()
    _, _, held = storage.held()
    db = storage.db_size()
    last_db = cache.get(LAST_DB_KEY)
    cache.set(LAST_DB_KEY, db, None)
    out["held_before"] = held
    need = held - m["low_water_bytes"] if held > m["high_water_bytes"] else 0
    if last_db is not None and db > last_db and db >= cap * VALVE_SHARE:
        # The file grew although (or after) we evicted: our count is optimistic. Evict the growth twice.
        need = max(need, 2 * (db - last_db))
        out["valve"] = True
    if need <= 0:
        return out
    out["need"] = need
    out["pressure"] = True
    out["events_deleted"], out["bodies_deleted"], out["bytes_freed"] = _evict(need)
    return out


def _vacuum() -> bool:
    """Make the freed pages reusable now rather than when autovacuum gets to it. VACUUM cannot run
    inside a transaction (tests), so it is skipped there."""
    if connection.in_atomic_block:
        return False
    with connection.cursor() as cur:
        cur.execute("VACUUM (ANALYZE) events_event, events_body")
    return True


def sweep() -> dict:
    now = timezone.now()
    out = {"at": _iso(now), "events_deleted": 0, "bodies_released": 0, "bodies_deleted": 0, "bytes_freed": 0}
    if settings.RETENTION_EVENT_DAYS:
        out["events_deleted"] = _delete_events(Event.objects.filter(ts__lt=now - timedelta(days=settings.RETENTION_EVENT_DAYS)))
    if settings.RETENTION_BODY_DAYS:
        cutoff = now - timedelta(days=settings.RETENTION_BODY_DAYS)
        out["bodies_released"] = _release(Event.objects.filter(ts__lt=cutoff, body__isnull=False))
    n, f = _drop_orphans()
    out["bodies_deleted"], out["bytes_freed"] = n, f
    s = _by_storage()
    out["events_deleted"] += s["events_deleted"]
    out["bodies_deleted"] += s["bodies_deleted"]
    out["bytes_freed"] += s["bytes_freed"]
    out.update(pressure=s["pressure"], valve=s["valve"], held_before=s["held_before"], need=s["need"])
    if out["events_deleted"] or out["bodies_released"] or out["bodies_deleted"]:
        out["vacuumed"] = _vacuum()
        log.info("retention: %s", out)
    cache.set(LAST_SWEEP_KEY, out, None)
    cache.delete(CACHE_KEY)
    return out
