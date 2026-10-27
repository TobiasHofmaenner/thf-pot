"""What the hub lets go of, and when. Three rules, run hourly by the worker:

1. events older than RETENTION_EVENT_DAYS are deleted;
2. bodies of events older than RETENTION_BODY_DAYS are released: the event keeps hash and size;
3. while live body bytes exceed RETENTION_BODY_BUDGET × STORAGE_CAPACITY_BYTES, the bodies of the
   oldest events are released first, until a little under the budget.

A body row is dropped once no event points at it, so a payload that keeps coming back stays as long
as its newest sighting. 0 days switches a rule off. Everything is chunked and idempotent."""

import logging
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.db.models import Sum
from django.db.models.functions import Coalesce
from django.utils import timezone

from .models import Body, Event
from .storage import CACHE_KEY, LAST_SWEEP_KEY, _iso

log = logging.getLogger(__name__)
CHUNK = 2000
PRESSURE_CHUNK = 200  # events whose bodies are released per step under budget pressure


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


def _pressure() -> tuple[int, int, int]:
    """Rule 3. Returns (events released, bodies dropped, bytes freed)."""
    cap, share = settings.STORAGE_CAPACITY_BYTES, settings.RETENTION_BODY_BUDGET
    if not cap or share <= 0:
        return 0, 0, 0
    budget = int(cap * share)
    live = Body.objects.aggregate(s=Coalesce(Sum("size"), 0))["s"]
    if live <= budget:
        return 0, 0, 0
    need = live - int(budget * 0.9)  # end a little under, so the next sweep is quiet
    released = dropped = freed = 0
    while freed < need:
        rows = list(Event.objects.filter(body__isnull=False).order_by("ts").values_list("id", "body_id")[:PRESSURE_CHUNK])
        if not rows:
            break
        released += Event.objects.filter(pk__in=[i for i, _ in rows]).update(body=None)
        n, f = _drop_orphans({h for _, h in rows})
        dropped += n
        freed += f
    return released, dropped, freed


def sweep() -> dict:
    now = timezone.now()
    out = {"at": _iso(now), "events_deleted": 0, "bodies_released": 0, "bodies_deleted": 0, "bytes_freed": 0, "pressure": False}
    if settings.RETENTION_EVENT_DAYS:
        out["events_deleted"] = _delete_events(Event.objects.filter(ts__lt=now - timedelta(days=settings.RETENTION_EVENT_DAYS)))
    if settings.RETENTION_BODY_DAYS:
        cutoff = now - timedelta(days=settings.RETENTION_BODY_DAYS)
        out["bodies_released"] = _release(Event.objects.filter(ts__lt=cutoff, body__isnull=False))
    n, f = _drop_orphans()
    out["bodies_deleted"], out["bytes_freed"] = n, f
    r, d, f = _pressure()
    out["bodies_released"] += r
    out["bodies_deleted"] += d
    out["bytes_freed"] += f
    out["pressure"] = bool(r)
    cache.set(LAST_SWEEP_KEY, out, None)
    cache.delete(CACHE_KEY)
    if any(out[k] for k in ("events_deleted", "bodies_released", "bodies_deleted")):
        log.info("retention: %s", out)
    return out
