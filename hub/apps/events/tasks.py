import logging

from celery import shared_task
from django.utils import timezone

from . import geo
from .models import Event

log = logging.getLogger(__name__)


def enrich(ids) -> int:
    """Attach geo + ASN to the given events. Idempotent; rows already enriched are skipped."""
    rows = list(Event.objects.filter(pk__in=ids, geo_at__isnull=True).only("id", "src"))
    now = timezone.now()
    cache: dict[str, dict] = {}
    for e in rows:
        g = cache.get(e.src)
        if g is None:
            g = cache[e.src] = geo.lookup(e.src)
        e.cc = g.get("cc", "") or ""
        e.city = g.get("city", "") or ""
        e.lat, e.lon = g.get("lat"), g.get("lon")
        e.asn, e.as_name = g.get("asn"), g.get("as_name", "") or ""
        e.geo_at = now
    if rows:
        Event.objects.bulk_update(rows, ["cc", "city", "lat", "lon", "asn", "as_name", "geo_at"], batch_size=500)
    return len(rows)


@shared_task(ignore_result=True)
def enrich_events(ids: list[int]):
    """Per ingested batch: geo first (rules may use cc), then the rule engine."""
    n = enrich(ids)
    from apps.rules import engine

    engine.classify_events(ids)
    return n


@shared_task(ignore_result=True)
def enrich_pending():
    """Sweep for anything the per-batch task missed (worker was down, task lost)."""
    ids = list(Event.objects.filter(geo_at__isnull=True).order_by("id").values_list("id", flat=True)[:2000])
    n = enrich(ids) if ids else 0
    if n:
        log.info("geo sweep enriched %d events", n)
    return n
