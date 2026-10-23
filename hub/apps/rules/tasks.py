import logging

from celery import shared_task

from apps.events.models import Event

from . import engine

log = logging.getLogger(__name__)


@shared_task(ignore_result=True)
def classify_events(ids: list[int]):
    return engine.classify_events(ids)


@shared_task(ignore_result=True)
def classify_pending():
    ids = list(Event.objects.filter(classified_at__isnull=True).order_by("id").values_list("id", flat=True)[:2000])
    return engine.classify_events(ids) if ids else 0


@shared_task(ignore_result=True)
def reclassify_all():
    """After a rule changed: every event gets labelled again, oldest first, in chunks."""
    engine.invalidate()
    rules = engine.ruleset()
    last, n = 0, 0
    while True:
        ids = list(Event.objects.filter(id__gt=last).order_by("id").values_list("id", flat=True)[:1000])
        if not ids:
            break
        n += engine.classify_events(ids, rules)
        last = ids[-1]
    log.info("reclassified %d events with %d rules", n, len(rules))
    return n
