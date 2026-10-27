"""The compiled rule set, cached per process, and classification of events with it."""

import logging
import threading

from django.db.models import BinaryField, F, Func, Max
from django.utils import timezone

from apps.events.models import Event

from . import sigma
from .models import Rule

log = logging.getLogger(__name__)
_lock = threading.Lock()
_cache: dict = {"key": None, "rules": []}


class Compiled:
    def __init__(self, rule: Rule):
        self.rule = rule
        self.name = rule.name
        self.severity = rule.severity
        self.suppressed_by = set(rule.suppressed_by or [])
        self.det = sigma.parse_detection(rule.detection)


def ruleset() -> list[Compiled]:
    """Enabled rules, recompiled only when the table changed."""
    agg = Rule.objects.filter(enabled=True).aggregate(n=Max("updated_at"))
    key = (agg["n"], Rule.objects.filter(enabled=True).count())
    with _lock:
        if _cache["key"] == key:
            return _cache["rules"]
        rules = []
        for r in Rule.objects.filter(enabled=True).order_by("id"):
            try:
                rules.append(Compiled(r))
            except sigma.RuleError as e:
                log.error("rule %s does not compile and is skipped: %s", r.name, e)
        _cache.update(key=key, rules=rules)
        return rules


def invalidate():
    with _lock:
        _cache["key"] = None


def classify_one(event: Event, rules: list[Compiled], known_hosts=()) -> tuple[list[str], int | None]:
    ctx = sigma.context(event, known_hosts)
    hits = [c for c in rules if c.det.evaluate(ctx)]
    got = {c.name for c in hits}
    hits = [c for c in hits if not (c.suppressed_by & got)]
    labels = sorted(c.name for c in hits)
    sev = max((c.severity for c in hits), default=None)
    return labels, sev


def for_rules(qs):
    """Rows as the rules need them: the node, and only the first RULE_BODY_BYTES of the body, cut in
    the database, so classifying never pulls a full-size body into the worker."""
    head = Func(F("body__data"), function="substring",
                template=f"%(function)s(%(expressions)s from 1 for {sigma.RULE_BODY_BYTES})", output_field=BinaryField())
    return qs.select_related("node").annotate(body_head=head)


def classify_events(ids, rules=None) -> int:
    rules = ruleset() if rules is None else rules
    now = timezone.now()
    n, changed = 0, []

    def flush():
        nonlocal n, changed
        if changed:
            Event.objects.bulk_update(changed, ["labels", "severity", "classified_at"], batch_size=500)
            n += len(changed)
            changed = []

    for e in for_rules(Event.objects.filter(pk__in=ids)).order_by("id").iterator(chunk_size=200):
        e.labels, e.severity = classify_one(e, rules, e.node.domains)
        e.classified_at = now
        changed.append(e)
        if len(changed) >= 500:
            flush()
    flush()
    return n


def test_rule(detection_text: str, n: int = 500, suppressed_by=()) -> dict:
    """Dry-run one detection against the newest n events: how many match, and a sample."""
    det = sigma.parse_detection(detection_text)
    rules = ruleset()
    matched, sample = 0, []
    qs = for_rules(Event.objects.order_by("-id"))[:n]
    total = 0
    for e in qs:
        total += 1
        ctx = sigma.context(e, e.node.domains)
        if det.evaluate(ctx):
            # the suppressions a real save would apply
            others = {c.name for c in rules if c.det.evaluate(ctx)}
            if set(suppressed_by) & others:
                continue
            matched += 1
            if len(sample) < 25:
                sample.append({"id": e.id, "ts": e.ts.isoformat(timespec="seconds").replace("+00:00", "Z"), "src": e.src,
                               "cc": e.cc, "method": e.method, "path": (e.target or e.path)[:120], "node": e.node.name})
    return {"matched": matched, "total": total, "sample": sample, "fields": sorted(det.fields())}
