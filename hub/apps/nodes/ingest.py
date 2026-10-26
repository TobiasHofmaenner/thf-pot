"""Turn node records into Event rows. Every field is attacker-influenced; parse defensively,
cap lengths, and never let one bad line reject a batch."""

import base64
import ipaddress
import logging
from datetime import datetime, timezone

from django.db import transaction
from django.db.models import F
from django.utils import timezone as dj_tz

from apps.events.models import Event

from .models import Node

log = logging.getLogger(__name__)

# The node stores everything it reads (MAX_READ_BYTES, 64 MiB); the hub keeps the same amount so
# nothing is lost between the two, and never more, whatever a node claims.
MAX_SAMPLE = 64 * 1024 * 1024
KNOWN_KEYS = {"v", "id", "ts", "src", "src_port", "self", "http", "host", "body", "multipart", "flags", "resp", "dur_ms"}


class BadRecord(ValueError):
    pass


def _s(v, n):
    return (v if isinstance(v, str) else "")[:n]


def _int(v, default=None):
    return v if isinstance(v, int) and not isinstance(v, bool) else default


def _ts(v):
    if not isinstance(v, str):
        raise BadRecord("ts")
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError as e:
        raise BadRecord("ts") from e
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def to_event(node: Node, rec: dict) -> Event:
    if not isinstance(rec, dict) or rec.get("v") != 1:
        raise BadRecord("schema")
    ulid = rec.get("id")
    if not isinstance(ulid, str) or len(ulid) != 26:
        raise BadRecord("id")
    try:
        src = str(ipaddress.ip_address(rec.get("src", "")))
    except ValueError as e:
        raise BadRecord("src") from e
    http = rec.get("http") or {}
    body = rec.get("body") or {}
    headers = http.get("headers") if isinstance(http.get("headers"), list) else []
    headers = [[_s(k, 200), _s(v, 2000)] for k, v in (h for h in headers if isinstance(h, list) and len(h) == 2)][:200]
    ctype = next((v for k, v in headers if k == "content-type"), "")

    sample = None
    b64 = body.pop("sample_b64", None) if isinstance(body, dict) else None  # drop the base64 once decoded
    if isinstance(b64, str) and b64:
        try:
            sample = base64.b64decode(b64, validate=True)[:MAX_SAMPLE]
        except ValueError:
            sample = None

    flags = [_s(f, 64) for f in (rec.get("flags") or []) if isinstance(f, str)][:64]
    extra = {k: v for k, v in rec.items() if k not in KNOWN_KEYS} or None

    return Event(
        node=node,
        ulid=ulid,
        ts=_ts(rec.get("ts")),
        src=src,
        src_port=_int(rec.get("src_port")),
        is_self=bool(rec.get("self", False)),
        scheme=_s(http.get("scheme"), 8),
        http_version=_s(http.get("version"), 16),
        method=_s(http.get("method"), 16) or "?",
        host=_s(rec.get("host"), 253),
        target=_s(http.get("target"), 4000),
        path=_s(http.get("path"), 2000),
        query=_s(http.get("query"), 2000),
        headers=headers,
        hdr_fp=_s(http.get("hdr_fp"), 16),
        content_type=_s(ctype, 255),
        declared_len=_int(body.get("declared_len")),
        read_len=_int(body.get("read_len"), 0),
        truncated=bool(body.get("truncated", False)),
        body_sha256=_s(body.get("sha256"), 64),
        body_sample=sample,
        multipart=rec.get("multipart") if isinstance(rec.get("multipart"), dict) else None,
        flags=flags,
        resp=rec.get("resp") if isinstance(rec.get("resp"), dict) else {},
        dur_ms=_int(rec.get("dur_ms"), 0),
        extra=extra,
    )


def _enqueue_geo(node_pk: int, ulids: list[str]):
    from apps.events.tasks import enrich_events

    ids = list(Event.objects.filter(node_id=node_pk, ulid__in=ulids).values_list("id", flat=True))
    try:
        enrich_events.delay(ids)
    except Exception as e:  # noqa: BLE001 - broker down: the periodic sweep catches up
        log.warning("geo task not queued (%s); the sweep will enrich", e)


def ingest_batch(node: Node, records: list) -> dict:
    """Insert what is new, count what is duplicate or malformed, bump the node's counters."""
    events, rejected = [], 0
    for rec in records:
        try:
            events.append(to_event(node, rec))
        except BadRecord as e:
            rejected += 1
            log.warning("node %s: rejected record (%s)", node.name, e)

    seen: set[str] = set()
    unique = []
    for e in events:
        if e.ulid not in seen:
            seen.add(e.ulid)
            unique.append(e)
    duplicates = len(events) - len(unique)

    accepted = 0
    if unique:
        with transaction.atomic():
            existing = set(
                Event.objects.filter(node=node, ulid__in=[e.ulid for e in unique]).values_list("ulid", flat=True)
            )
            new = [e for e in unique if e.ulid not in existing]
            duplicates += len(unique) - len(new)
            if new:
                # ignore_conflicts covers a retried batch racing its own first delivery.
                Event.objects.bulk_create(new, ignore_conflicts=True, batch_size=200)
                accepted = len(new)
                latest = max(e.ts for e in new)
                Node.objects.filter(pk=node.pk).update(
                    events_total=F("events_total") + accepted,
                    last_event_at=latest,
                    last_seen_at=dj_tz.now(),
                )
                ulids = [e.ulid for e in new]
                transaction.on_commit(lambda: _enqueue_geo(node.pk, ulids))
    if not accepted:
        Node.objects.filter(pk=node.pk).update(last_seen_at=dj_tz.now())
    return {"accepted": accepted, "duplicates": duplicates, "rejected": rejected}
