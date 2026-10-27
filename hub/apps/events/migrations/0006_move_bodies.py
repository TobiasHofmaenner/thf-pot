"""Move the per-event body samples into the shared Body table: one row per distinct sha256, the event
points at it and records the hash and size. Chunked, so a few large bodies never need much memory."""

import hashlib

from django.db import migrations

CHUNK = 500


def forwards(apps, schema_editor):
    Event = apps.get_model("events", "Event")
    Body = apps.get_model("events", "Body")
    seen: dict[str, list] = {}  # sha256 -> [first_ts, last_ts]
    repeated: set[str] = set()
    last = 0
    while True:
        rows = list(
            Event.objects.filter(id__gt=last, body_sample__isnull=False).order_by("id").only("id", "ts", "body_sample")[:CHUNK]
        )
        if not rows:
            break
        new, by_sha = [], {}
        for e in rows:
            data = bytes(e.body_sample)
            h = hashlib.sha256(data).hexdigest()
            if h not in seen:
                seen[h] = [e.ts, e.ts]
                new.append(Body(sha256=h, data=data, size=len(data), first_seen_at=e.ts, last_seen_at=e.ts))
            else:
                s = seen[h]
                s[0], s[1] = min(s[0], e.ts), max(s[1], e.ts)
                repeated.add(h)
            by_sha.setdefault((h, len(data)), []).append(e.id)
        Body.objects.bulk_create(new, ignore_conflicts=True)
        for (h, size), ids in by_sha.items():
            Event.objects.filter(id__in=ids).update(body_id=h, body_size=size, body_sha256=h)
        last = rows[-1].id
    for h in repeated:
        Body.objects.filter(sha256=h).update(first_seen_at=seen[h][0], last_seen_at=seen[h][1])


def backwards(apps, schema_editor):
    Event = apps.get_model("events", "Event")
    Body = apps.get_model("events", "Body")
    for b in Body.objects.iterator(chunk_size=100):
        Event.objects.filter(body_id=b.sha256).update(body_sample=bytes(b.data))


class Migration(migrations.Migration):
    dependencies = [("events", "0005_body")]

    operations = [migrations.RunPython(forwards, backwards)]
