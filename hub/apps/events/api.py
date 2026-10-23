"""What the dashboard reads. Everything here is derived from rows a sensor sent; attacker bytes
are returned as data for the page to render as text, never as markup."""

from datetime import timedelta

from django.db import connection
from django.http import Http404
from django.utils import timezone
from ninja import Router

from apps.sensors.models import Sensor

from .models import Event

router = Router(tags=["events"])

MAX_HOURS = 24 * 30


def _ua(headers) -> str:
    for k, v in headers or []:
        if k == "user-agent":
            return v
    return ""


def _compact(e: Event, sensors: dict) -> dict:
    return {
        "id": e.id,
        "ts": e.ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "src": e.src,
        "cc": e.cc or "??",
        "city": e.city,
        "lat": e.lat,
        "lon": e.lon,
        "method": e.method,
        "host": e.host or "-",
        "path": e.target or e.path,
        "sensor": sensors.get(e.sensor_id, "?"),
        "tier": (e.resp or {}).get("tier", ""),
        "flags": e.flags,
        "labels": e.labels,
        "sev": e.sev,
        "ua": _ua(e.headers)[:200],
        "self": e.is_self,
    }


def _sensor_names() -> dict:
    return dict(Sensor.objects.values_list("id", "name"))


@router.get("/events/recent")
def recent(request, n: int = 200, after: int | None = None):
    """Newest first by default; with `after=<id>` the events since that id, oldest first (polling)."""
    n = max(1, min(n, 500))
    names = _sensor_names()
    if after is not None:
        qs = Event.objects.filter(id__gt=after).order_by("id")[:n]
        return [_compact(e, names) for e in qs]
    qs = Event.objects.order_by("-id")[:n]
    return [_compact(e, names) for e in qs]


@router.get("/events/summary")
def summary(request, hours: int = 168):
    """Hourly buckets for the window: counts, geo points, sources, requested hosts, sensors."""
    hours = max(1, min(hours, MAX_HOURS))
    since = (timezone.now() - timedelta(hours=hours)).replace(minute=0, second=0, microsecond=0)
    flagged_sql = "(cardinality(labels) > 0 OR flags::text[] && %s::text[])"
    params = [list(Event.SUSPICIOUS_FLAGS)]
    by_hour: dict[str, dict] = {}

    def bucket(h):
        return by_hour.setdefault(h, {"n": 0, "flagged": 0, "geo": [], "ips": [], "host": [], "sensor": []})

    with connection.cursor() as cur:
        cur.execute(
            f"""select to_char(date_trunc('hour', ts) at time zone 'UTC', 'YYYY-MM-DD"T"HH24') h,
                       count(*), count(*) filter (where {flagged_sql})
                from events_event where ts >= %s group by 1 order by 1""",
            params + [since],
        )
        for h, n, f in cur.fetchall():
            b = bucket(h)
            b["n"], b["flagged"] = n, f
        cur.execute(
            f"""select to_char(date_trunc('hour', ts) at time zone 'UTC', 'YYYY-MM-DD"T"HH24') h,
                       round(lat::numeric, 1), round(lon::numeric, 1), cc, max(city), count(*), count(*) filter (where {flagged_sql})
                from events_event where ts >= %s and lat is not null group by 1, 2, 3, 4""",
            params + [since],
        )
        for h, la, lo, cc, city, n, f in cur.fetchall():
            bucket(h)["geo"].append([float(la), float(lo), n, cc or "??", city or "", f])
        cur.execute(
            f"""select to_char(date_trunc('hour', ts) at time zone 'UTC', 'YYYY-MM-DD"T"HH24') h,
                       host(src), max(cc), count(*), count(*) filter (where {flagged_sql})
                from events_event where ts >= %s group by 1, 2""",
            params + [since],
        )
        for h, ip, cc, n, f in cur.fetchall():
            bucket(h)["ips"].append([ip, n, cc or "??", f])
        cur.execute(
            f"""select to_char(date_trunc('hour', ts) at time zone 'UTC', 'YYYY-MM-DD"T"HH24') h,
                       coalesce(nullif(host, ''), '-'), count(*), count(*) filter (where {flagged_sql})
                from events_event where ts >= %s group by 1, 2""",
            params + [since],
        )
        for h, host, n, f in cur.fetchall():
            bucket(h)["host"].append([host, n, f])
        cur.execute(
            f"""select to_char(date_trunc('hour', e.ts) at time zone 'UTC', 'YYYY-MM-DD"T"HH24') h,
                       s.name, count(*), count(*) filter (where {flagged_sql})
                from events_event e join sensors_sensor s on s.id = e.sensor_id where e.ts >= %s group by 1, 2""",
            params + [since],
        )
        for h, name, n, f in cur.fetchall():
            bucket(h)["sensor"].append([name, n, f])

    sensors = {
        s.name: {"lat": s.lat, "lon": s.lon, "cc": s.cc, "city": s.city, "ip": s.public_ip, "active": s.is_active,
                 "online": s.online}
        for s in Sensor.objects.all()
    }
    return {
        "generated": timezone.now().isoformat(timespec="seconds").replace("+00:00", "Z"),
        "total": Event.objects.count(),
        "hours": sorted(by_hour),
        "by_hour": by_hour,
        "sensors": sensors,
    }


@router.get("/events/{int:event_id}")
def detail(request, event_id: int):
    try:
        e = Event.objects.select_related("sensor").get(pk=event_id)
    except Event.DoesNotExist as err:
        raise Http404 from err
    body = bytes(e.body_sample or b"")
    return {
        "id": e.id,
        "ts": e.ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "received_at": e.received_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "sensor": e.sensor.name,
        "src": e.src, "src_port": e.src_port, "self": e.is_self,
        "cc": e.cc, "city": e.city, "lat": e.lat, "lon": e.lon, "asn": e.asn, "as_name": e.as_name,
        "scheme": e.scheme, "http": e.http_version, "method": e.method, "host": e.host,
        "target": e.target, "path": e.path, "query": e.query,
        "headers": e.headers, "hdr_fp": e.hdr_fp, "content_type": e.content_type,
        "declared_length": e.declared_len, "body_bytes_read": e.read_len, "truncated": e.truncated,
        "body_stored": len(body), "body_sha256": e.body_sha256,
        "body": body.decode("latin-1"),
        "multipart": e.multipart, "flags": e.flags, "resp": e.resp, "dur_ms": e.dur_ms,
        "labels": e.labels, "sev": e.sev,
    }
