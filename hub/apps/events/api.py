"""What the dashboard reads. Everything here is derived from rows a node sent; attacker bytes
are returned as data for the page to render as text, never as markup."""

from datetime import timedelta

from django.db import connection
from django.http import Http404
from django.utils import timezone
from ninja import Router

from apps.nodes.hosts import match_host
from apps.nodes.models import Node

from .models import Event

router = Router(tags=["events"])

MAX_HOURS = 24 * 30


def _ua(headers) -> str:
    for k, v in headers or []:
        if k == "user-agent":
            return v
    return ""


def _compact(e: Event, nodes: dict) -> dict:
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
        "node": nodes.get(e.node_id, ("?", []))[0],
        # sensor = the hostname of ours the request was aimed at; empty when the scanner typed something else
        "sensor": e.host if match_host(e.host, nodes.get(e.node_id, ("?", []))[1]) else "",
        "tier": (e.resp or {}).get("tier", ""),
        "flags": e.flags,
        "labels": e.labels,
        "sev": e.sev,
        "ua": _ua(e.headers)[:200],
        "self": e.is_self,
    }


def _node_names() -> dict:
    return {i: (n, list(doms)) for i, n, doms in Node.objects.values_list("id", "name", "domains")}


@router.get("/events/recent")
def recent(request, n: int = 200, after: int | None = None):
    """Newest first by default; with `after=<id>` the events since that id, oldest first (polling)."""
    n = max(1, min(n, 500))
    names = _node_names()
    if after is not None:
        qs = Event.objects.filter(id__gt=after).order_by("id")[:n]
        return [_compact(e, names) for e in qs]
    qs = Event.objects.order_by("-id")[:n]
    return [_compact(e, names) for e in qs]


@router.get("/events/summary")
def summary(request, hours: int = 168, labels: str | None = None):
    """Hourly buckets for the window: counts, geo points, sources, requested hosts, nodes.

    `flagged` means: carries one of the labels in `labels` (comma-separated). Without the parameter
    it falls back to "any label or structural flag"; an empty parameter flags nothing."""
    hours = max(1, min(hours, MAX_HOURS))
    since = (timezone.now() - timedelta(hours=hours)).replace(minute=0, second=0, microsecond=0)
    if labels is None:
        flagged_sql = "(cardinality(labels) > 0 OR flags::text[] && %s::text[])"
        params = [list(Event.SUSPICIOUS_FLAGS)]
    else:
        wanted = [x.strip() for x in labels.split(",") if x.strip()][:200]
        flagged_sql = "(labels::text[] && %s::text[])" if wanted else "(%s::int = 1)"
        params = [wanted] if wanted else [0]
    by_hour: dict[str, dict] = {}

    def bucket(h):
        return by_hour.setdefault(h, {"n": 0, "flagged": 0, "geo": [], "ips": [], "host": [], "node": [], "labels": []})

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
                from events_event e join nodes_node s on s.id = e.node_id where e.ts >= %s group by 1, 2""",
            params + [since],
        )
        for h, name, n, f in cur.fetchall():
            bucket(h)["node"].append([name, n, f])
        # label counts per hour, so the picker can show how often each label occurred in the window
        cur.execute(
            """select to_char(date_trunc('hour', ts) at time zone 'UTC', 'YYYY-MM-DD"T"HH24') h, l, count(*)
               from events_event, unnest(labels) l where ts >= %s group by 1, 2""",
            [since],
        )
        for h, label, n in cur.fetchall():
            bucket(h).setdefault("labels", []).append([label, n])

    nodes = {
        s.name: {"lat": s.lat, "lon": s.lon, "cc": s.cc, "city": s.city, "ip": s.public_ip, "active": s.is_active,
                 "online": s.online}
        for s in Node.objects.all()
    }
    return {
        "generated": timezone.now().isoformat(timespec="seconds").replace("+00:00", "Z"),
        "total": Event.objects.count(),
        "hours": sorted(by_hour),
        "by_hour": by_hour,
        "nodes": nodes,
    }


@router.get("/events/{int:event_id}")
def detail(request, event_id: int):
    try:
        e = Event.objects.select_related("node").get(pk=event_id)
    except Event.DoesNotExist as err:
        raise Http404 from err
    body = bytes(e.body_sample or b"")
    return {
        "id": e.id,
        "ts": e.ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "received_at": e.received_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "node": e.node.name,
        "sensor": e.host if match_host(e.host, e.node.domains) else "",
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
