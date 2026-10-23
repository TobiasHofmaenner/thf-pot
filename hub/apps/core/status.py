"""One place that asks every part of the stack whether it is there."""

import time

from django.conf import settings
from django.core.cache import cache
from django.db import connection

from .tasks import ping


def _check(fn):
    t0 = time.monotonic()
    try:
        fn()
        return {"ok": True, "ms": round((time.monotonic() - t0) * 1000)}
    except Exception as e:  # noqa: BLE001 - any failure is the answer here
        return {"ok": False, "ms": round((time.monotonic() - t0) * 1000), "error": str(e)[:200]}


def _db():
    with connection.cursor() as cur:
        cur.execute("SELECT 1")
        cur.fetchone()


def _redis():
    key = "thf-pot:status-probe"
    cache.set(key, "1", 10)
    if cache.get(key) != "1":
        raise RuntimeError("cache round-trip failed")


def _worker():
    if ping.apply_async(expires=5).get(timeout=5) != "pong":
        raise RuntimeError("unexpected reply")


def collect(include_worker=True):
    out = {
        "version": settings.APP_VERSION,
        "db": _check(_db),
        "redis": _check(_redis),
    }
    if include_worker:
        out["worker"] = _check(_worker)
    return out
