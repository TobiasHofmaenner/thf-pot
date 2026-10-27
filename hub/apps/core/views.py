from django.http import HttpResponse, JsonResponse
from django.shortcuts import render

from apps.events import storage

from . import status


def index(request):
    return render(request, "core/index.html")


def status_fragment(request):
    """htmx partial: the index page swaps this in on load and every few seconds."""
    return render(request, "core/_status.html", {"s": status.collect()})


def storage_fragment(request):
    """htmx partial: how full the database is, what is kept and for how long."""
    u = storage.usage()
    r = u["retention"]
    h = {
        "db": storage.human(u["db_bytes"]), "cap": storage.human(u["capacity_bytes"]),
        "held": storage.human(u["held_bytes"]),
        "high": storage.human(u["high_water_bytes"]), "low": storage.human(u["low_water_bytes"]),
        "high_pct": round(r["high_water"] * 100), "low_pct": round(r["low_water"] * 100),
        "events_disk": storage.human(u["events"]["disk_bytes"]),
        "bodies_live": storage.human(u["bodies"]["bytes"]), "bodies_disk": storage.human(u["bodies"]["disk_bytes"]),
        "time_rules": ", ".join(x for x in (
            f"events older than {r['event_days']} days are deleted" if r["event_days"] else "",
            f"bodies of events older than {r['body_days']} days are released" if r["body_days"] else "")
            if x),
        "freed": storage.human((u["last_sweep"] or {}).get("bytes_freed", 0)),
    }
    return render(request, "core/_storage.html", {"u": u, "h": h})


def healthz(request):
    """Liveness: the process answers. No dependencies, so a broken DB never restarts the web pod."""
    return HttpResponse("ok", content_type="text/plain")


def readyz(request):
    """Readiness: DB and cache reachable. The worker is not required to serve pages."""
    s = status.collect(include_worker=False)
    ok = s["db"]["ok"] and s["redis"]["ok"]
    return JsonResponse(s, status=200 if ok else 503)
