from django.http import HttpResponse, JsonResponse
from django.shortcuts import render

from . import status


def index(request):
    return render(request, "core/index.html")


def status_fragment(request):
    """htmx partial: the index page swaps this in on load and every few seconds."""
    return render(request, "core/_status.html", {"s": status.collect()})


def healthz(request):
    """Liveness: the process answers. No dependencies, so a broken DB never restarts the web pod."""
    return HttpResponse("ok", content_type="text/plain")


def readyz(request):
    """Readiness: DB and cache reachable. The worker is not required to serve pages."""
    s = status.collect(include_worker=False)
    ok = s["db"]["ok"] and s["redis"]["ok"]
    return JsonResponse(s, status=200 if ok else 503)
