import re

from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from . import snippets
from .models import Sensor

_HOST = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$")


def parse_domains(text: str) -> list[str]:
    out, seen = [], set()
    for raw in re.split(r"[\s,;]+", text or ""):
        d = raw.strip().lower().rstrip(".")
        if not d:
            continue
        if not _HOST.match(d):
            raise ValueError(f"not a hostname: {raw!r}")
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _list(request, status=200):
    resp = render(request, "sensors/_node_list.html", {"nodes": Sensor.objects.all()}, status=status)
    return resp


def nodes(request):
    return render(request, "sensors/nodes.html", {"nodes": Sensor.objects.all()})


def node_list(request):
    return _list(request)


def _created(request, sensor, token, title):
    resp = render(
        request,
        "sensors/_node_created.html",
        {"node": sensor, "token": token, "title": title, "s": snippets.build(sensor, token, snippets.hub_url(request))},
    )
    resp["HX-Trigger"] = "nodes-changed"
    return resp


def _error(request, msg):
    return render(request, "sensors/_node_error.html", {"msg": msg}, status=200)


@require_POST
def node_create(request):
    try:
        domains = parse_domains(request.POST.get("domains", ""))
    except ValueError as e:
        return _error(request, str(e))
    if not domains:
        return _error(request, "at least one domain is required")
    name = (request.POST.get("name") or domains[0]).strip()[:80]
    if Sensor.objects.filter(name=name).exists():
        return _error(request, f"a node named {name!r} already exists")
    sensor = Sensor(
        name=name,
        domains=domains,
        acme_email=(request.POST.get("acme_email") or "").strip()[:254],
        notes=(request.POST.get("notes") or "").strip()[:2000],
    )
    token = sensor.mint_token()
    sensor.save()
    return _created(request, sensor, token, f"node {sensor.name} added")


@require_POST
def node_rotate(request, pk):
    sensor = get_object_or_404(Sensor, pk=pk)
    token = sensor.mint_token()
    sensor.token_rotated_at = timezone.now()
    sensor.save(update_fields=["token_sha256", "token_prefix", "token_rotated_at"])
    return _created(request, sensor, token, f"token for {sensor.name} rotated — the old one stops working now")


@require_POST
def node_toggle(request, pk):
    sensor = get_object_or_404(Sensor, pk=pk)
    sensor.is_active = not sensor.is_active
    sensor.save(update_fields=["is_active"])
    return _list(request)


@require_POST
def node_delete(request, pk):
    """Only a revoked node that never produced an event can go; anything with events is evidence."""
    sensor = get_object_or_404(Sensor, pk=pk)
    if sensor.is_active or sensor.events.exists():
        return HttpResponseBadRequest("only a revoked node without events can be deleted")
    sensor.delete()
    return _list(request)
