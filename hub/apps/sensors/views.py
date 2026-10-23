import ipaddress
import re

from django.http import HttpResponseBadRequest
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.core.net import client_ip

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


def parse_self_ips(text: str) -> list[str]:
    """Addresses or networks, normalised; anything else is an error."""
    out, seen = [], set()
    for raw in re.split(r"[\s,;]+", text or ""):
        s = raw.strip()
        if not s:
            continue
        try:
            s = str(ipaddress.ip_address(s))
        except ValueError:
            try:
                s = str(ipaddress.ip_network(s, strict=False))
            except ValueError as e:
                raise ValueError(f"not an address or network: {raw!r}") from e
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _list(request, status=200):
    return render(request, "sensors/_node_list.html", {"nodes": Sensor.objects.all()}, status=status)


def nodes(request):
    return render(request, "sensors/nodes.html", {"nodes": Sensor.objects.all(), "your_ip": client_ip(request) or ""})


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


def _apply_fields(sensor, post):
    """Shared by create and edit. Raises ValueError with a message for the page."""
    domains = parse_domains(post.get("domains", ""))
    if not domains:
        raise ValueError("at least one domain is required")
    sensor.domains = domains
    sensor.self_ips = parse_self_ips(post.get("self_ips", ""))
    sensor.acme_email = (post.get("acme_email") or "").strip()[:254]
    sensor.notes = (post.get("notes") or "").strip()[:2000]


@require_POST
def node_create(request):
    sensor = Sensor()
    try:
        _apply_fields(sensor, request.POST)
    except ValueError as e:
        return _error(request, str(e))
    sensor.name = (request.POST.get("name") or sensor.domains[0]).strip()[:80]
    if Sensor.objects.filter(name=sensor.name).exists():
        return _error(request, f"a node named {sensor.name!r} already exists")
    token = sensor.mint_token()
    sensor.save()
    return _created(request, sensor, token, f"node {sensor.name} added")


def node_edit(request, pk):
    sensor = get_object_or_404(Sensor, pk=pk)
    if request.method == "POST":
        try:
            _apply_fields(sensor, request.POST)
        except ValueError as e:
            return _error(request, str(e))
        sensor.save(update_fields=["domains", "self_ips", "acme_email", "notes"])
        env = [line for line in snippets.env_lines(sensor, "<unchanged>", snippets.hub_url(request)) if not line.startswith("#")]
        resp = render(request, "sensors/_node_edited.html", {"node": sensor, "env": "\n".join(env)})
        resp["HX-Trigger"] = "nodes-changed"
        return resp
    return render(request, "sensors/_node_edit.html", {"node": sensor})


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
