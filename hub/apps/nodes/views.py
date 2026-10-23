import ipaddress
import re

from django.http import HttpResponseBadRequest
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.core.net import client_ip

from . import snippets
from .models import Node

# A hostname, or a wildcard sensor such as *.example.org (served by a wildcard certificate behind a proxy).
_HOST = re.compile(r"^(?=.{1,253}$)(\*\.)?(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$")


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
    return render(request, "nodes/_node_list.html", {"nodes": Node.objects.all()}, status=status)


def nodes(request):
    return render(request, "nodes/nodes.html", {"nodes": Node.objects.all(), "your_ip": client_ip(request) or ""})


def node_list(request):
    return _list(request)


def _created(request, node, token, title):
    resp = render(
        request,
        "nodes/_node_created.html",
        {"node": node, "token": token, "title": title, "s": snippets.build(node, token, snippets.hub_url(request))},
    )
    resp["HX-Trigger"] = "nodes-changed"
    return resp


def _error(request, msg):
    return render(request, "nodes/_node_error.html", {"msg": msg}, status=200)


def _apply_fields(node, post):
    """Shared by create and edit. Raises ValueError with a message for the page."""
    domains = parse_domains(post.get("domains", ""))
    if not domains:
        raise ValueError("at least one domain is required")
    node.domains = domains
    node.self_ips = parse_self_ips(post.get("self_ips", ""))
    node.proxied = post.get("proxied") == "on"
    node.acme_email = (post.get("acme_email") or "").strip()[:254]
    node.notes = (post.get("notes") or "").strip()[:2000]


@require_POST
def node_create(request):
    node = Node()
    try:
        _apply_fields(node, request.POST)
    except ValueError as e:
        return _error(request, str(e))
    node.name = (request.POST.get("name") or node.domains[0]).strip()[:80]
    if Node.objects.filter(name=node.name).exists():
        return _error(request, f"a node named {node.name!r} already exists")
    token = node.mint_token()
    node.save()
    return _created(request, node, token, f"node {node.name} added")


def node_edit(request, pk):
    node = get_object_or_404(Node, pk=pk)
    if request.method == "POST":
        try:
            _apply_fields(node, request.POST)
        except ValueError as e:
            return _error(request, str(e))
        node.save(update_fields=["domains", "self_ips", "proxied", "acme_email", "notes"])
        env = [line for line in snippets.env_lines(node, "<unchanged>", snippets.hub_url(request)) if not line.startswith("#")]
        resp = render(request, "nodes/_node_edited.html", {"node": node, "env": "\n".join(env)})
        resp["HX-Trigger"] = "nodes-changed"
        return resp
    return render(request, "nodes/_node_edit.html", {"node": node})


@require_POST
def node_rotate(request, pk):
    node = get_object_or_404(Node, pk=pk)
    token = node.mint_token()
    node.token_rotated_at = timezone.now()
    node.save(update_fields=["token_sha256", "token_prefix", "token_rotated_at"])
    return _created(request, node, token, f"token for {node.name} rotated — the old one stops working now")


@require_POST
def node_toggle(request, pk):
    node = get_object_or_404(Node, pk=pk)
    node.is_active = not node.is_active
    node.save(update_fields=["is_active"])
    return _list(request)


@require_POST
def node_delete(request, pk):
    """Only a revoked node that never produced an event can go; anything with events is evidence."""
    node = get_object_or_404(Node, pk=pk)
    if node.is_active or node.events.exists():
        return HttpResponseBadRequest("only a revoked node without events can be deleted")
    node.delete()
    return _list(request)
