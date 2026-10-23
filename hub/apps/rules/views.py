"""The rule editor page: htmx partials around the same service layer the JSON API uses."""

from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_POST

from apps.events.models import Event

from . import engine, export, service
from .models import Rule
from .sigma import FIELDS, RuleError

TEMPLATE = """sel:
  path|contains: ['/.env', '/.git/config']
  method: [GET, HEAD]
condition: sel
"""


def _hits():
    out = {}
    for labels in Event.objects.filter(labels__len__gt=0).values_list("labels", flat=True):
        for lab in labels:
            out[lab] = out.get(lab, 0) + 1
    return out


def _rows():
    hits = _hits()
    rows = []
    for r in Rule.objects.all():
        ex = export.exportability(r)
        rows.append({"r": r, "hits": hits.get(r.name, 0), "waf": "ok" if not ex["modsec"] else ex["modsec"],
                     "cf": "ok" if not ex["cloudflare"] else ex["cloudflare"]})
    return rows


def rules(request):
    return render(request, "rules/rules.html", {"rows": _rows(), "fields": FIELDS})


def rule_list(request):
    return render(request, "rules/_rule_list.html", {"rows": _rows()})


def _editor(request, rule: Rule, msg: str = "", error: str = "", result=None, status=200):
    ex = export.exportability(rule) if rule.pk else {}
    resp = render(request, "rules/_rule_editor.html",
                  {"rule": rule, "msg": msg, "error": error, "result": result, "ex": ex, "origins": Rule.ORIGINS,
                   "sevs": Rule.SEVERITIES}, status=status)
    return resp


def rule_new(request):
    return _editor(request, Rule(detection=TEMPLATE, origin="human"))


def rule_edit(request, pk):
    return _editor(request, get_object_or_404(Rule, pk=pk))


def _form(post) -> dict:
    return {k: post.get(k) for k in ("name", "title", "description", "origin", "tags", "severity", "cve", "detection", "suppressed_by")} | {
        "enabled": post.get("enabled") == "on"}


@require_POST
def rule_save(request, pk=None):
    rule = get_object_or_404(Rule, pk=pk) if pk else Rule(created_by="page")
    try:
        service.apply(rule, _form(request.POST))
    except service.ValidationError as e:
        # keep what was typed
        for k, v in _form(request.POST).items():
            if k in ("name", "title", "description", "detection") and v is not None:
                setattr(rule, k, v)
        return _editor(request, rule, error=str(e))
    service.save(rule)
    resp = _editor(request, rule, msg=f"saved {rule.name}; events are being relabelled")
    resp["HX-Trigger"] = "rules-changed"
    return resp


@require_POST
def rule_delete(request, pk):
    rule = get_object_or_404(Rule, pk=pk)
    service.delete(rule)
    resp = HttpResponse("")
    resp["HX-Trigger"] = "rules-changed"
    return resp


@require_POST
def rule_check(request, pk=None):
    """Validate + test the detection as typed, without saving."""
    rule = get_object_or_404(Rule, pk=pk) if pk else Rule(created_by="page")
    form = _form(request.POST)
    try:
        service.apply(rule, form)
    except service.ValidationError as e:
        for k, v in form.items():
            if k in ("name", "title", "description", "detection") and v is not None:
                setattr(rule, k, v)
        return _editor(request, rule, error=str(e))
    try:
        result = engine.test_rule(rule.detection, n=500, suppressed_by=rule.suppressed_by)
    except RuleError as e:
        return _editor(request, rule, error=str(e))
    return _editor(request, rule, result=result, msg="valid — not saved")


def rule_export_view(request):
    fmt = request.GET.get("format", "modsec")
    mode = request.GET.get("mode", "detect")
    from .api import export_rules

    return export_rules(request, format=fmt, mode=mode)
