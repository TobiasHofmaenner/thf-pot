"""Rules CRUD + validate / test / export. Mutations require the X-Requested-With header: the hub
sits behind basic auth, which browsers replay automatically, so a custom header is what keeps a
foreign page from posting here with your credentials."""

from typing import Any

from django.db.models import Count
from django.http import Http404, HttpResponse
from ninja import Router, Schema
from ninja.errors import HttpError
from ninja.security import APIKeyHeader

from apps.events.models import Event

from . import engine, export, service
from .models import Rule
from .sigma import FIELDS, RuleError

router = Router(tags=["rules"])


class Xhr(APIKeyHeader):
    param_name = "X-Requested-With"

    def authenticate(self, request, key):
        return key if key else None


xhr = Xhr()


class RuleIn(Schema):
    name: str | None = None
    title: str | None = None
    description: str | None = None
    origin: str | None = None
    tags: list[str] | str | None = None
    severity: int | str | None = None
    cve: list[str] | str | None = None
    enabled: bool | None = None
    detection: str | dict | None = None
    suppressed_by: list[str] | str | None = None


class DetectionIn(Schema):
    detection: str | dict
    suppressed_by: list[str] = []
    n: int = 500


def _get(rule_id: int) -> Rule:
    try:
        return Rule.objects.get(pk=rule_id)
    except Rule.DoesNotExist as e:
        raise Http404 from e


def _hits() -> dict[str, int]:
    rows = Event.objects.filter(labels__len__gt=0).values_list("labels", flat=True)
    out: dict[str, int] = {}
    for labels in rows:
        for lab in labels:
            out[lab] = out.get(lab, 0) + 1
    return out


@router.get("/rules")
def list_rules(request, export_status: bool = False):
    hits = _hits()
    out = []
    for r in Rule.objects.all():
        d = service.to_dict(r, with_export=export_status)
        d["hits"] = hits.get(r.name, 0)
        out.append(d)
    return out


@router.get("/rules/fields")
def fields(request):
    return [{"field": k, "kind": v.kind, "doc": v.doc, "modsec": v.modsec, "cloudflare": v.cf} for k, v in FIELDS.items()] + [
        {"field": "header.<name>", "kind": "str", "doc": "any request header", "modsec": "REQUEST_HEADERS:<name>", "cloudflare": 'http.request.headers["<name>"][0]'}
    ]


@router.post("/rules", auth=xhr, response={201: dict})
def create_rule(request, body: RuleIn):
    rule = Rule(created_by=f"api:{body.origin or 'human'}")
    try:
        service.apply(rule, body.dict(exclude_unset=True))
    except service.ValidationError as e:
        raise HttpError(422, str(e)) from None
    service.save(rule)
    return 201, service.to_dict(rule, with_export=True)


@router.get("/rules/export")
def export_rules(request, format: str = "modsec", mode: str = "detect", enabled_only: bool = True):
    """All exportable rules in one file; the ones that cannot travel are listed in a comment."""
    qs = Rule.objects.filter(enabled=True) if enabled_only else Rule.objects.all()
    body, skipped = [], []
    for r in qs:
        try:
            if format == "cloudflare":
                body.append(f"# {r.name} (severity {r.severity_name})\n{export.cloudflare(r)}\n")
            elif format == "modsec":
                body.append(export.modsec(r, mode=mode))
            else:
                raise HttpError(400, "format must be modsec or cloudflare")
        except export.NotExportable as e:
            skipped.append(f"# not exportable: {r.name} — {e}")
        except RuleError as e:
            skipped.append(f"# does not compile: {r.name} — {e}")
    head = f"# thf-pot rules export · format={format} mode={mode} · {len(body)} rules, {len(skipped)} skipped\n"
    text = head + "\n".join(skipped) + ("\n\n" if skipped else "\n") + "\n".join(body)
    return HttpResponse(text, content_type="text/plain; charset=utf-8")


@router.get("/rules/{int:rule_id}")
def get_rule(request, rule_id: int):
    return service.to_dict(_get(rule_id), with_export=True)


@router.put("/rules/{int:rule_id}", auth=xhr)
def update_rule(request, rule_id: int, body: RuleIn):
    rule = _get(rule_id)
    try:
        service.apply(rule, body.dict(exclude_unset=True), partial=True)
    except service.ValidationError as e:
        raise HttpError(422, str(e)) from None
    service.save(rule)
    return service.to_dict(rule, with_export=True)


@router.delete("/rules/{int:rule_id}", auth=xhr, response={204: None})
def delete_rule(request, rule_id: int):
    service.delete(_get(rule_id))
    return 204, None


@router.get("/rules/{int:rule_id}/export")
def export_rule(request, rule_id: int, format: str = "modsec", mode: str = "detect"):
    r = _get(rule_id)
    try:
        text = export.cloudflare(r) if format == "cloudflare" else export.modsec(r, mode=mode)
    except export.NotExportable as e:
        raise HttpError(422, f"not exportable: {e}") from None
    return HttpResponse(text, content_type="text/plain; charset=utf-8")


@router.post("/rules/validate", auth=xhr)
def validate(request, body: DetectionIn):
    try:
        det = service.validate_detection(body.detection if isinstance(body.detection, str) else __import__("yaml").safe_dump(body.detection))
    except service.ValidationError as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "fields": sorted(det.fields()), "condition": det.condition_text}


@router.post("/rules/test", auth=xhr)
def test_detection(request, body: DetectionIn):
    try:
        text = body.detection if isinstance(body.detection, str) else __import__("yaml").safe_dump(body.detection)
        return engine.test_rule(text, n=max(1, min(body.n, 5000)), suppressed_by=body.suppressed_by)
    except RuleError as e:
        raise HttpError(422, str(e)) from None


@router.post("/rules/{int:rule_id}/test", auth=xhr)
def test_rule(request, rule_id: int, n: int = 500):
    r = _get(rule_id)
    return engine.test_rule(r.detection, n=max(1, min(n, 5000)), suppressed_by=r.suppressed_by)


@router.post("/rules/reclassify", auth=xhr)
def reclassify(request):
    from .tasks import reclassify_all

    reclassify_all.delay()
    return {"queued": True}


def _unused(_: Any = Count):  # keep the import for future aggregate use without lint noise
    return None
