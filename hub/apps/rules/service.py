"""One place that validates and saves rules; the JSON API and the htmx page both call it."""

import re

from django.db import transaction

from . import engine, export, sigma
from .models import Rule

NAME_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._\-/:()+]{0,63}$")
ORIGINS = {o for o, _ in Rule.ORIGINS}


class ValidationError(ValueError):
    pass


def _list(v, maxlen) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        v = re.split(r"[\s,;]+", v)
    out, seen = [], set()
    for x in v:
        x = str(x).strip()
        if x and x not in seen and len(x) <= maxlen:
            seen.add(x)
            out.append(x)
    return out


def validate_detection(text: str) -> sigma.Detection:
    try:
        return sigma.parse_detection(text)
    except sigma.RuleError as e:
        raise ValidationError(str(e)) from None


def apply(rule: Rule, data: dict, partial: bool = False) -> Rule:
    """Set fields from a dict (JSON body or form). Raises ValidationError with a human message."""
    def has(k):
        return k in data and not (partial and data[k] is None)

    if has("name"):
        name = str(data["name"]).strip()
        if not NAME_RX.match(name):
            raise ValidationError("name: 1–64 characters, letters, digits, space . _ - / : ( ) +")
        if Rule.objects.filter(name=name).exclude(pk=rule.pk).exists():
            raise ValidationError(f"a rule named {name!r} already exists")
        rule.name = name
    elif not rule.name:
        raise ValidationError("name is required")
    if has("title"):
        rule.title = str(data["title"] or "").strip()[:200]
    if has("description"):
        rule.description = str(data["description"] or "").strip()
    if has("origin"):
        if data["origin"] not in ORIGINS:
            raise ValidationError(f"origin must be one of {sorted(ORIGINS)}")
        rule.origin = data["origin"]
    if has("tags"):
        rule.tags = _list(data["tags"], 40)
    if has("cve"):
        rule.cve = [c.upper() for c in _list(data["cve"], 24)]
    if has("severity"):
        try:
            sev = int(data["severity"])
        except (TypeError, ValueError):
            sev = {"benign": 0, "suspicious": 1, "malicious": 2}.get(str(data["severity"]).lower(), -1)
        if sev not in (0, 1, 2):
            raise ValidationError("severity must be 0 benign, 1 suspicious or 2 malicious")
        rule.severity = sev
    if has("enabled"):
        v = data["enabled"]
        rule.enabled = v if isinstance(v, bool) else str(v).lower() in ("1", "true", "yes", "on")
    if has("suppressed_by"):
        rule.suppressed_by = _list(data["suppressed_by"], 64)
    if has("detection"):
        det = data["detection"]
        if isinstance(det, dict):
            import yaml

            det = yaml.safe_dump(det, sort_keys=False, allow_unicode=True)
        rule.detection = str(det or "").strip() + "\n"
    if not rule.detection or not rule.detection.strip():
        raise ValidationError("detection is required")
    validate_detection(rule.detection)
    return rule


def save(rule: Rule, reclassify: bool = True) -> Rule:
    rule.save()
    engine.invalidate()
    if reclassify:
        from .tasks import reclassify_all

        transaction.on_commit(lambda: _queue(reclassify_all))
    return rule


def delete(rule: Rule):
    rule.delete()
    engine.invalidate()
    from .tasks import reclassify_all

    transaction.on_commit(lambda: _queue(reclassify_all))


def _queue(task):
    try:
        task.delay()
    except Exception as e:  # noqa: BLE001 - broker down; the sweep and the next save catch up
        import logging

        logging.getLogger(__name__).warning("reclassify not queued: %s", e)


def to_dict(rule: Rule, with_export: bool = False) -> dict:
    d = {
        "id": rule.pk, "name": rule.name, "title": rule.title, "description": rule.description,
        "origin": rule.origin, "tags": rule.tags, "severity": rule.severity, "severity_name": rule.severity_name,
        "cve": rule.cve, "enabled": rule.enabled, "detection": rule.detection, "suppressed_by": rule.suppressed_by,
        "created_at": rule.created_at.isoformat(timespec="seconds") if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat(timespec="seconds") if rule.updated_at else None,
        "created_by": rule.created_by,
    }
    if with_export:
        d["exportable"] = export.exportability(rule)
    return d
