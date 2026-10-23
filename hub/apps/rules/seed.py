"""Load seed.yml into the Rule table. Used by the data migration and by `manage.py seed_rules`."""

import os

import yaml


def load(Rule, path=None) -> tuple[int, int]:
    path = path or os.path.join(os.path.dirname(__file__), "seed.yml")
    with open(path, encoding="utf-8") as f:
        items = yaml.safe_load(f)
    created = updated = 0
    for it in items:
        defaults = {
            "title": it.get("title", ""), "description": (it.get("description") or "").strip(),
            "severity": int(it.get("severity", 1)), "cve": list(it.get("cve") or []), "tags": list(it.get("tags") or []),
            "suppressed_by": list(it.get("suppressed_by") or []), "detection": it["detection"].strip() + "\n",
            "origin": "local", "created_by": "seed",
        }
        existing = Rule.objects.filter(name=it["name"]).first()
        if existing is None:
            Rule.objects.create(name=it["name"], **defaults)
            created += 1
        elif existing.origin == "local":
            for k, v in defaults.items():
                setattr(existing, k, v)
            existing.save()
            updated += 1
    return created, updated
