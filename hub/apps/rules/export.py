"""Compile a rule for the edge. Two targets today: ModSecurity / Coraza `SecRule` chains (nginx,
Traefik's coraza plugin) and Cloudflare custom-rule expressions. A rule that looks at something only
the honeypot knows (multipart framing, node flags, node tier) cannot be exported and says why."""

import re

from .sigma import Detection, Match, field_spec, parse_detection

MAX_GROUPS = 32


class NotExportable(ValueError):
    pass


# ---- condition → DNF --------------------------------------------------------------------------
def _nnf(node, neg=False):
    k = node[0]
    if k == "sel":
        return ("nsel" if neg else "sel", node[1])
    if k == "not":
        return _nnf(node[1], not neg)
    kids = [_nnf(n, neg) for n in node[1]]
    return ("or" if (k == "and") == neg else "and", kids)


def to_dnf(node) -> list[list[tuple[str, bool]]]:
    """[[(selection, negated), ...], ...]: OR of ANDs."""
    n = _nnf(node)

    def walk(x):
        if x[0] in ("sel", "nsel"):
            return [[(x[1], x[0] == "nsel")]]
        if x[0] == "or":
            out = []
            for c in x[1]:
                out.extend(walk(c))
            return out
        prod = [[]]
        for c in x[1]:
            prod = [a + b for a in prod for b in walk(c)]
            if len(prod) > MAX_GROUPS:
                raise NotExportable("condition expands to too many alternatives")
        return prod

    return walk(n)


# ---- ModSecurity / Coraza --------------------------------------------------------------------
def _q(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"') if "@rx" not in s else s


def _rx_alt(values, cased, anchor_l="", anchor_r="", escape=True, ci=False) -> str:
    alts = "|".join(re.escape(v) if escape else f"(?:{v})" for v in values)
    pat = f"{anchor_l}(?:{alts}){anchor_r}"
    return ("(?i)" if (ci or not cased) and escape or (ci and not escape) else "") + pat


def _modsec_ops(m: Match, negated: bool) -> list[tuple[str, str]]:
    """-> [(operator-with-arg, transformations)] one SecRule each (several when |all)."""
    spec = field_spec(m.field)
    if spec.modsec is None:
        raise NotExportable(f"field {m.field!r} exists only on the honeypot")
    bang = "!" if negated else ""
    if spec.kind in ("int", "bool"):
        op = {"eq": "@eq", "gt": "@gt", "gte": "@ge", "lt": "@lt", "lte": "@le"}[m.op]
        if len(m.values) > 1 and m.op != "eq":
            raise NotExportable(f"{m.field}: several numeric bounds")
        return [(f"{bang}{op} {int(v)}", "t:none") for v in m.values] if m.all or len(m.values) == 1 else \
            [(f"{bang}@rx ^(?:{'|'.join(str(int(v)) for v in m.values)})$", "t:none")]
    vals = m.values
    tl = "t:none" if m.cased else "t:none,t:lowercase"
    low = (lambda s: s) if m.cased else (lambda s: s.lower())
    groups = [[v] for v in vals] if (m.all and len(vals) > 1) else [vals]
    out = []
    for vs in groups:
        if m.op == "re":
            pat = _rx_alt(vs, cased=True, escape=False, ci=m.ci_re) if len(vs) > 1 else (("(?i)" if m.ci_re else "") + vs[0])
            out.append((f"{bang}@rx {pat}", "t:none"))
        elif m.op == "contains":
            if len(vs) == 1:
                out.append((f"{bang}@contains {low(vs[0])}", tl))
            elif not m.cased and all(" " not in v for v in vs):
                out.append((f"{bang}@pm {' '.join(vs)}", "t:none"))  # @pm is case-insensitive
            else:
                out.append((f"{bang}@rx {_rx_alt(vs, m.cased)}", "t:none"))
        elif m.op == "startswith":
            out.append((f"{bang}@beginsWith {low(vs[0])}", tl) if len(vs) == 1 else (f"{bang}@rx {_rx_alt(vs, m.cased, '^')}", "t:none"))
        elif m.op == "endswith":
            out.append((f"{bang}@endsWith {low(vs[0])}", tl) if len(vs) == 1 else (f"{bang}@rx {_rx_alt(vs, m.cased, '', '$')}", "t:none"))
        else:  # eq
            if any("*" in v or "?" in v for v in vs):
                pats = [re.escape(v).replace("\\*", ".*").replace("\\?", ".") for v in vs]
                out.append((f"{bang}@rx {'(?i)' if not m.cased else ''}^(?:{'|'.join(pats)})$", "t:none"))
            elif len(vs) == 1:
                out.append((f"{bang}@streq {low(vs[0])}", tl))
            else:
                out.append((f"{bang}@rx {_rx_alt(vs, m.cased, '^', '$')}", "t:none"))
    return out


def modsec(rule, det: Detection | None = None, mode: str = "detect", base_id: int = 9_000_000) -> str:
    det = det or parse_detection(rule.detection)
    groups = []
    for conj in to_dnf(det.condition):
        # each literal may itself be OR over maps → expand
        alts = [[]]
        for name, negated in conj:
            maps = det.selections[name]
            if negated and len(maps) > 1:
                raise NotExportable(f"negated selection {name!r} with several alternatives")
            if negated and len(maps[0]) > 1:
                raise NotExportable(f"negated selection {name!r} with several fields (NOT of an AND)")
            alts = [a + [(m, negated) for m in grp] for a in alts for grp in maps]
            if len(alts) > MAX_GROUPS:
                raise NotExportable("rule expands to too many alternatives")
        groups.extend(alts)
    action = "deny,status:403" if mode == "block" else "pass"
    sev = {0: "NOTICE", 1: "WARNING", 2: "CRITICAL"}[rule.severity]
    msg = rule.name.replace("'", "")
    tags = ",".join(f"tag:'thf-pot/{t}'" for t in (["thf-pot"] + list(rule.tags) + list(rule.cve)))
    lines = [f"# {rule.name}: {rule.title or ''} (thf-pot, origin {rule.origin}, severity {rule.severity_name})"]
    for gi, group in enumerate(groups):
        checks = []
        for m, negated in group:
            var = field_spec(m.field).modsec
            for op, tr in _modsec_ops(m, negated):
                checks.append((var, op, tr))
        rid = base_id + rule.pk * 10 + gi if rule.pk else base_id + gi
        for ci, (var, op, tr) in enumerate(checks):
            first, last = ci == 0, ci == len(checks) - 1
            acts = [f"id:{rid}", "phase:2", action, "log", f"msg:'thf-pot: {msg}'", f"severity:'{sev}'", tags] if first else []
            acts.append(tr)
            if not last:
                acts.append("chain")
            indent = "" if first else "    "
            lines.append(f'{indent}SecRule {var} "{_q(op)}" "{",".join(a for a in acts if a)}"')
    return "\n".join(lines) + "\n"


# ---- Cloudflare -------------------------------------------------------------------------------
def _cf_str(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _cf_match(m: Match) -> str:
    spec = field_spec(m.field)
    if spec.cf is None:
        raise NotExportable(f"field {m.field!r} exists only on the honeypot")
    f = spec.cf
    if spec.kind in ("int", "bool"):
        op = {"eq": "eq", "gt": "gt", "gte": "ge", "lt": "lt", "lte": "le"}[m.op]
        parts = [f"{f} {op} {str(v).lower() if spec.kind == 'bool' else int(v)}" for v in m.values]
        return _join(parts, m.all)
    if m.field == "src":
        if m.op != "eq":
            raise NotExportable("src: only equality exports to Cloudflare")
        return f"{f} in {{{' '.join(m.values)}}}" if len(m.values) > 1 else f"{f} eq {m.values[0]}"
    lf = f if m.cased else f"lower({f})"
    norm = (lambda s: s) if m.cased else (lambda s: s.lower())
    if m.op == "re":
        parts = [f"{f} matches {_cf_str(('(?i)' if m.ci_re else '') + v)}" for v in m.values]
    elif m.op == "contains":
        parts = [f"{lf} contains {_cf_str(norm(v))}" for v in m.values]
    elif m.op == "startswith":
        parts = [f"starts_with({lf}, {_cf_str(norm(v))})" for v in m.values]
    elif m.op == "endswith":
        parts = [f"ends_with({lf}, {_cf_str(norm(v))})" for v in m.values]
    else:
        if any("*" in v or "?" in v for v in m.values):
            parts = [f"{f} wildcard {_cf_str(v)}" for v in m.values]
        elif len(m.values) > 1 and not m.all:
            return f"{lf} in {{{' '.join(_cf_str(norm(v)) for v in m.values)}}}"
        else:
            parts = [f"{lf} eq {_cf_str(norm(v))}" for v in m.values]
    return _join(parts, m.all)


def _join(parts, all_):
    if len(parts) == 1:
        return parts[0]
    return "(" + (" and " if all_ else " or ").join(parts) + ")"


def _cf_node(node, sels) -> str:
    k = node[0]
    if k == "sel":
        maps = sels[node[1]]
        alts = ["(" + " and ".join(_cf_match(m) for m in grp) + ")" if len(grp) > 1 else _cf_match(grp[0]) for grp in maps]
        return alts[0] if len(alts) == 1 else "(" + " or ".join(alts) + ")"
    if k == "not":
        return f"not {_cf_node(node[1], sels)}"
    inner = [_cf_node(n, sels) for n in node[1]]
    return "(" + f" {k} ".join(inner) + ")"


def cloudflare(rule, det: Detection | None = None) -> str:
    det = det or parse_detection(rule.detection)
    expr = _cf_node(det.condition, det.selections)
    return expr[1:-1] if expr.startswith("(") and expr.endswith(")") and _balanced(expr[1:-1]) else expr


def _balanced(s: str) -> bool:
    depth = 0
    for ch in s:
        depth += (ch == "(") - (ch == ")")
        if depth < 0:
            return False
    return depth == 0


def exportability(rule, det: Detection | None = None) -> dict:
    """What the editor shows next to a rule: can it travel, and if not, why."""
    out = {}
    try:
        det = det or parse_detection(rule.detection)
    except Exception as e:  # noqa: BLE001
        return {"modsec": str(e), "cloudflare": str(e)}
    for name, fn in (("modsec", lambda: modsec(rule, det)), ("cloudflare", lambda: cloudflare(rule, det))):
        try:
            fn()
            out[name] = ""
        except NotExportable as e:
            out[name] = str(e)
    return out
