"""A Sigma subset: parse a `detection:` block, evaluate it against one event, and keep the parsed
form around for the exporters. Fields and operators are chosen so that what a WAF can check is a
strict subset of what we can check here.

    detection:
      sel:
        path|contains: ['/.env', '/.git/config']
        method: [GET, HEAD]
      hostile:
        path|re: '\\.\\./'
      condition: sel and not hostile

Keys are `field` or `field|modifier[|modifier]`. Values are a scalar or a list (list = OR, unless
`|all`). Keys inside one map are ANDed; a selection given as a list of maps is OR across the maps.
String matching is case-insensitive unless `|cased`; `|re` is case-sensitive unless `|re|i`.
Condition grammar: identifiers, `and`, `or`, `not`, parentheses, `1 of x*`, `all of x*`, `them`.
"""

import fnmatch
import re
from dataclasses import dataclass, field

import yaml

from apps.nodes.hosts import match_host


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class FieldSpec:
    kind: str  # str | int | bool | list
    modsec: str | None = None  # ModSecurity/Coraza variable, None = not exportable
    cf: str | None = None  # Cloudflare expression, None = not exportable
    doc: str = ""


# Everything a rule may look at. The event row is the only source; nothing here is third-party data.
FIELDS: dict[str, FieldSpec] = {
    "method": FieldSpec("str", "REQUEST_METHOD", "http.request.method", "request method"),
    "path": FieldSpec("str", "REQUEST_FILENAME", "http.request.uri.path", "path without the query string"),
    "query": FieldSpec("str", "QUERY_STRING", "http.request.uri.query", "query string without the leading ?"),
    "target": FieldSpec("str", "REQUEST_URI", "http.request.uri", "path and query as received"),
    "host": FieldSpec("str", "REQUEST_HEADERS:Host", "http.host", "Host header"),
    "ua": FieldSpec("str", "REQUEST_HEADERS:User-Agent", "http.user_agent", "User-Agent header"),
    "content_type": FieldSpec("str", "REQUEST_HEADERS:Content-Type", 'http.request.headers["content-type"][0]', "Content-Type header"),
    "headers": FieldSpec("str", "REQUEST_HEADERS", None, "every header value, one per line"),
    "body": FieldSpec("str", "REQUEST_BODY", "http.request.body.raw", "stored body sample as latin-1 text"),
    "src": FieldSpec("str", "REMOTE_ADDR", "ip.src", "source address"),
    "cc": FieldSpec("str", None, "ip.geoip.country", "source country (DB-IP)"),
    "declared_len": FieldSpec("int", "REQUEST_HEADERS:Content-Length", 'http.request.headers["content-length"][0]', "Content-Length as declared"),
    "read_len": FieldSpec("int", None, "http.request.body.size", "body bytes the node actually read"),
    "truncated": FieldSpec("bool", None, None, "client offered more than the node reads"),
    "flags": FieldSpec("list", None, None, "the node's structural flags"),
    "mp.boundary": FieldSpec("str", None, None, "multipart boundary"),
    "mp.parts": FieldSpec("int", None, None, "multipart parts"),
    "mp.preamble_len": FieldSpec("int", None, None, "bytes before the first boundary"),
    "mp.epilogue_len": FieldSpec("int", None, None, "bytes after the closing boundary"),
    "mp.max_headers_in_part": FieldSpec("int", None, None, ""),
    "mp.max_name_depth": FieldSpec("int", None, None, ""),
    "mp.file_parts": FieldSpec("int", None, None, ""),
    "mp.empty_file_parts": FieldSpec("int", None, None, ""),
    "mp.session_upload_progress": FieldSpec("bool", None, None, "PHP_SESSION_UPLOAD_PROGRESS field present"),
    "mp.names": FieldSpec("str", None, None, "multipart field names, one per line"),
    "resp.tier": FieldSpec("str", None, None, "persona tier the node answered with"),
    "resp.kind": FieldSpec("str", None, None, "what the node answered"),
    "node": FieldSpec("str", None, None, "node name (the server)"),
    "sensor": FieldSpec("str", None, None, "the hostname of ours the request was aimed at; empty if not ours"),
    "hdr_fp": FieldSpec("str", None, None, "header-order fingerprint"),
    "host_known": FieldSpec("bool", None, None, "Host header is one of the node's own domains"),
    "self": FieldSpec("bool", None, None, "request from an operator address"),
    "minted_return": FieldSpec("str", None, None,
                               "where a value one of our answers handed out came back: "
                               "body|query|path|header|cookie, empty if none did"),
}
HEADER_PREFIX = "header."
RULE_BODY_BYTES = 1024 * 1024
STR_OPS = ("eq", "contains", "startswith", "endswith", "re")
NUM_OPS = ("eq", "gt", "gte", "lt", "lte")


def field_spec(name: str) -> FieldSpec:
    if name.startswith(HEADER_PREFIX):
        h = name[len(HEADER_PREFIX):].lower()
        if not re.fullmatch(r"[a-z0-9-]+", h):
            raise RuleError(f"bad header field {name!r}")
        return FieldSpec("str", f"REQUEST_HEADERS:{h}", f'http.request.headers["{h}"][0]', f"{h} header")
    try:
        return FIELDS[name]
    except KeyError:
        raise RuleError(f"unknown field {name!r}") from None


@dataclass
class Match:
    field: str
    op: str
    values: list
    all: bool = False
    cased: bool = False
    ci_re: bool = False
    _rx: list = field(default_factory=list, repr=False)

    def compile(self):
        spec = field_spec(self.field)
        if spec.kind in ("int",):
            if self.op not in NUM_OPS:
                raise RuleError(f"{self.field}: {self.op} is not a numeric operator")
            try:
                self.values = [int(v) for v in self.values]
            except (TypeError, ValueError):
                raise RuleError(f"{self.field}: numeric value expected") from None
            return self
        if spec.kind == "bool":
            if self.op != "eq":
                raise RuleError(f"{self.field}: only equality works on a boolean")
            self.values = [_as_bool(v) for v in self.values]
            return self
        if self.op not in STR_OPS:
            raise RuleError(f"{self.field}: {self.op} is not a string operator")
        self.values = ["" if v is None else str(v) for v in self.values]
        flags = re.S | (re.I if (self.ci_re if self.op == "re" else not self.cased) else 0)
        self._rx = []
        for v in self.values:
            if self.op == "re":
                try:
                    self._rx.append(re.compile(v, flags))
                except re.error as e:
                    raise RuleError(f"{self.field}: bad regex {v!r}: {e}") from None
            elif self.op == "eq" and ("*" in v or "?" in v):
                self._rx.append(re.compile(fnmatch.translate(v), flags))
            else:
                self._rx.append(None)
        return self

    def _one(self, hay, i: int) -> bool:
        v = self.values[i]
        if isinstance(hay, bool) or isinstance(hay, int):
            if self.op == "eq":
                return hay == v
            return {"gt": hay > v, "gte": hay >= v, "lt": hay < v, "lte": hay <= v}[self.op]
        rx = self._rx[i]
        if rx is not None:
            return bool(rx.search(hay)) if self.op == "re" else bool(rx.match(hay))
        h, n = (hay, v) if self.cased else (hay.lower(), v.lower())
        return {"eq": h == n, "contains": n in h, "startswith": h.startswith(n), "endswith": h.endswith(n)}[self.op]

    def test(self, hay) -> bool:
        if hay is None:
            return False
        if isinstance(hay, list):
            hits = [any(self._one(x, i) for x in hay) for i in range(len(self.values))]
        else:
            hits = [self._one(hay, i) for i in range(len(self.values))]
        return all(hits) if self.all else any(hits)


def _as_bool(v):
    if isinstance(v, bool):
        return v
    if str(v).lower() in ("true", "yes", "1"):
        return True
    if str(v).lower() in ("false", "no", "0"):
        return False
    raise RuleError(f"not a boolean: {v!r}")


def parse_key(key: str) -> tuple[str, str, bool, bool, bool]:
    parts = str(key).split("|")
    fld, mods = parts[0].strip(), [m.strip() for m in parts[1:]]
    op, all_, cased, ci = "eq", False, False, False
    for m in mods:
        if m in ("contains", "startswith", "endswith", "re", "gt", "gte", "lt", "lte"):
            if op != "eq":
                raise RuleError(f"{key}: two operators")
            op = m
        elif m == "all":
            all_ = True
        elif m == "cased":
            cased = True
        elif m == "i":
            ci = True
        else:
            raise RuleError(f"{key}: unknown modifier {m!r}")
    return fld, op, all_, cased, ci


def parse_selection(name: str, body) -> list[list[Match]]:
    """A selection is OR over maps, each map AND over its keys."""
    maps = body if isinstance(body, list) else [body]
    out = []
    for m in maps:
        if not isinstance(m, dict) or not m:
            raise RuleError(f"selection {name!r}: expected a map of field: value")
        group = []
        for k, v in m.items():
            fld, op, all_, cased, ci = parse_key(k)
            vals = v if isinstance(v, list) else [v]
            if not vals:
                raise RuleError(f"{name}.{k}: empty value list")
            group.append(Match(fld, op, list(vals), all_, cased, ci).compile())
        out.append(group)
    return out


# ---- condition ---------------------------------------------------------------------------------
_TOK = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|\bthem\b|[A-Za-z0-9_*.-]+)")


def parse_condition(text: str, names: list[str]):
    toks = []
    pos = 0
    text = (text or "").strip()
    if not text:
        raise RuleError("condition is required")
    while pos < len(text):
        m = _TOK.match(text, pos)
        if not m:
            raise RuleError(f"condition: cannot read {text[pos:pos+12]!r}")
        toks.append(m.group(1))
        pos = m.end()
    i = 0

    def peek():
        return toks[i] if i < len(toks) else None

    def take():
        nonlocal i
        t = toks[i]
        i += 1
        return t

    def expr():
        node = term()
        while peek() == "or":
            take()
            node = ("or", [node, term()])
        return node

    def term():
        node = factor()
        while peek() == "and":
            take()
            node = ("and", [node, factor()])
        return node

    def factor():
        t = peek()
        if t is None:
            raise RuleError("condition: unexpected end")
        if t == "not":
            take()
            return ("not", factor())
        if t == "(":
            take()
            node = expr()
            if take() != ")":
                raise RuleError("condition: missing )")
            return node
        if t in ("1 of", "all of"):
            take()
            pat = take()
            chosen = names if pat == "them" else [n for n in names if fnmatch.fnmatchcase(n, pat)]
            if not chosen:
                raise RuleError(f"condition: nothing matches {pat!r}")
            return ("or" if t == "1 of" else "and", [("sel", n) for n in chosen])
        take()
        if t not in names:
            raise RuleError(f"condition: unknown selection {t!r}")
        return ("sel", t)

    node = expr()
    if peek() is not None:
        raise RuleError(f"condition: trailing {peek()!r}")
    return node


@dataclass
class Detection:
    selections: dict
    condition: tuple
    condition_text: str

    def fields(self) -> set[str]:
        return {m.field for groups in self.selections.values() for g in groups for m in g}

    def evaluate(self, ctx: dict) -> bool:
        return _eval(self.condition, self.selections, ctx)


def _eval(node, sels, ctx) -> bool:
    kind = node[0]
    if kind == "sel":
        return any(all(m.test(ctx.get(m.field)) for m in group) for group in sels[node[1]])
    if kind == "not":
        return not _eval(node[1], sels, ctx)
    if kind == "and":
        return all(_eval(n, sels, ctx) for n in node[1])
    return any(_eval(n, sels, ctx) for n in node[1])


def parse_detection(text) -> Detection:
    """Accepts the YAML text of a `detection:` block (with or without the `detection:` key)."""
    try:
        doc = yaml.safe_load(text) if isinstance(text, str) else text
    except yaml.YAMLError as e:
        raise RuleError(f"YAML: {e}") from None
    if isinstance(doc, dict) and "detection" in doc and isinstance(doc["detection"], dict):
        doc = doc["detection"]
    if not isinstance(doc, dict):
        raise RuleError("detection must be a map of selections plus a condition")
    cond = doc.get("condition")
    sels = {}
    for name, body in doc.items():
        if name == "condition":
            continue
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", str(name)):
            raise RuleError(f"bad selection name {name!r}")
        sels[str(name)] = parse_selection(str(name), body)
    if not sels:
        raise RuleError("at least one selection is required")
    if cond is None:
        cond = " or ".join(sels) if len(sels) == 1 else None
        if cond is None:
            raise RuleError("condition is required when there is more than one selection")
    return Detection(sels, parse_condition(str(cond), list(sels)), str(cond))


# ---- evaluation context from an Event ----------------------------------------------------------
def context(e, known_hosts=()) -> dict:
    headers = e.headers or []
    hdr = {}
    for k, v in headers:
        hdr.setdefault(str(k).lower(), str(v))
    mp = e.multipart or {}
    # Rules see the first MiB: enough for any payload we have met, and bounded regex cost per event.
    # engine.for_rules() already cuts it in the database (body_head); a plain row is cut here.
    raw = e.body_head if hasattr(e, "body_head") else (e.body.data if e.body_id else None)
    body = bytes(raw or b"")[:RULE_BODY_BYTES].decode("latin-1")
    ctx = {
        "method": e.method, "path": e.path, "query": e.query, "target": e.target or e.path,
        "host": e.host, "ua": hdr.get("user-agent", ""), "content_type": e.content_type,
        "headers": "\n".join(str(v) for _k, v in headers), "body": body, "src": e.src, "cc": e.cc or "",
        "declared_len": e.declared_len if e.declared_len is not None else -1, "read_len": e.read_len,
        "truncated": e.truncated, "flags": list(e.flags or []),
        "mp.boundary": mp.get("boundary") or "", "mp.parts": int(mp.get("parts") or 0),
        "mp.preamble_len": int(mp.get("preamble_len") or 0), "mp.epilogue_len": int(mp.get("epilogue_len") or 0),
        "mp.max_headers_in_part": int(mp.get("max_headers_in_part") or 0), "mp.max_name_depth": int(mp.get("max_name_depth") or 0),
        "mp.file_parts": int(mp.get("file_parts") or 0), "mp.empty_file_parts": int(mp.get("empty_file_parts") or 0),
        "mp.session_upload_progress": bool(mp.get("session_upload_progress")), "mp.names": "\n".join(mp.get("names_sample") or []),
        "resp.tier": (e.resp or {}).get("tier", ""), "resp.kind": (e.resp or {}).get("kind", ""),
        "node": getattr(getattr(e, "node", None), "name", ""), "hdr_fp": e.hdr_fp,
        "host_known": bool(match_host(e.host, known_hosts)), "self": e.is_self,
        "minted_return": e.minted_return,
        "sensor": e.host if match_host(e.host, known_hosts) else "",
    }
    for k, v in hdr.items():
        ctx[HEADER_PREFIX + k] = v
    return ctx
