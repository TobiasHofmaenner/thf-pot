"""Did a request carry back a value one of our answers handed out?

Every value a node mints begins with a 16-hex-character key (`sensor/src/mint.rs`). A request
holding one of those keys anywhere could only have learnt it by reading one of our answers, so this
is a lookup and not a heuristic: find the hex runs, confirm them against the keys we issued.

Where a key comes back decides what it means. In a body, a path or a query it was read and put to
use. In a Cookie header it may be no more than a client that keeps cookies, which most scanners do
not bother with, so that is worth recording but is the weakest of the positions.
"""

import re

from .models import MintedToken

KEY_LEN = 16
HEX = "0123456789abcdef"
HEX_RUN = re.compile(r"[0-9a-f]{%d,}" % KEY_LEN)
SCAN_BODY_BYTES = 1024 * 1024  # as much of a body as the rules see, for the same reason
MAX_CANDIDATES = 200  # per request
MAX_BATCH_CANDIDATES = 20000


def is_key(s) -> bool:
    return isinstance(s, str) and len(s) == KEY_LEN and all(c in HEX for c in s)


def candidates(event, body: bytes = b"") -> dict[str, str]:
    """Every 16-character hex window in the request, mapped to where it was found. Scanned
    most-telling-first, so a key present in several places is reported at the best one."""
    found: dict[str, str] = {}

    def scan(where: str, text: str):
        if not text or len(found) >= MAX_CANDIDATES:
            return
        for m in HEX_RUN.finditer(text.lower()):
            run = m.group(0)
            for i in range(len(run) - KEY_LEN + 1):
                found.setdefault(run[i : i + KEY_LEN], where)
                if len(found) >= MAX_CANDIDATES:
                    return

    scan("body", bytes(body or b"")[:SCAN_BODY_BYTES].decode("latin-1"))
    scan("query", event.query)
    scan("path", event.path)
    for k, v in event.headers or []:
        scan("cookie" if str(k).lower() == "cookie" else "header", str(v))
    return found


def detect(events, ids: dict) -> int:
    """Record on each freshly stored event whether it carried one of our keys back, and where.

    `events` are Event objects with `_sample` attached by the ingest path; `ids` maps ulid to pk.
    """
    from .models import Event

    cand: dict[str, list[tuple[str, str]]] = {}
    for e in events:
        if len(cand) >= MAX_BATCH_CANDIDATES:
            break
        for key, where in candidates(e, getattr(e, "_sample", None) or b"").items():
            cand.setdefault(key, []).append((e.ulid, where))
    if not cand:
        return 0
    keys = list(cand)
    n = 0
    for i in range(0, len(keys), 5000):
        for key in MintedToken.objects.filter(key__in=keys[i : i + 5000]).values_list("key", flat=True):
            for ulid, where in cand[key]:
                pk = ids.get(ulid)
                if pk and Event.objects.filter(pk=pk).update(minted_return=where, minted_return_key=key):
                    n += 1
    return n
