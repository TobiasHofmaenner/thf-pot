"""Node-facing endpoints (docs/PROTOCOL.md). Bearer token → Node; everything else is 401."""

import gzip
import json
import logging
import zlib

from django.utils import timezone
from ninja import Router, Schema
from ninja.errors import HttpError
from ninja.security import HttpBearer

from apps.core.net import client_ip
from apps.events import geo

from .ingest import ingest_batch
from .models import Node

log = logging.getLogger(__name__)
router = Router(tags=["nodes"])

# Decompressed. A node batch is at most 1 MiB, unless one record carries a full-size body: 64 MiB
# read on the node is ~86 MiB of base64 in the line. The node itself skips lines above 128 MiB.
MAX_BATCH_BYTES = 128 * 1024 * 1024


class NodeAuth(HttpBearer):
    def authenticate(self, request, token):
        return Node.authenticate(token)


auth = NodeAuth()


def _decode_body(request) -> bytes:
    raw = request.body
    enc = request.headers.get("Content-Encoding", "").lower()
    if enc == "gzip":
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = d.decompress(raw, MAX_BATCH_BYTES + 1)
            if len(out) > MAX_BATCH_BYTES or d.unconsumed_tail:
                raise HttpError(413, "batch too large")
            return out
        except (zlib.error, EOFError, gzip.BadGzipFile) as e:
            raise HttpError(400, "bad gzip") from e
    if enc not in ("", "identity"):
        raise HttpError(415, f"unsupported Content-Encoding {enc}")
    return raw


@router.post("/ingest", auth=auth, response={202: dict})
def ingest(request):
    node = request.auth
    lines = _decode_body(request).splitlines()  # a batch may be one ~90 MB line: keep one copy, not two
    records, bad_lines = [], 0
    for line in lines:
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except ValueError:
            bad_lines += 1
    if not records and bad_lines:
        raise HttpError(400, "no parseable records")
    result = ingest_batch(node, records)
    result["rejected"] += bad_lines
    if result["rejected"]:
        log.warning("node %s: %d record(s) rejected in a batch of %d", node.name, result["rejected"], len(records) + bad_lines)
    return 202, result


class HeartbeatIn(Schema):
    ts: str = ""
    version: str = ""
    domains: list[str] = []
    cursor_file: str = ""
    cursor_offset: int = 0
    uptime_s: int = 0
    state: str = ""
    detail: dict = {}


@router.post("/heartbeat", auth=auth)
def heartbeat(request, hb: HeartbeatIn):
    node = request.auth
    now = timezone.now()
    body = hb.dict()
    body["received_at"] = now.isoformat(timespec="seconds")
    body["domains"] = [str(d)[:253] for d in body["domains"][:50]]
    ip = client_ip(request)
    fields = {"last_heartbeat": body, "last_seen_at": now, "public_ip": ip}
    if node.first_seen_at is None:
        fields["first_seen_at"] = now
    if ip and (ip != node.public_ip or node.lat is None):
        # Where the node is: the map draws arcs to it.
        g = geo.lookup(ip)
        fields.update(cc=g.get("cc", "") or "", city=g.get("city", "") or "", lat=g.get("lat"), lon=g.get("lon"))
    state = body.pop("state", "")[:32]
    detail = body.pop("detail", {})
    if state:
        if state != node.state or detail != (node.state_detail or {}):
            fields["state_changed_at"] = now
        fields["state"] = state
        fields["state_detail"] = detail if isinstance(detail, dict) else {}
        log.info("node %s: state %s", node.name, state)
    Node.objects.filter(pk=node.pk).update(**fields)
    return {"ok": True, "your_ip": ip}
