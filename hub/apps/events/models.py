"""One row per request a node saw. Columns map 1:1 onto node schema v1 (docs/PROTOCOL.md);
anything the hub does not know yet lands in `extra`. Rows are evidence: the ingest path only
inserts, and the only columns ever updated later are the analysis ones (labels, severity) and the
body pointer, which retention releases."""

import hashlib

from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.indexes import GinIndex
from django.db import models


class Body(models.Model):
    """One copy of each distinct request body, keyed by its sha256 (computed on the hub over the
    bytes it stores, never trusted from the node). Events point at it, so a scanner posting the same
    exploit twenty times costs one copy, and "seen before" is a column, not a scan. Retention
    releases the bytes; the event keeps the hash and size as evidence of what was there."""

    sha256 = models.CharField(max_length=64, primary_key=True)
    data = models.BinaryField()
    size = models.BigIntegerField()
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField(db_index=True)

    @classmethod
    def store(cls, data: bytes, seen_at) -> "Body":
        """Get-or-create for a single body (tests, imports); the ingest path does this in bulk."""
        h = hashlib.sha256(data).hexdigest()
        b, created = cls.objects.get_or_create(
            sha256=h, defaults={"data": data, "size": len(data), "first_seen_at": seen_at, "last_seen_at": seen_at}
        )
        if not created and seen_at > b.last_seen_at:
            cls.objects.filter(pk=h).update(last_seen_at=seen_at)
        return b

    def __str__(self):
        return f"{self.sha256[:12]} ({self.size} B)"


class MintedToken(models.Model):
    """A value one of our answers handed out: a session identifier, a form token, a path shown in an
    info page. The key is its first 16 hex characters, which is what a returning request is matched
    on. Nothing recorded here is a secret of ours; the only thing that matters is that the requester
    could not have known it in advance (see `apps/events/minted.py`)."""

    key = models.CharField(max_length=16, primary_key=True)
    node = models.ForeignKey("nodes.Node", on_delete=models.CASCADE, related_name="minted_tokens")
    # The answer that handed it out, for a value minted per request. A node-scoped value belongs to
    # the node rather than to one answer and is stored without an event, so it outlives retention.
    event = models.ForeignKey("events.Event", null=True, blank=True, on_delete=models.CASCADE,
                              related_name="minted_tokens")
    at = models.CharField(max_length=40)  # "cookie", "req:form_token", "node:upload_tmp_dir"
    first_issued_at = models.DateTimeField()
    last_issued_at = models.DateTimeField(db_index=True)

    def __str__(self):
        return f"{self.key} ({self.at})"


class Event(models.Model):
    node = models.ForeignKey("nodes.Node", on_delete=models.PROTECT, related_name="events")
    ulid = models.CharField(max_length=26)
    ts = models.DateTimeField(db_index=True)
    received_at = models.DateTimeField(auto_now_add=True)

    src = models.GenericIPAddressField()
    src_port = models.IntegerField(null=True, blank=True)
    is_self = models.BooleanField(default=False)

    scheme = models.CharField(max_length=8, blank=True, default="")
    http_version = models.CharField(max_length=16, blank=True, default="")
    method = models.CharField(max_length=16)
    host = models.CharField(max_length=253, blank=True, default="")
    target = models.TextField(blank=True, default="")
    path = models.TextField(blank=True, default="")
    query = models.TextField(blank=True, default="")
    headers = models.JSONField(default=list)
    hdr_fp = models.CharField(max_length=16, blank=True, default="", db_index=True)
    content_type = models.CharField(max_length=255, blank=True, default="")

    declared_len = models.BigIntegerField(null=True, blank=True)
    read_len = models.BigIntegerField(default=0)
    truncated = models.BooleanField(default=False)
    # sha256 and size of what the node stored; both stay after retention released the bytes.
    body_sha256 = models.CharField(max_length=64, blank=True, default="", db_index=True)
    body_size = models.BigIntegerField(default=0)
    body = models.ForeignKey(Body, null=True, blank=True, on_delete=models.SET_NULL, related_name="events")
    multipart = models.JSONField(null=True, blank=True)

    flags = ArrayField(models.CharField(max_length=64), default=list, blank=True)
    resp = models.JSONField(default=dict)
    dur_ms = models.IntegerField(default=0)

    # Analysis layer (hub-owned; the only mutable columns). Filled by the rule engine in the worker.
    labels = ArrayField(models.CharField(max_length=64), default=list, blank=True)
    severity = models.SmallIntegerField(null=True, blank=True)
    classified_at = models.DateTimeField(null=True, blank=True)

    # Geo + ASN, filled in by the worker after ingest (DB-IP Lite). geo_at null = not yet done.
    cc = models.CharField(max_length=2, blank=True, default="")
    city = models.CharField(max_length=100, blank=True, default="")
    lat = models.FloatField(null=True, blank=True)
    lon = models.FloatField(null=True, blank=True)
    asn = models.IntegerField(null=True, blank=True)
    as_name = models.CharField(max_length=200, blank=True, default="")
    geo_at = models.DateTimeField(null=True, blank=True)

    # Did this request carry back a value one of our answers handed out, and where: body, query,
    # path, header or cookie. Empty means it did not, which is what a precomputed payload looks like.
    minted_return = models.CharField(max_length=16, blank=True, default="", db_index=True)
    minted_return_key = models.CharField(max_length=16, blank=True, default="")

    extra = models.JSONField(null=True, blank=True)

    # Until the analysis layer lands, these structural flags are what makes a request "suspicious".
    SUSPICIOUS_FLAGS = ("mp:upload_progress_field", "mp:excessive_part_headers", "mp:many_empty_file_parts",
                        "mp:deep_nesting", "mp:huge_part_count", "mp:preamble")

    @property
    def sev(self) -> str:
        if self.severity is not None:
            return "malicious" if self.severity >= 2 else "suspicious" if self.severity == 1 else "benign"
        return "suspicious" if any(f in self.SUSPICIOUS_FLAGS for f in self.flags) else "benign"

    @property
    def body_bytes(self) -> bytes:
        """The stored body; empty when there was none or retention released it. Use select_related("body")."""
        return bytes(self.body.data) if self.body_id else b""

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["node", "ulid"], name="uniq_event_node_ulid"),
        ]
        indexes = [
            models.Index(fields=["src", "ts"], name="event_src_ts"),
            models.Index(fields=["node", "ts"], name="event_node_ts"),
            models.Index(fields=["geo_at"], name="event_geo_at"),
            models.Index(fields=["classified_at"], name="event_classified_at"),
            GinIndex(fields=["flags"], name="event_flags_gin"),
            GinIndex(fields=["labels"], name="event_labels_gin"),
        ]

    def __str__(self):
        return f"{self.ts:%Y-%m-%d %H:%M:%S} {self.src} {self.method} {self.path}"
