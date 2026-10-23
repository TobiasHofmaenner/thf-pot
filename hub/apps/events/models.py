"""One row per request a node saw. Columns map 1:1 onto node schema v1 (docs/PROTOCOL.md);
anything the hub does not know yet lands in `extra`. Rows are evidence: the ingest path only
inserts, and the only columns ever updated later are the analysis ones (labels, severity)."""

from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.indexes import GinIndex
from django.db import models


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
    body_sha256 = models.CharField(max_length=64, blank=True, default="", db_index=True)
    body_sample = models.BinaryField(null=True, blank=True)
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

    extra = models.JSONField(null=True, blank=True)

    # Until the analysis layer lands, these structural flags are what makes a request "suspicious".
    SUSPICIOUS_FLAGS = ("mp:upload_progress_field", "mp:excessive_part_headers", "mp:many_empty_file_parts",
                        "mp:deep_nesting", "mp:huge_part_count", "mp:preamble")

    @property
    def sev(self) -> str:
        if self.severity is not None:
            return "malicious" if self.severity >= 2 else "suspicious" if self.severity == 1 else "benign"
        return "suspicious" if any(f in self.SUSPICIOUS_FLAGS for f in self.flags) else "benign"

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
