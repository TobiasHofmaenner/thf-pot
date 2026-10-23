"""One row per request a sensor saw. Columns map 1:1 onto sensor schema v1 (docs/PROTOCOL.md);
anything the hub does not know yet lands in `extra`. Rows are evidence: the ingest path only
inserts, and the only columns ever updated later are the analysis ones (labels, severity)."""

from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.indexes import GinIndex
from django.db import models


class Event(models.Model):
    sensor = models.ForeignKey("sensors.Sensor", on_delete=models.PROTECT, related_name="events")
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

    # Analysis layer (hub-owned; the only mutable columns).
    labels = ArrayField(models.CharField(max_length=64), default=list, blank=True)
    severity = models.SmallIntegerField(null=True, blank=True)

    extra = models.JSONField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["sensor", "ulid"], name="uniq_event_sensor_ulid"),
        ]
        indexes = [
            models.Index(fields=["src", "ts"], name="event_src_ts"),
            models.Index(fields=["sensor", "ts"], name="event_sensor_ts"),
            GinIndex(fields=["flags"], name="event_flags_gin"),
            GinIndex(fields=["labels"], name="event_labels_gin"),
        ]

    def __str__(self):
        return f"{self.ts:%Y-%m-%d %H:%M:%S} {self.src} {self.method} {self.path}"
