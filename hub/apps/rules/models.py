"""A rule is a Sigma-style detection over one event. Its name is the label an event gets when it
matches; its severity is what the map colours by. `origin` says who wrote it."""

from django.contrib.postgres.fields import ArrayField
from django.db import models


class Rule(models.Model):
    ORIGINS = [("human", "human"), ("local", "local"), ("api", "api"), ("ai", "ai")]
    SEVERITIES = [(0, "benign"), (1, "suspicious"), (2, "malicious")]

    name = models.CharField(max_length=64, unique=True)
    title = models.CharField(max_length=200, blank=True, default="")
    description = models.TextField(blank=True, default="")
    origin = models.CharField(max_length=8, choices=ORIGINS, default="human")
    tags = ArrayField(models.CharField(max_length=40), default=list, blank=True)
    severity = models.SmallIntegerField(choices=SEVERITIES, default=1)
    cve = ArrayField(models.CharField(max_length=24), default=list, blank=True)
    enabled = models.BooleanField(default=True)
    # The Sigma `detection:` block (selections + condition) as YAML text, exactly as authored.
    detection = models.TextField()
    # A generic label says nothing beside the specific one that implies it: dropped when any of these matched.
    suppressed_by = ArrayField(models.CharField(max_length=64), default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=80, blank=True, default="")

    class Meta:
        ordering = ["-severity", "name"]

    def __str__(self):
        return self.name

    @property
    def severity_name(self) -> str:
        return dict(self.SEVERITIES)[self.severity]
