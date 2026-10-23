"""A sensor is a node that ships events. It is identified by a bearer token whose SHA-256 is the
only thing stored here: a dump of this table cannot be used to impersonate a node."""

import hashlib
import re
import secrets
from datetime import timedelta

from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.utils import timezone

ONLINE_WINDOW = timedelta(minutes=3)  # heartbeats come every 60 s


def acme_detail(err: str) -> str:
    """An ACME failure arrives as the client's wrapped error text with the CA's JSON problem
    document inside; the `detail` sentence in there is the part a human needs."""
    m = re.search(r'detail\\?":\s*\\?"([^"\\]+)', err)
    return (m.group(1) if m else err)[:200]


class Sensor(models.Model):
    KIND_WEB = "web-pot"

    name = models.CharField(max_length=80, unique=True)
    kind = models.CharField(max_length=32, default=KIND_WEB)
    domains = ArrayField(models.CharField(max_length=253), default=list, blank=True)
    acme_email = models.EmailField(blank=True, default="")
    notes = models.TextField(blank=True, default="")

    token_sha256 = models.CharField(max_length=64, unique=True)
    token_prefix = models.CharField(max_length=8)
    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    token_rotated_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    last_heartbeat = models.JSONField(null=True, blank=True)
    last_event_at = models.DateTimeField(null=True, blank=True)
    events_total = models.BigIntegerField(default=0)

    # Lifecycle as reported by the node: new → starting → dns_failed* → dns_ok → cert_pending →
    # cert_error* / ready. `new` means the node has never phoned home.
    state = models.CharField(max_length=32, default="new")
    state_detail = models.JSONField(null=True, blank=True)
    state_changed_at = models.DateTimeField(null=True, blank=True)
    first_seen_at = models.DateTimeField(null=True, blank=True)
    public_ip = models.GenericIPAddressField(null=True, blank=True)

    STATES_AFTER_DNS = ("dns_ok", "cert_pending", "cert_error", "ready")

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def mint_token(self) -> str:
        """Set a fresh token on this instance (not saved) and return the plaintext once."""
        token = secrets.token_urlsafe(32)
        self.token_sha256 = self.hash_token(token)
        self.token_prefix = token[:8]
        return token

    @classmethod
    def authenticate(cls, token: str):
        if not token or len(token) > 128:
            return None
        return cls.objects.filter(token_sha256=cls.hash_token(token), is_active=True).first()

    @property
    def online(self) -> bool:
        return bool(self.is_active and self.last_seen_at and timezone.now() - self.last_seen_at < ONLINE_WINDOW)

    @property
    def status(self) -> str:
        if not self.is_active:
            return "revoked"
        if self.last_seen_at is None:
            return "never seen"
        return "online" if self.online else "offline"

    @property
    def version(self) -> str:
        return (self.last_heartbeat or {}).get("version", "")

    def phases(self) -> list[dict]:
        """The deploy checklist the node page shows: deployed → dns → certs → live."""
        d = self.state_detail or {}
        deployed = self.first_seen_at is not None
        if not deployed:
            dns = certs = ("pending", "")
        elif d.get("dns") == "skipped":
            dns, certs = ("skip", "http only"), ("skip", "tls disabled")
        else:
            if self.state == "dns_failed":
                bad = [f"{name} → {', '.join(v.get('resolved') or ['nothing'])}"
                       for name, v in (d.get("domains") or {}).items() if not v.get("ok")]
                dns = ("fail", f"expected {d.get('public_ip', '?')}; " + "; ".join(bad))
            elif self.state in self.STATES_AFTER_DNS:
                dns = ("ok", str(d.get("public_ip", "")))
            else:
                dns = ("pending", "")
            if self.state == "ready":
                certs = ("ok", ", ".join(d.get("certs") or []))
            elif self.state == "cert_error":
                certs = ("fail", acme_detail(str(d.get("error", ""))))
            elif self.state in ("dns_ok", "cert_pending"):
                certs = ("pending", "waiting for the CA")
            else:
                certs = ("pending", "")
        live = ("ok", "") if self.online else (("fail", "no heartbeat") if deployed else ("pending", ""))
        return [
            {"name": "deployed", "status": "ok" if deployed else "pending", "note": ""},
            {"name": "dns", "status": dns[0], "note": dns[1]},
            {"name": "certs", "status": certs[0], "note": certs[1]},
            {"name": "live", "status": live[0], "note": live[1]},
        ]
