import hashlib
import json
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.nodes.models import Node

from . import geo, retention, storage, tasks
from .models import Body, Event


def mk_node(name="s1"):
    s = Node(name=name, domains=[f"{name}.example.org"], lat=1.3, lon=103.8, cc="SG", city="Singapore", public_ip="5.0.0.1")
    s.mint_token()
    s.save()
    return s


_n = [0]


def mk_event(node, **over):
    """body_sample= is stored the way ingest does it: one Body row per distinct sha256."""
    _n[0] += 1
    kw = dict(node=node, ulid=f"01JAX{_n[0]:021d}", ts=timezone.now(),
              src="203.0.113.9", method="GET", host="s1.example.org", target="/x", path="/x",
              headers=[["user-agent", "curl/8"]], resp={"status": 200, "tier": "full", "kind": "index", "bundle": "php", "profile": "p"},
              body_sample=b"abc")
    kw.update(over)
    sample = kw.pop("body_sample", None)
    if sample:
        b = Body.store(sample, kw["ts"])
        kw.update(body=b, body_size=len(sample), body_sha256=b.sha256)
    return Event.objects.create(**kw)


@override_settings(GEOIP_DIR="/nonexistent")
class GeoTests(TestCase):
    def setUp(self):
        geo._reader.cache_clear()

    def test_missing_database_means_no_geo_not_an_error(self):
        self.assertEqual(geo.lookup("203.0.113.9"), {})
        self.assertEqual(geo.version(), "none")

    def test_enrich_marks_rows_done_and_uses_lookup(self):
        s = mk_node()
        a, b = mk_event(s), mk_event(s, src="198.51.100.7")
        with mock.patch.object(geo, "lookup", return_value={"cc": "DE", "city": "Berlin", "lat": 52.5, "lon": 13.4, "asn": 3320, "as_name": "DTAG"}) as m:
            self.assertEqual(tasks.enrich([a.id, b.id]), 2)
            self.assertEqual(m.call_count, 2)  # one per distinct address
        a.refresh_from_db()
        self.assertEqual((a.cc, a.city, a.lat, a.lon, a.asn, a.as_name), ("DE", "Berlin", 52.5, 13.4, 3320, "DTAG"))
        self.assertIsNotNone(a.geo_at)
        self.assertEqual(tasks.enrich([a.id, b.id]), 0)  # idempotent
        self.assertEqual(tasks.enrich_pending(), 0)


class EventsApiTests(TestCase):
    def setUp(self):
        self.s = mk_node()

    def test_recent_and_after(self):
        e1 = mk_event(self.s)
        e2 = mk_event(self.s, flags=["multipart", "mp:upload_progress_field"], src="198.51.100.7")
        r = self.client.get("/api/v1/events/recent?n=10").json()
        self.assertEqual([x["id"] for x in r], [e2.id, e1.id])
        self.assertEqual(r[0]["sev"], "suspicious")
        self.assertEqual(r[1]["sev"], "benign")
        self.assertEqual(r[0]["node"], "s1")
        self.assertEqual(r[0]["tier"], "full")
        self.assertEqual(r[0]["ua"], "curl/8")
        r = self.client.get(f"/api/v1/events/recent?after={e1.id}").json()
        self.assertEqual([x["id"] for x in r], [e2.id])

    def test_summary_buckets(self):
        mk_event(self.s, lat=52.5, lon=13.4, cc="DE", city="Berlin")
        mk_event(self.s, lat=52.52, lon=13.41, cc="DE", city="Berlin", flags=["mp:preamble"])
        mk_event(self.s, src="198.51.100.7", cc="FR", host="")
        d = self.client.get("/api/v1/events/summary?hours=24").json()
        self.assertEqual(d["total"], 3)
        self.assertEqual(len(d["hours"]), 1)
        b = d["by_hour"][d["hours"][0]]
        self.assertEqual((b["n"], b["flagged"]), (3, 1))
        self.assertEqual(b["geo"], [[52.5, 13.4, 2, "DE", "Berlin", 1]])
        self.assertEqual(sorted(x[0] for x in b["ips"]), ["198.51.100.7", "203.0.113.9"])
        self.assertEqual(sorted(x[0] for x in b["host"]), ["-", "s1.example.org"])
        self.assertEqual(b["node"], [["s1", 3, 1]])
        self.assertEqual(d["nodes"]["s1"]["lat"], 1.3)

    def test_summary_flagged_follows_selected_labels(self):
        mk_event(self.s, lat=52.5, lon=13.4, labels=["crawler"], severity=0)
        mk_event(self.s, lat=52.5, lon=13.4, labels=["path traversal"], severity=2)
        mk_event(self.s, lat=52.5, lon=13.4, flags=["mp:preamble"])
        h = lambda d: d["by_hour"][d["hours"][0]]  # noqa: E731
        d = self.client.get("/api/v1/events/summary?hours=24").json()  # no parameter: old heuristic
        self.assertEqual(h(d)["flagged"], 3)
        d = self.client.get("/api/v1/events/summary?hours=24&labels=path%20traversal").json()
        self.assertEqual(h(d)["flagged"], 1)
        self.assertEqual(h(d)["geo"][0][5], 1)
        self.assertEqual(sorted(h(d)["labels"]), [["crawler", 1], ["path traversal", 1]])
        d = self.client.get("/api/v1/events/summary?hours=24&labels=crawler,path%20traversal").json()
        self.assertEqual(h(d)["flagged"], 2)
        d = self.client.get("/api/v1/events/summary?hours=24&labels=").json()  # explicitly nothing
        self.assertEqual(h(d)["flagged"], 0)

    def test_detail_returns_body_as_text_and_404_for_unknown(self):
        e = mk_event(self.s, body_sample=b"a=1&b=\xff", multipart={"boundary": "x", "parts": 2})
        d = self.client.get(f"/api/v1/events/{e.id}").json()
        self.assertEqual(d["body"], "a=1&b=\xff")
        self.assertEqual((d["body_stored"], d["body_shown"], d["body_present"]), (7, 7, True))
        self.assertEqual(d["body_seen"]["events"], 1)
        self.assertEqual(d["multipart"]["boundary"], "x")
        self.assertEqual(d["node"], "s1")
        self.assertEqual(self.client.get("/api/v1/events/999999").status_code, 404)

    def test_detail_shows_at_most_a_mebibyte_and_the_download_has_it_all(self):
        from .api import BODY_VIEW_BYTES

        body = b"x" * BODY_VIEW_BYTES + b"TAIL"
        e = mk_event(self.s, body_sample=body)
        d = self.client.get(f"/api/v1/events/{e.id}").json()
        self.assertEqual((d["body_stored"], d["body_shown"], len(d["body"])), (len(body), BODY_VIEW_BYTES, BODY_VIEW_BYTES))
        r = self.client.get(f"/api/v1/events/{e.id}/body")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Content-Type"], "application/octet-stream")
        self.assertEqual(r["X-Body-SHA256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(r.content, body)
        self.assertEqual(self.client.get("/api/v1/events/999999/body").status_code, 404)
        self.assertEqual(self.client.get("/api/v1/events/recent?n=1").json()[0]["id"], e.id)

    def test_released_body_is_410_and_the_detail_says_so(self):
        e = mk_event(self.s, body_sample=b"payload")
        sha = e.body_sha256
        Event.objects.filter(pk=e.pk).update(body=None)
        d = self.client.get(f"/api/v1/events/{e.id}").json()
        self.assertEqual((d["body_present"], d["body_stored"], d["body_sha256"], d["body"], d["body_seen"]), (False, 7, sha, "", None))
        self.assertEqual(self.client.get(f"/api/v1/events/{e.id}/body").status_code, 410)
        none = mk_event(self.s, body_sample=None)
        self.assertEqual(self.client.get(f"/api/v1/events/{none.id}/body").status_code, 404)

    def test_same_body_twice_is_one_row_and_the_detail_counts_it(self):
        a = mk_event(self.s, body_sample=b"same")
        b = mk_event(self.s, body_sample=b"same", ts=timezone.now() + timedelta(hours=1))
        self.assertEqual(Body.objects.count(), 1)
        self.assertEqual(a.body_id, b.body_id)
        d = self.client.get(f"/api/v1/events/{a.id}").json()
        self.assertEqual(d["body_seen"]["events"], 2)
        self.assertEqual(d["body_seen"]["last"], b.ts.isoformat(timespec="seconds").replace("+00:00", "Z"))

    def test_dashboard_renders(self):
        r = self.client.get("/")
        self.assertContains(r, "Requests by source location")
        self.assertContains(r, "DB-IP")


class StorageTests(TestCase):
    def setUp(self):
        cache.delete(storage.CACHE_KEY)
        cache.delete(storage.LAST_SWEEP_KEY)
        self.s = mk_node()

    @override_settings(STORAGE_CAPACITY_BYTES=1000, RETENTION_BODY_BUDGET=0.5, RETENTION_EVENT_DAYS=365, RETENTION_BODY_DAYS=90)
    def test_usage_endpoint_fragment_and_gauge(self):
        mk_event(self.s, body_sample=b"x" * 100)
        mk_event(self.s, body_sample=b"x" * 100)
        mk_event(self.s, body_sample=None)
        u = storage.usage(fresh=True)
        self.assertEqual((u["events"]["count"], u["bodies"]["count"], u["bodies"]["bytes"], u["bodies"]["refs"]), (3, 1, 100, 2))
        self.assertEqual(u["bodies"]["budget_bytes"], 500)
        self.assertGreater(u["db_bytes"], 1000)
        self.assertEqual(u["level"], "critical")  # a database is far bigger than a 1000-byte volume
        self.assertEqual(u["retention"], {"event_days": 365, "body_days": 90, "body_budget": 0.5})
        self.assertIsNone(u["last_sweep"])
        self.assertEqual(self.client.get("/api/v1/storage").json()["events"]["count"], 3)
        r = self.client.get("/_storage")
        self.assertContains(r, "3 rows")
        self.assertContains(r, "not yet run")
        self.assertContains(self.client.get("/"), 'id="stbar"')
        self.assertEqual(storage.human(3145754), "3.0 MiB")


class RetentionTests(TestCase):
    def setUp(self):
        cache.delete(storage.CACHE_KEY)
        cache.delete(storage.LAST_SWEEP_KEY)
        self.s = mk_node()
        self.now = timezone.now()

    def ev(self, days_ago, body=None):
        return mk_event(self.s, ts=self.now - timedelta(days=days_ago), body_sample=body)

    @override_settings(RETENTION_EVENT_DAYS=30, RETENTION_BODY_DAYS=7, STORAGE_CAPACITY_BYTES=10**9, RETENTION_BODY_BUDGET=0.5)
    def test_time_rules_delete_release_and_drop_orphans(self):
        ancient = self.ev(40, b"old payload")  # the event goes
        old = self.ev(10, b"old payload")  # released; its body row is then unreferenced and dropped
        shared_old = self.ev(10, b"shared")  # released, but the row stays: a fresh event still points at it
        fresh = self.ev(1, b"shared")
        self.ev(1, None)
        out = retention.sweep()
        self.assertEqual((out["events_deleted"], out["bodies_released"], out["bodies_deleted"], out["bytes_freed"], out["pressure"]),
                         (1, 2, 1, 11, False))
        self.assertFalse(Event.objects.filter(pk=ancient.pk).exists())
        old.refresh_from_db()
        self.assertIsNone(old.body_id)
        self.assertEqual((old.body_size, old.body_sha256), (11, hashlib.sha256(b"old payload").hexdigest()))
        shared_old.refresh_from_db()
        self.assertIsNone(shared_old.body_id)
        self.assertEqual(list(Body.objects.values_list("sha256", flat=True)), [fresh.body_id])
        fresh.refresh_from_db()
        self.assertEqual(fresh.body_bytes, b"shared")
        self.assertEqual(cache.get(storage.LAST_SWEEP_KEY)["events_deleted"], 1)
        again = retention.sweep()  # idempotent
        self.assertEqual((again["events_deleted"], again["bodies_released"], again["bodies_deleted"]), (0, 0, 0))

    @override_settings(RETENTION_EVENT_DAYS=0, RETENTION_BODY_DAYS=0, STORAGE_CAPACITY_BYTES=1000, RETENTION_BODY_BUDGET=0.5)
    def test_budget_pressure_releases_the_oldest_bodies_first(self):
        oldest, middle, newest = self.ev(5, b"a" * 300), self.ev(3, b"b" * 300), self.ev(1, b"c" * 300)
        # live 900 B against a 500 B budget: free down to 450, oldest first, one event at a time here
        with mock.patch.object(retention, "PRESSURE_CHUNK", 1):
            out = retention.sweep()
        self.assertTrue(out["pressure"])
        self.assertEqual((out["events_deleted"], out["bodies_released"], out["bodies_deleted"], out["bytes_freed"]), (0, 2, 2, 600))
        for e, has_body in ((oldest, False), (middle, False), (newest, True)):
            e.refresh_from_db()
            self.assertEqual(bool(e.body_id), has_body, e.body_sha256)
        self.assertFalse(retention.sweep()["pressure"])  # 300 B live now, under budget


class HeartbeatGeoTests(TestCase):
    def test_sensor_location_from_public_ip(self):
        s = Node(name="n", domains=["n.example.org"])
        tok = s.mint_token()
        s.save()
        with mock.patch.object(geo, "lookup", return_value={"cc": "SG", "city": "Singapore", "lat": 1.3, "lon": 103.8}):
            r = self.client.post("/api/v1/heartbeat", json.dumps({"state": "ready"}), content_type="application/json",
                                 HTTP_AUTHORIZATION=f"Bearer {tok}", HTTP_X_FORWARDED_FOR="5.223.45.139")
        self.assertEqual(r.status_code, 200)
        s.refresh_from_db()
        self.assertEqual((s.public_ip, s.cc, s.city, s.lat, s.lon), ("5.223.45.139", "SG", "Singapore", 1.3, 103.8))
