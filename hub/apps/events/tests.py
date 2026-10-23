import json
from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.sensors.models import Sensor

from . import geo, tasks
from .models import Event


def mk_sensor(name="s1"):
    s = Sensor(name=name, domains=[f"{name}.example.org"], lat=1.3, lon=103.8, cc="SG", city="Singapore", public_ip="5.0.0.1")
    s.mint_token()
    s.save()
    return s


def mk_event(sensor, **over):
    kw = dict(sensor=sensor, ulid="01JAX0000000000000000000" + str(Event.objects.count()).zfill(2), ts=timezone.now(),
              src="203.0.113.9", method="GET", host="s1.example.org", target="/x", path="/x",
              headers=[["user-agent", "curl/8"]], resp={"status": 200, "tier": "full", "kind": "index", "bundle": "php", "profile": "p"},
              body_sample=b"abc")
    kw.update(over)
    return Event.objects.create(**kw)


@override_settings(GEOIP_DIR="/nonexistent")
class GeoTests(TestCase):
    def setUp(self):
        geo._reader.cache_clear()

    def test_missing_database_means_no_geo_not_an_error(self):
        self.assertEqual(geo.lookup("203.0.113.9"), {})
        self.assertEqual(geo.version(), "none")

    def test_enrich_marks_rows_done_and_uses_lookup(self):
        s = mk_sensor()
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
        self.s = mk_sensor()

    def test_recent_and_after(self):
        e1 = mk_event(self.s)
        e2 = mk_event(self.s, flags=["multipart", "mp:upload_progress_field"], src="198.51.100.7")
        r = self.client.get("/api/v1/events/recent?n=10").json()
        self.assertEqual([x["id"] for x in r], [e2.id, e1.id])
        self.assertEqual(r[0]["sev"], "suspicious")
        self.assertEqual(r[1]["sev"], "benign")
        self.assertEqual(r[0]["sensor"], "s1")
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
        self.assertEqual(b["sensor"], [["s1", 3, 1]])
        self.assertEqual(d["sensors"]["s1"]["lat"], 1.3)

    def test_detail_returns_body_as_text_and_404_for_unknown(self):
        e = mk_event(self.s, body_sample=b"a=1&b=\xff", multipart={"boundary": "x", "parts": 2})
        d = self.client.get(f"/api/v1/events/{e.id}").json()
        self.assertEqual(d["body"], "a=1&b=\xff")
        self.assertEqual(d["body_stored"], 7)
        self.assertEqual(d["multipart"]["boundary"], "x")
        self.assertEqual(d["sensor"], "s1")
        self.assertEqual(self.client.get("/api/v1/events/999999").status_code, 404)

    def test_dashboard_renders(self):
        r = self.client.get("/")
        self.assertContains(r, "Requests by source location")
        self.assertContains(r, "DB-IP")


class HeartbeatGeoTests(TestCase):
    def test_sensor_location_from_public_ip(self):
        s = Sensor(name="n", domains=["n.example.org"])
        tok = s.mint_token()
        s.save()
        with mock.patch.object(geo, "lookup", return_value={"cc": "SG", "city": "Singapore", "lat": 1.3, "lon": 103.8}):
            r = self.client.post("/api/v1/heartbeat", json.dumps({"state": "ready"}), content_type="application/json",
                                 HTTP_AUTHORIZATION=f"Bearer {tok}", HTTP_X_FORWARDED_FOR="5.223.45.139")
        self.assertEqual(r.status_code, 200)
        s.refresh_from_db()
        self.assertEqual((s.public_ip, s.cc, s.city, s.lat, s.lon), ("5.223.45.139", "SG", "Singapore", 1.3, 103.8))
