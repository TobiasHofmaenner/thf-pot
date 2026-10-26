import gzip
import json

from django.test import TestCase
from django.utils import timezone

from apps.events.models import Event

from .models import Node
from .views import parse_domains


def record(ulid, **over):
    r = {
        "v": 1, "id": ulid, "ts": "2026-10-23T12:00:00.123Z", "src": "203.0.113.9", "src_port": 51234, "self": False,
        "http": {"scheme": "https", "version": "HTTP/1.1", "method": "POST", "target": "/index.php?page=upload",
                 "path": "/index.php", "query": "page=upload",
                 "headers": [["host", "files.example.org"], ["content-type", "multipart/form-data; boundary=x"]],
                 "hdr_fp": "9f3c1a0b2d4e6f70"},
        "host": "files.example.org",
        "body": {"declared_len": 3, "read_len": 3, "truncated": False, "sha256": "ab" * 32, "sample_b64": "YWJj"},
        "multipart": {"boundary": "x", "parts": 2, "session_upload_progress": True},
        "flags": ["multipart", "mp:upload_progress_field"],
        "resp": {"status": 200, "profile": "php-full", "bundle": "php", "tier": "full", "kind": "upload"},
        "dur_ms": 3,
    }
    r.update(over)
    return r


def ndjson_gz(records):
    return gzip.compress("".join(json.dumps(r) + "\n" for r in records).encode())


class IngestTests(TestCase):
    def setUp(self):
        self.node = Node(name="n1", domains=["files.example.org"])
        self.token = self.node.mint_token()
        self.node.save()
        self.auth = {"HTTP_AUTHORIZATION": f"Bearer {self.token}", "HTTP_CONTENT_ENCODING": "gzip"}

    def post(self, body, **extra):
        return self.client.post("/api/v1/ingest", body, content_type="application/x-ndjson", **{**self.auth, **extra})

    def test_batch_is_stored_and_deduplicated(self):
        a, b = "01JAX000000000000000000001", "01JAX000000000000000000002"
        r = self.post(ndjson_gz([record(a), record(b), record(a)]))
        self.assertEqual(r.status_code, 202, r.content)
        self.assertEqual(r.json(), {"accepted": 2, "duplicates": 1, "rejected": 0})
        self.assertEqual(Event.objects.count(), 2)
        e = Event.objects.get(ulid=a)
        self.assertEqual(bytes(e.body_sample), b"abc")
        self.assertEqual(e.content_type, "multipart/form-data; boundary=x")
        self.assertEqual(e.flags, ["multipart", "mp:upload_progress_field"])
        self.assertEqual(str(e.src), "203.0.113.9")
        self.node.refresh_from_db()
        self.assertEqual(self.node.events_total, 2)
        self.assertIsNotNone(self.node.last_event_at)
        # A retried batch is fully duplicate and changes nothing.
        r = self.post(ndjson_gz([record(a), record(b)]))
        self.assertEqual(r.json(), {"accepted": 0, "duplicates": 2, "rejected": 0})
        self.assertEqual(Event.objects.count(), 2)

    def test_bad_records_are_counted_not_fatal(self):
        good = record("01JAX000000000000000000003")
        bad_src = record("01JAX000000000000000000004", src="not-an-ip")
        lines = json.dumps(good) + "\n" + json.dumps(bad_src) + "\n{not json}\n"
        r = self.post(gzip.compress(lines.encode()))
        self.assertEqual(r.status_code, 202)
        self.assertEqual(r.json(), {"accepted": 1, "duplicates": 0, "rejected": 2})

    def test_a_full_size_body_is_stored_whole(self):
        import base64

        raw = bytes(range(256)) * (8 * 1024) + b"END"  # 2 MiB: above the hub's former 1 MiB cap
        body = {"declared_len": len(raw), "read_len": len(raw), "truncated": False, "sha256": "ab" * 32,
                "sample_b64": base64.b64encode(raw).decode()}
        r = self.post(ndjson_gz([record("01JAX00000000000000000000A", body=body)]))
        self.assertEqual(r.status_code, 202, r.content)
        self.assertEqual(bytes(Event.objects.get().body_sample), raw)

    def test_unknown_keys_land_in_extra(self):
        r = self.post(ndjson_gz([record("01JAX000000000000000000005", future_field={"x": 1})]))
        self.assertEqual(r.status_code, 202)
        self.assertEqual(Event.objects.get().extra, {"future_field": {"x": 1}})

    def test_wrong_token_is_401(self):
        r = self.post(ndjson_gz([record("01JAX000000000000000000006")]), HTTP_AUTHORIZATION="Bearer nope")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(Event.objects.count(), 0)

    def test_revoked_sensor_is_401(self):
        Node.objects.filter(pk=self.node.pk).update(is_active=False)
        r = self.post(ndjson_gz([record("01JAX000000000000000000007")]))
        self.assertEqual(r.status_code, 401)

    def test_plain_ndjson_without_gzip_works(self):
        body = (json.dumps(record("01JAX000000000000000000008")) + "\n").encode()
        r = self.client.post("/api/v1/ingest", body, content_type="application/x-ndjson",
                             HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.assertEqual(r.status_code, 202)

    def test_heartbeat(self):
        hb = {"ts": "2026-10-23T12:00:00Z", "version": "0.1.0", "domains": ["files.example.org"],
              "cursor_file": "events-2026-10-23.jsonl", "cursor_offset": 4200, "uptime_s": 61}
        r = self.client.post("/api/v1/heartbeat", json.dumps(hb), content_type="application/json",
                             HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.assertEqual(r.status_code, 200, r.content)
        self.node.refresh_from_db()
        self.assertEqual(self.node.last_heartbeat["cursor_offset"], 4200)
        self.assertEqual(self.node.version, "0.1.0")
        self.assertTrue(self.node.online)
        self.assertIsNotNone(self.node.first_seen_at)

    def hb(self, state, detail, **extra):
        body = {"version": "0.2.0", "state": state, "detail": detail}
        return self.client.post("/api/v1/heartbeat", json.dumps(body), content_type="application/json",
                                HTTP_AUTHORIZATION=f"Bearer {self.token}", **extra)

    def test_heartbeat_reports_public_ip_and_tracks_state(self):
        r = self.hb("starting", {}, HTTP_X_FORWARDED_FOR="198.51.100.7, 10.0.0.1")
        self.assertEqual(r.json(), {"ok": True, "your_ip": "198.51.100.7"})
        r = self.hb("starting", {}, HTTP_CF_CONNECTING_IP="198.51.100.8", HTTP_X_FORWARDED_FOR="10.0.0.1")
        self.assertEqual(r.json()["your_ip"], "198.51.100.8")
        self.node.refresh_from_db()
        self.assertEqual(self.node.state, "starting")
        self.assertEqual(self.node.public_ip, "198.51.100.8")
        first_change = self.node.state_changed_at

        detail = {"public_ip": "198.51.100.8", "domains": {"files.example.org": {"ok": False, "resolved": ["203.0.113.1"]}}}
        self.hb("dns_failed", detail)
        self.node.refresh_from_db()
        self.assertEqual(self.node.state, "dns_failed")
        self.assertGreater(self.node.state_changed_at, first_change)
        phases = {p["name"]: p for p in self.node.phases()}
        self.assertEqual(phases["deployed"]["status"], "ok")
        self.assertEqual(phases["dns"]["status"], "fail")
        self.assertIn("files.example.org → 203.0.113.1", phases["dns"]["note"])
        self.assertIn("expected 198.51.100.8", phases["dns"]["note"])
        self.assertEqual(phases["certs"]["status"], "pending")

        raw = 'order: acme error: http request error: non 2xx http status: 400 "{\\n  \\"type\\": \\"urn:ietf:params:acme:error:rejectedIdentifier\\",\\n  \\"detail\\": \\"Invalid identifiers requested :: Cannot issue for \\\\\\"good.test\\\\\\": Domain name does not end with a valid public suffix (TLD)\\",\\n  \\"status\\": 400\\n}"'
        self.hb("cert_error", {"public_ip": "198.51.100.8", "error": raw})
        self.node.refresh_from_db()
        certs = next(p for p in self.node.phases() if p["name"] == "certs")
        self.assertEqual(certs["status"], "fail")
        self.assertTrue(certs["note"].startswith("Invalid identifiers requested"), certs["note"])

        self.hb("ready", {"public_ip": "198.51.100.8", "certs": ["files.example.org"]})
        self.node.refresh_from_db()
        phases = {p["name"]: p for p in self.node.phases()}
        self.assertEqual([phases[k]["status"] for k in ("deployed", "dns", "certs", "live")], ["ok", "ok", "ok", "ok"])
        self.assertEqual(phases["certs"]["note"], "files.example.org")

        r = self.client.get("/nodes/list")
        self.assertContains(r, "✓ certs")

    def test_phases_before_first_contact(self):
        self.assertEqual([p["status"] for p in self.node.phases()], ["pending"] * 4)
        self.hb("ready", {"tls": "disabled", "dns": "skipped"})
        self.node.refresh_from_db()
        self.assertEqual([p["status"] for p in self.node.phases()], ["ok", "skip", "skip", "ok"])


class NodePageTests(TestCase):
    def test_parse_domains(self):
        self.assertEqual(parse_domains("A.Example.org, b.example.org\nA.example.org."), ["a.example.org", "b.example.org"])
        with self.assertRaises(ValueError):
            parse_domains("not a host")

    def test_self_ips_in_snippets_and_edit(self):
        r = self.client.post("/nodes/new", {"domains": "x.example.org", "self_ips": "37.17.239.121, 2001:db8::/48"})
        html = r.content.decode()
        self.assertIn("SELF_IPS=37.17.239.121", html)
        self.assertIn("SELF_NETS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128,2001:db8::/48", html)
        node = Node.objects.get(name="x.example.org")
        self.assertEqual(node.self_ips, ["37.17.239.121", "2001:db8::/48"])
        r = self.client.post("/nodes/new", {"domains": "y.example.org", "self_ips": "not-an-ip"})
        self.assertIn("not an address", r.content.decode())
        r = self.client.get(f"/nodes/{node.pk}/edit")
        self.assertContains(r, "37.17.239.121")
        r = self.client.post(f"/nodes/{node.pk}/edit", {"domains": "x.example.org, z.example.org", "self_ips": "198.51.100.7"})
        self.assertEqual(r["HX-Trigger"], "nodes-changed")
        self.assertIn("SELF_IPS=198.51.100.7", r.content.decode())
        node.refresh_from_db()
        self.assertEqual(node.domains, ["x.example.org", "z.example.org"])
        self.assertEqual(node.self_ips, ["198.51.100.7"])

    def test_nodes_page_prefills_your_ip(self):
        r = self.client.get("/nodes/", HTTP_X_FORWARDED_FOR="37.17.239.121")
        self.assertContains(r, 'value="37.17.239.121"')

    def test_add_node_mints_token_and_snippets(self):
        r = self.client.post("/nodes/new", {"domains": "files.example.org\nbackup.example.org", "acme_email": "a@b.cd"},
                             HTTP_HOST="pot.example", HTTP_X_FORWARDED_PROTO="https")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["HX-Trigger"], "nodes-changed")
        node = Node.objects.get(name="files.example.org")
        self.assertEqual(node.domains, ["files.example.org", "backup.example.org"])
        html = r.content.decode()
        # The plaintext token appears on the page and only its hash in the database.
        token = html.split('<pre id="tok" class="token">')[1].split("</pre>")[0]
        self.assertEqual(len(token), 43)
        self.assertEqual(node.token_sha256, Node.hash_token(token))
        self.assertEqual(Node.authenticate(token), node)
        self.assertIn("NODE_TOKEN=" + token, html)
        self.assertIn("DOMAINS=files.example.org,backup.example.org", html)
        self.assertIn("HUB_URL=https://pot.example", html)
        self.assertIn("ACME_EMAIL=a@b.cd", html)
        self.assertIn("-e NODE_TOKEN=" + token, html)

    def test_rotate_invalidates_old_token(self):
        node = Node(name="n", domains=["x.example.org"])
        old = node.mint_token()
        node.save()
        r = self.client.post(f"/nodes/{node.pk}/rotate")
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(Node.authenticate(old))
        node.refresh_from_db()
        self.assertIsNotNone(node.token_rotated_at)

    def test_toggle_revokes(self):
        node = Node(name="n", domains=["x.example.org"])
        tok = node.mint_token()
        node.save()
        self.client.post(f"/nodes/{node.pk}/toggle")
        self.assertIsNone(Node.authenticate(tok))
        self.client.post(f"/nodes/{node.pk}/toggle")
        self.assertEqual(Node.authenticate(tok), node)

    def test_delete_only_revoked_nodes_without_events(self):
        node = Node(name="n", domains=["x.example.org"])
        node.mint_token()
        node.save()
        self.assertEqual(self.client.post(f"/nodes/{node.pk}/delete").status_code, 400)  # still active
        node.is_active = False
        node.save()
        Event.objects.create(node=node, ulid="01JAX000000000000000000009", ts=timezone.now(), src="203.0.113.9", method="GET")
        self.assertEqual(self.client.post(f"/nodes/{node.pk}/delete").status_code, 400)  # has evidence
        Event.objects.all().delete()
        self.assertEqual(self.client.post(f"/nodes/{node.pk}/delete").status_code, 200)
        self.assertFalse(Node.objects.filter(pk=node.pk).exists())

    def test_duplicate_name_is_an_error_not_a_500(self):
        Node(name="files.example.org", domains=["files.example.org"], token_sha256="x" * 64, token_prefix="x").save()
        r = self.client.post("/nodes/new", {"domains": "files.example.org"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("already exists", r.content.decode())
        self.assertEqual(Node.objects.count(), 1)

    def test_list_page_renders(self):
        n = Node(name="n", domains=["x.example.org"], last_seen_at=timezone.now(), last_heartbeat={"version": "0.1.0"})
        n.mint_token()
        n.save()
        r = self.client.get("/nodes/")
        self.assertContains(r, "✓ live")
        self.assertContains(r, "0.1.0")
