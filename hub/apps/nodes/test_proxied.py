from django.test import TestCase
from django.utils import timezone

from .hosts import match_host
from .models import Node
from .views import parse_domains


class WildcardAndProxiedTests(TestCase):
    def test_wildcard_domains_parse_and_match(self):
        self.assertEqual(parse_domains("*.replicator.uk, test.replicator.uk"), ["*.replicator.uk", "test.replicator.uk"])
        with self.assertRaises(ValueError):
            parse_domains("*replicator.uk")
        doms = ["old.ferp.ch", "*.replicator.uk"]
        self.assertEqual(match_host("old.ferp.ch", doms), "old.ferp.ch")
        self.assertEqual(match_host("OLD.FERP.CH.", doms), "old.ferp.ch")
        self.assertEqual(match_host("foo.replicator.uk", doms), "*.replicator.uk")
        self.assertEqual(match_host("a.b.replicator.uk", doms), "*.replicator.uk")
        self.assertEqual(match_host("replicator.uk", doms), "")
        self.assertEqual(match_host("evil.com", doms), "")
        self.assertEqual(match_host("", doms), "")

    def test_proxied_node_snippets(self):
        r = self.client.post("/nodes/new", {"domains": "test.niguna.ch\n*.replicator.uk", "name": "Germany", "proxied": "on",
                                            "self_ips": "91.107.205.244"}, HTTP_HOST="pot.example", HTTP_X_FORWARDED_PROTO="https")
        html = r.content.decode()
        node = Node.objects.get(name="Germany")
        self.assertTrue(node.proxied)
        self.assertEqual(node.domains, ["test.niguna.ch", "*.replicator.uk"])
        self.assertIn("HTTP_ONLY=1", html)
        self.assertIn("TRUST_PROXY=1", html)
        self.assertIn("-p 127.0.0.1:8081:8080", html)
        self.assertNotIn("443:8443", html)
        self.assertIn("127.0.0.1:8081:8080", html)  # the compose block (quotes are HTML-escaped on the page)
        self.assertIn("NODE_TOKEN=", html)
        self.assertIn("point every sensor's vhost", html)
        # a normal node keeps the public ports
        r = self.client.post("/nodes/new", {"domains": "x.example.org"})
        self.assertIn("-p 80:8080 -p 443:8443", r.content.decode())

    def test_phases_proxied_ready(self):
        node = Node(name="n", domains=["x.example.org"], proxied=True, first_seen_at=timezone.now(), last_seen_at=timezone.now(),
                    state="ready", state_detail={"public_ip": "91.107.205.244", "tls": "disabled",
                                                 "domains": {"x.example.org": {"ok": True, "resolved": ["91.107.205.244"]}}})
        phases = {p["name"]: p for p in node.phases()}
        self.assertEqual(phases["dns"]["status"], "ok")
        self.assertEqual(phases["certs"]["status"], "skip")
        self.assertIn("proxy", phases["certs"]["note"])
        self.assertEqual(phases["live"]["status"], "ok")
