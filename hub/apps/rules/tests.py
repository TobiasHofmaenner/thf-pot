import json

from django.test import TestCase
from django.utils import timezone

from apps.events.models import Event
from apps.nodes.models import Node

from . import engine, export, sigma
from .models import Rule


def mk_node(name="s1"):
    s = Node(name=name, domains=["s1.example.org"])
    s.mint_token()
    s.save()
    return s


_n = [0]


def mk_event(node, **over):
    _n[0] += 1
    kw = dict(node=node, ulid=f"01JAX{_n[0]:021d}", ts=timezone.now(), src="203.0.113.9", method="GET",
              host="s1.example.org", target="/", path="/", query="", headers=[["user-agent", "curl/8"]], resp={"tier": "full"})
    kw.update(over)
    if "target" not in over and ("path" in over or "query" in over):
        kw["target"] = kw["path"] + ("?" + kw["query"] if kw["query"] else "")
    return Event.objects.create(**kw)


class SigmaTests(TestCase):
    def ev(self, **over):
        return sigma.context(mk_event(self.s, **over), self.s.domains)

    def setUp(self):
        self.s = mk_node()

    def test_parse_and_evaluate_basics(self):
        det = sigma.parse_detection("sel:\n  path|contains: ['/.env', '/.git/config']\n  method: [GET, HEAD]\ncondition: sel\n")
        self.assertTrue(det.evaluate(self.ev(path="/.ENV")))
        self.assertFalse(det.evaluate(self.ev(path="/.env", method="POST")))
        self.assertEqual(det.fields(), {"path", "method"})

    def test_modifiers(self):
        self.assertTrue(sigma.parse_detection("a:\n  path|startswith: /wp\ncondition: a").evaluate(self.ev(path="/WP-admin/")))
        self.assertFalse(sigma.parse_detection("a:\n  path|startswith|cased: /wp\ncondition: a").evaluate(self.ev(path="/WP-admin/")))
        self.assertTrue(sigma.parse_detection("a:\n  path|re: '^/a/\\d+$'\ncondition: a").evaluate(self.ev(path="/a/42")))
        self.assertFalse(sigma.parse_detection("a:\n  path|re: '^/A/'\ncondition: a").evaluate(self.ev(path="/a/42")))
        self.assertTrue(sigma.parse_detection("a:\n  path|re|i: '^/A/'\ncondition: a").evaluate(self.ev(path="/a/42")))
        self.assertTrue(sigma.parse_detection("a:\n  path: '/x/*.php'\ncondition: a").evaluate(self.ev(path="/x/shell.php")))
        self.assertTrue(sigma.parse_detection("a:\n  body|contains|all: [foo, bar]\ncondition: a").evaluate(self.ev(body_sample=b"foo bar")))
        self.assertFalse(sigma.parse_detection("a:\n  body|contains|all: [foo, bar]\ncondition: a").evaluate(self.ev(body_sample=b"foo")))
        self.assertTrue(sigma.parse_detection("a:\n  read_len|gt: 10\ncondition: a").evaluate(self.ev(read_len=11)))
        self.assertTrue(sigma.parse_detection("a:\n  flags|contains: mp:preamble\ncondition: a").evaluate(self.ev(flags=["multipart", "mp:preamble"])))
        self.assertTrue(sigma.parse_detection("a:\n  header.x-foo: bar\ncondition: a").evaluate(self.ev(headers=[["X-Foo", "BAR"]])))
        self.assertTrue(sigma.parse_detection("a:\n  host_known: false\ncondition: a").evaluate(self.ev(host="other.example")))
        self.assertFalse(sigma.parse_detection("a:\n  host_known: false\ncondition: a").evaluate(self.ev(host="s1.example.org")))

    def test_condition_grammar(self):
        text = "a:\n  path|contains: x\nb:\n  method: POST\nc1:\n  ua|contains: curl\nc2:\n  ua|contains: wget\ncondition: {cond}"
        p = lambda c: sigma.parse_detection(text.format(cond=c))  # noqa: E731
        self.assertTrue(p("a and not b").evaluate(self.ev(path="/x")))
        self.assertFalse(p("a and not b").evaluate(self.ev(path="/x", method="POST")))
        self.assertTrue(p("(a or b) and 1 of c*").evaluate(self.ev(method="POST")))
        self.assertFalse(p("all of c*").evaluate(self.ev()))
        self.assertTrue(p("1 of them").evaluate(self.ev()))
        with self.assertRaises(sigma.RuleError):
            p("a and")
        with self.assertRaises(sigma.RuleError):
            p("nope")
        with self.assertRaises(sigma.RuleError):
            sigma.parse_detection("a:\n  nosuchfield: 1\ncondition: a")
        with self.assertRaises(sigma.RuleError):
            sigma.parse_detection("a:\n  path|re: '('\ncondition: a")
        with self.assertRaises(sigma.RuleError):
            sigma.parse_detection("a:\n  read_len|contains: x\ncondition: a")

    def test_selection_as_list_is_or(self):
        det = sigma.parse_detection("brand:\n  - ua|contains: php2shell\n  - path|contains: php2shell\ncondition: brand")
        self.assertTrue(det.evaluate(self.ev(path="/php2shell")))
        self.assertTrue(det.evaluate(self.ev(headers=[["user-agent", "PHP2Shell/1"]])))
        self.assertFalse(det.evaluate(self.ev()))


class SeedRuleTests(TestCase):
    """The migration seeded the local rules; they must fire on the shapes they were written for."""

    def setUp(self):
        self.s = mk_node()
        self.rules = engine.ruleset()

    def labels(self, **over):
        return engine.classify_one(mk_event(self.s, **over), self.rules, self.s.domains)

    def test_seed_loaded(self):
        self.assertGreaterEqual(Rule.objects.filter(origin="local").count(), 30)

    def test_php2shell_structural_and_corroborated(self):
        labels, sev = self.labels(method="POST", flags=["multipart", "mp:huge_part_count"], target="/index.php", path="/index.php")
        self.assertIn("PHP2Shell", labels)
        self.assertEqual(sev, 2)
        labels, sev = self.labels(method="POST", flags=["multipart", "mp:upload_progress_field"], read_len=300)
        self.assertNotIn("PHP2Shell", labels)
        self.assertIn("session upload progress abuse", labels)
        labels, _ = self.labels(method="POST", flags=["multipart", "mp:upload_progress_field"], read_len=300, multipart={"preamble_len": 3763})
        self.assertIn("PHP2Shell", labels)
        self.assertNotIn("session upload progress abuse", labels)  # suppressed
        self.assertNotIn("multipart preamble", labels) if "inspection-window evasion" in labels else None

    def test_branding_only_suppressed_by_exploit(self):
        labels, sev = self.labels(method="POST", headers=[["user-agent", "php2shell/1.0"]])
        self.assertIn("php2shell branding only", labels)
        self.assertEqual(sev, 1)

    def test_common_probes(self):
        self.assertIn(".env harvesting", self.labels(path="/.env")[0])
        self.assertIn("git repository exposure", self.labels(path="/.git/config")[0])
        self.assertIn("PHPUnit eval-stdin", self.labels(path="/vendor/phpunit/src/Util/PHP/eval-stdin.php", method="POST", body_sample=b"<?php echo 1;")[0])
        labels = self.labels(path="/vendor/phpunit/src/Util/PHP/eval-stdin.php", method="POST", body_sample=b"<?php echo 1;")[0]
        self.assertNotIn("PHP code in body", labels)  # implied by the specific one
        self.assertIn("path traversal", self.labels(path="/../../etc/passwd")[0])
        self.assertIn("webshell probing", self.labels(path="/wso.php")[0])
        self.assertIn("filesystem path in parameter", self.labels(path="/index.php", query="page=/etc/passwd")[0])
        self.assertIn("remote file inclusion", self.labels(path="/index.php", query="page=http://evil.example/x.txt")[0])
        self.assertIn("Next.js middleware bypass", self.labels(headers=[["x-middleware-subrequest", "middleware:middleware:middleware"]])[0])
        self.assertIn("header-injected file read", self.labels(headers=[["cookie", "lang=../../../../etc/passwd"]])[0])
        self.assertIn("generic fetch", self.labels(path="/favicon.ico")[0])
        self.assertNotIn("generic fetch", self.labels(path="/index.php", query="page=login")[0])
        self.assertIn("login probing", self.labels(path="/index.php", query="page=login")[0])
        self.assertIn("host mismatch", self.labels(host="www.example.com")[0])
        self.assertNotIn("host mismatch", self.labels(host="s1.example.org")[0])

    def test_crawler_vs_spoofed(self):
        ua = [["user-agent", "Mozilla/5.0 (compatible; Googlebot/2.1)"]]
        self.assertIn("crawler", self.labels(headers=ua)[0])
        labels, sev = self.labels(headers=ua, path="/../../etc/passwd")
        self.assertIn("spoofed crawler UA", labels)
        self.assertNotIn("crawler", labels)
        self.assertEqual(sev, 2)

    def test_classify_events_updates_rows(self):
        e = mk_event(self.s, path="/.env")
        self.assertEqual(engine.classify_events([e.id]), 1)
        e.refresh_from_db()
        self.assertEqual(e.labels, [".env harvesting"])
        self.assertEqual(e.severity, 2)
        self.assertEqual(e.sev, "malicious")
        self.assertIsNotNone(e.classified_at)
        plain = mk_event(self.s, path="/whatever")
        engine.classify_events([plain.id])
        plain.refresh_from_db()
        self.assertEqual(plain.labels, [])
        self.assertIsNone(plain.severity)


class ExportTests(TestCase):
    def rule(self, detection, **kw):
        r = Rule(name=kw.pop("name", "t"), severity=kw.pop("severity", 2), detection=detection, **kw)
        r.pk = 7
        return r

    def test_modsec_chain_and_dnf(self):
        r = self.rule("a:\n  path|contains: ['/.env', '/.git']\n  method: [GET, HEAD]\nb:\n  ua|contains: curl\ncondition: a and not b")
        text = export.modsec(r, mode="block")
        self.assertIn('SecRule REQUEST_FILENAME "@pm /.env /.git"', text)
        self.assertIn('SecRule REQUEST_METHOD "@rx (?i)^(?:GET|HEAD)$"', text)
        self.assertIn('SecRule REQUEST_HEADERS:User-Agent "!@contains curl"', text)
        self.assertIn("deny,status:403", text)
        self.assertIn("id:9000070", text)
        first = [ln for ln in text.splitlines() if ln.startswith("SecRule")][0]
        self.assertIn("chain", first)
        self.assertEqual(text.count("chain"), 2)

    def test_modsec_or_expands_to_two_groups(self):
        r = self.rule("a:\n  path|contains: x\nb:\n  body|re: 'y+'\ncondition: a or b")
        text = export.modsec(r)
        self.assertIn("id:9000070", text)
        self.assertIn("id:9000071", text)
        self.assertIn('"@rx y+"', text)

    def test_honeypot_only_fields_are_not_exportable(self):
        r = self.rule("a:\n  flags|contains: mp:preamble\ncondition: a")
        with self.assertRaises(export.NotExportable):
            export.modsec(r)
        with self.assertRaises(export.NotExportable):
            export.cloudflare(r)
        ex = export.exportability(r)
        self.assertIn("flags", ex["modsec"])

    def test_cloudflare_expression(self):
        r = self.rule("a:\n  path|contains: ['/.env', '/.git']\n  method: [GET, HEAD]\nb:\n  ua|re|i: 'curl|wget'\ncondition: a and not b")
        expr = export.cloudflare(r)
        self.assertEqual(expr, '((lower(http.request.uri.path) contains "/.env" or lower(http.request.uri.path) contains "/.git") '
                               'and lower(http.request.method) in {"get" "head"}) and not http.user_agent matches "(?i)curl|wget"')


class RuleApiAndPageTests(TestCase):
    H = {"HTTP_X_REQUESTED_WITH": "thf-pot"}

    def test_crud(self):
        body = {"name": "env sweep", "severity": "malicious", "origin": "api", "tags": ["secrets"], "cve": ["cve-2099-1"],
                "detection": {"sel": {"path|contains": "/.env"}, "condition": "sel"}}
        r = self.client.post("/api/v1/rules", json.dumps(body), content_type="application/json", **self.H)
        self.assertEqual(r.status_code, 201, r.content)
        d = r.json()
        self.assertEqual((d["severity"], d["origin"], d["cve"], d["exportable"]["modsec"]), (2, "api", ["CVE-2099-1"], ""))
        rid = d["id"]
        self.assertEqual(self.client.post("/api/v1/rules", json.dumps(body), content_type="application/json").status_code, 401)  # no header
        r = self.client.put(f"/api/v1/rules/{rid}", json.dumps({"enabled": False, "tags": "a, b"}), content_type="application/json", **self.H)
        self.assertEqual(r.json()["enabled"], False)
        self.assertEqual(r.json()["tags"], ["a", "b"])
        self.assertEqual(self.client.get(f"/api/v1/rules/{rid}").json()["name"], "env sweep")
        self.assertTrue(any(x["name"] == "env sweep" for x in self.client.get("/api/v1/rules").json()))
        self.assertIn("SecRule", self.client.get(f"/api/v1/rules/{rid}/export?format=modsec&mode=block").content.decode())
        self.assertIn("lower(http.request.uri.path)", self.client.get(f"/api/v1/rules/{rid}/export?format=cloudflare").content.decode())
        r = self.client.post("/api/v1/rules/validate", json.dumps({"detection": "sel:\n  nosuch: 1\ncondition: sel"}), content_type="application/json", **self.H)
        self.assertFalse(r.json()["ok"])
        self.assertEqual(self.client.delete(f"/api/v1/rules/{rid}", **self.H).status_code, 204)
        self.assertEqual(self.client.get(f"/api/v1/rules/{rid}").status_code, 404)
        r = self.client.post("/api/v1/rules", json.dumps({"name": "bad", "detection": "x:\n  path|re: '('\ncondition: x"}), content_type="application/json", **self.H)
        self.assertEqual(r.status_code, 422)

    def test_export_all(self):
        text = self.client.get("/api/v1/rules/export?format=modsec").content.decode()
        self.assertIn("SecRule", text)
        self.assertIn("not exportable: PHP2Shell", text)
        self.assertIn("thf-pot: .env harvesting", text)

    def test_page_and_editor(self):
        s = mk_node()
        mk_event(s, path="/.env")
        self.assertContains(self.client.get("/rules/"), ".env harvesting")
        r = self.client.get("/rules/new")
        self.assertContains(r, "new rule")
        r = self.client.post("/rules/new/check", {"name": "t", "severity": "1", "origin": "human", "enabled": "on",
                                                 "detection": "sel:\n  path|contains: /.env\ncondition: sel"})
        self.assertContains(r, "1 of the last 1 events match")
        r = self.client.post("/rules/new/save", {"name": "t", "severity": "1", "origin": "human", "enabled": "on",
                                                "detection": "sel:\n  path|contains: /.env\ncondition: sel"})
        self.assertEqual(r["HX-Trigger"], "rules-changed")
        rule = Rule.objects.get(name="t")
        r = self.client.post(f"/rules/{rule.pk}/save", {"name": "t", "severity": "x", "origin": "human", "detection": rule.detection})
        self.assertContains(r, "severity must be")
        self.assertEqual(self.client.post(f"/rules/{rule.pk}/delete")["HX-Trigger"], "rules-changed")
        self.assertFalse(Rule.objects.filter(name="t").exists())
