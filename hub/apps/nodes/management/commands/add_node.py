"""Same as the "add node" button, from a shell: prints the token and the .env once."""

from django.core.management.base import BaseCommand, CommandError

from apps.nodes import snippets
from apps.nodes.models import Node
from apps.nodes.views import parse_domains


class Command(BaseCommand):
    help = "Create a node node and print its token"

    def add_arguments(self, parser):
        parser.add_argument("--domains", required=True, help="comma-separated hostnames the node serves")
        parser.add_argument("--name", default="", help="defaults to the first domain")
        parser.add_argument("--hub", default="", help="public hub URL for the snippets (default: HUB_PUBLIC_URL)")

    def handle(self, *args, **opts):
        try:
            domains = parse_domains(opts["domains"])
        except ValueError as e:
            raise CommandError(str(e)) from e
        if not domains:
            raise CommandError("no domains")
        node = Node(name=opts["name"] or domains[0], domains=domains)
        token = node.mint_token()
        node.save()
        from django.conf import settings

        hub = opts["hub"] or settings.HUB_PUBLIC_URL or "https://pot.thfops.net"
        s = snippets.build(node, token, hub)
        self.stdout.write(f"node {node.name} (id {node.pk}) created\n\n# .env\n{s['env']}\n{s['docker_run']}\n")
