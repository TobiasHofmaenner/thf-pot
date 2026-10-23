from django.core.management.base import BaseCommand

from apps.rules import engine, seed
from apps.rules.models import Rule


class Command(BaseCommand):
    help = "Load or refresh the bundled (origin=local) rules from seed.yml"

    def handle(self, *args, **opts):
        created, updated = seed.load(Rule)
        engine.invalidate()
        self.stdout.write(f"rules seeded: {created} created, {updated} updated")
