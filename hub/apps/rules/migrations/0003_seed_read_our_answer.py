"""Re-run the seed loader so deployments pick up rules added to seed.yml. Rules whose origin is
still `local` are updated in place; anything a human took over is left alone."""

from django.db import migrations


def seed(apps, schema_editor):
    from apps.rules.seed import load

    load(apps.get_model("rules", "Rule"))


class Migration(migrations.Migration):
    dependencies = [("rules", "0002_seed_local_rules")]

    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
