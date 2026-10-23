from django.db import migrations


def seed(apps, schema_editor):
    from apps.rules.seed import load

    load(apps.get_model("rules", "Rule"))


class Migration(migrations.Migration):
    dependencies = [("rules", "0001_initial")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
