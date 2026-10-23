from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("nodes", "0001_initial")]

    operations = [
        migrations.AddField(model_name="node", name="proxied", field=models.BooleanField(default=False)),
    ]
