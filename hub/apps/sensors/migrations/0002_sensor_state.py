from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("sensors", "0001_initial")]

    operations = [
        migrations.AddField(model_name="sensor", name="state", field=models.CharField(default="new", max_length=32)),
        migrations.AddField(model_name="sensor", name="state_detail", field=models.JSONField(blank=True, null=True)),
        migrations.AddField(model_name="sensor", name="state_changed_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="sensor", name="first_seen_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="sensor", name="public_ip", field=models.GenericIPAddressField(blank=True, null=True)),
    ]
