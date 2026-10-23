import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("sensors", "0002_sensor_state")]

    operations = [
        migrations.AddField(
            model_name="sensor",
            name="self_ips",
            field=django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=64), blank=True, default=list, size=None),
        ),
        migrations.AddField(model_name="sensor", name="cc", field=models.CharField(blank=True, default="", max_length=2)),
        migrations.AddField(model_name="sensor", name="city", field=models.CharField(blank=True, default="", max_length=100)),
        migrations.AddField(model_name="sensor", name="lat", field=models.FloatField(blank=True, null=True)),
        migrations.AddField(model_name="sensor", name="lon", field=models.FloatField(blank=True, null=True)),
    ]
