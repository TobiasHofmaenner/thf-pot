from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("events", "0001_initial")]

    operations = [
        migrations.AddField(model_name="event", name="cc", field=models.CharField(blank=True, default="", max_length=2)),
        migrations.AddField(model_name="event", name="city", field=models.CharField(blank=True, default="", max_length=100)),
        migrations.AddField(model_name="event", name="lat", field=models.FloatField(blank=True, null=True)),
        migrations.AddField(model_name="event", name="lon", field=models.FloatField(blank=True, null=True)),
        migrations.AddField(model_name="event", name="asn", field=models.IntegerField(blank=True, null=True)),
        migrations.AddField(model_name="event", name="as_name", field=models.CharField(blank=True, default="", max_length=200)),
        migrations.AddField(model_name="event", name="geo_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddIndex(model_name="event", index=models.Index(fields=["geo_at"], name="event_geo_at")),
    ]
