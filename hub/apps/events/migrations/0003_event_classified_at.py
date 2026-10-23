from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("events", "0002_event_geo")]

    operations = [
        migrations.AddField(model_name="event", name="classified_at", field=models.DateTimeField(blank=True, null=True)),
        migrations.AddIndex(model_name="event", index=models.Index(fields=["classified_at"], name="event_classified_at")),
    ]
