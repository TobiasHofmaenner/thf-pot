import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("events", "0004_event_node")]

    operations = [
        migrations.CreateModel(
            name="Body",
            fields=[
                ("sha256", models.CharField(max_length=64, primary_key=True, serialize=False)),
                ("data", models.BinaryField()),
                ("size", models.BigIntegerField()),
                ("first_seen_at", models.DateTimeField()),
                ("last_seen_at", models.DateTimeField(db_index=True)),
            ],
        ),
        migrations.AddField(model_name="event", name="body_size", field=models.BigIntegerField(default=0)),
        migrations.AddField(
            model_name="event",
            name="body",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    related_name="events", to="events.body"),
        ),
    ]
