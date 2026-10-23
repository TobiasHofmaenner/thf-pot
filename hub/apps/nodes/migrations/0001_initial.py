"""The server row used to be sensors.Sensor. Vocabulary: node = the server, sensor = a hostname
pointed at it. The table is renamed in place so existing rows (and the events pointing at them)
survive; the model state is created fresh here and removed from the sensors app in its 0004."""

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    # After every migration that still creates something referencing the old table name: on a fresh
    # database events.0001 adds its FK as deferred SQL against "sensors_sensor", so the rename must
    # come after it, not before.
    dependencies = [("sensors", "0003_sensor_self_ips_geo"), ("events", "0003_event_classified_at")]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL("ALTER TABLE sensors_sensor RENAME TO nodes_node",
                                  "ALTER TABLE nodes_node RENAME TO sensors_sensor"),
                migrations.RunSQL("ALTER SEQUENCE IF EXISTS sensors_sensor_id_seq RENAME TO nodes_node_id_seq",
                                  "ALTER SEQUENCE IF EXISTS nodes_node_id_seq RENAME TO sensors_sensor_id_seq"),
            ],
            state_operations=[
                migrations.CreateModel(
                    name="Node",
                    fields=[
                        ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                        ("name", models.CharField(max_length=80, unique=True)),
                        ("kind", models.CharField(default="web-pot", max_length=32)),
                        ("domains", django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=253), blank=True, default=list, size=None)),
                        ("self_ips", django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=64), blank=True, default=list, size=None)),
                        ("acme_email", models.EmailField(blank=True, default="", max_length=254)),
                        ("notes", models.TextField(blank=True, default="")),
                        ("cc", models.CharField(blank=True, default="", max_length=2)),
                        ("city", models.CharField(blank=True, default="", max_length=100)),
                        ("lat", models.FloatField(blank=True, null=True)),
                        ("lon", models.FloatField(blank=True, null=True)),
                        ("token_sha256", models.CharField(max_length=64, unique=True)),
                        ("token_prefix", models.CharField(max_length=8)),
                        ("is_active", models.BooleanField(default=True)),
                        ("created_at", models.DateTimeField(auto_now_add=True)),
                        ("token_rotated_at", models.DateTimeField(blank=True, null=True)),
                        ("last_seen_at", models.DateTimeField(blank=True, null=True)),
                        ("last_heartbeat", models.JSONField(blank=True, null=True)),
                        ("last_event_at", models.DateTimeField(blank=True, null=True)),
                        ("events_total", models.BigIntegerField(default=0)),
                        ("state", models.CharField(default="new", max_length=32)),
                        ("state_detail", models.JSONField(blank=True, null=True)),
                        ("state_changed_at", models.DateTimeField(blank=True, null=True)),
                        ("first_seen_at", models.DateTimeField(blank=True, null=True)),
                        ("public_ip", models.GenericIPAddressField(blank=True, null=True)),
                    ],
                    options={"ordering": ["name"]},
                ),
            ],
        ),
    ]
