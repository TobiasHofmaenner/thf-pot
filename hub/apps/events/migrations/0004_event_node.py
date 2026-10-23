"""Event.sensor -> Event.node (the server). The table it points at was renamed by nodes.0001, and the
FK constraint follows a rename by itself (Postgres tracks the OID), so only the column, the unique
constraint and the index are renamed here; the Django state is updated separately because its own
FK rewrite would try to reference the old table name."""

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("events", "0003_event_classified_at"), ("nodes", "0001_initial")]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL("ALTER TABLE events_event RENAME COLUMN sensor_id TO node_id",
                                  "ALTER TABLE events_event RENAME COLUMN node_id TO sensor_id"),
                migrations.RunSQL("ALTER TABLE events_event RENAME CONSTRAINT uniq_event_sensor_ulid TO uniq_event_node_ulid",
                                  "ALTER TABLE events_event RENAME CONSTRAINT uniq_event_node_ulid TO uniq_event_sensor_ulid"),
                migrations.RunSQL("ALTER INDEX event_sensor_ts RENAME TO event_node_ts",
                                  "ALTER INDEX event_node_ts RENAME TO event_sensor_ts"),
            ],
            state_operations=[
                migrations.RenameField(model_name="event", old_name="sensor", new_name="node"),
                migrations.AlterField(
                    model_name="event",
                    name="node",
                    field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="events", to="nodes.node"),
                ),
                migrations.RemoveConstraint(model_name="event", name="uniq_event_sensor_ulid"),
                migrations.AddConstraint(model_name="event", constraint=models.UniqueConstraint(fields=("node", "ulid"), name="uniq_event_node_ulid")),
                migrations.RemoveIndex(model_name="event", name="event_sensor_ts"),
                migrations.AddIndex(model_name="event", index=models.Index(fields=["node", "ts"], name="event_node_ts")),
            ],
        ),
    ]
