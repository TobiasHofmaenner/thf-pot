from django.db import migrations


class Migration(migrations.Migration):
    """State only: the table was renamed to nodes_node by nodes.0001 and the FK re-pointed by events.0004."""

    dependencies = [("sensors", "0003_sensor_self_ips_geo"), ("nodes", "0001_initial"), ("events", "0004_event_node")]

    operations = [
        migrations.SeparateDatabaseAndState(state_operations=[migrations.DeleteModel(name="Sensor")]),
    ]
