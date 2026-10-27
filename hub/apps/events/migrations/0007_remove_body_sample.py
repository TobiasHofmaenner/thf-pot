from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("events", "0006_move_bodies")]

    operations = [migrations.RemoveField(model_name="event", name="body_sample")]
