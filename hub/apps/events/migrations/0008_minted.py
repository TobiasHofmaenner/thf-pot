import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("events", "0007_remove_body_sample"), ("nodes", "0002_node_proxied")]

    operations = [
        migrations.AddField(
            model_name="event", name="minted_return",
            field=models.CharField(blank=True, db_index=True, default="", max_length=16),
        ),
        migrations.AddField(
            model_name="event", name="minted_return_key",
            field=models.CharField(blank=True, default="", max_length=16),
        ),
        migrations.CreateModel(
            name="MintedToken",
            fields=[
                ("key", models.CharField(max_length=16, primary_key=True, serialize=False)),
                ("at", models.CharField(max_length=40)),
                ("first_issued_at", models.DateTimeField()),
                ("last_issued_at", models.DateTimeField(db_index=True)),
                ("event", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE,
                                            related_name="minted_tokens", to="events.event")),
                ("node", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                                           related_name="minted_tokens", to="nodes.node")),
            ],
        ),
    ]
