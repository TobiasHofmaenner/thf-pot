import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Rule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=64, unique=True)),
                ("title", models.CharField(blank=True, default="", max_length=200)),
                ("description", models.TextField(blank=True, default="")),
                ("origin", models.CharField(choices=[("human", "human"), ("local", "local"), ("api", "api"), ("ai", "ai")], default="human", max_length=8)),
                ("tags", django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=40), blank=True, default=list, size=None)),
                ("severity", models.SmallIntegerField(choices=[(0, "benign"), (1, "suspicious"), (2, "malicious")], default=1)),
                ("cve", django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=24), blank=True, default=list, size=None)),
                ("enabled", models.BooleanField(default=True)),
                ("detection", models.TextField()),
                ("suppressed_by", django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=64), blank=True, default=list, size=None)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("created_by", models.CharField(blank=True, default="", max_length=80)),
            ],
            options={"ordering": ["-severity", "name"]},
        ),
    ]
