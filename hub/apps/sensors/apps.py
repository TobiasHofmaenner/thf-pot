from django.apps import AppConfig


class SensorsConfig(AppConfig):
    """Migration history only: the server row moved to apps.nodes (node = server, sensor = a hostname pointed at it)."""

    name = "apps.sensors"
    label = "sensors"
