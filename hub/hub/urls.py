from django.urls import path

from apps.core import views
from apps.core.api import api

urlpatterns = [
    path("", views.index, name="index"),
    path("_status", views.status_fragment, name="status_fragment"),
    path("healthz", views.healthz, name="healthz"),
    path("readyz", views.readyz, name="readyz"),
    path("api/v1/", api.urls),
]
