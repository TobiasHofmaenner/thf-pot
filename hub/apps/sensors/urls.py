from django.urls import path

from . import views

urlpatterns = [
    path("", views.nodes, name="nodes"),
    path("list", views.node_list, name="node_list"),
    path("new", views.node_create, name="node_create"),
    path("<int:pk>/rotate", views.node_rotate, name="node_rotate"),
    path("<int:pk>/toggle", views.node_toggle, name="node_toggle"),
    path("<int:pk>/delete", views.node_delete, name="node_delete"),
]
