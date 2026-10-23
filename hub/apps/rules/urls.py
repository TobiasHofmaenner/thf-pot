from django.urls import path

from . import views

urlpatterns = [
    path("", views.rules, name="rules"),
    path("list", views.rule_list, name="rule_list"),
    path("new", views.rule_new, name="rule_new"),
    path("new/save", views.rule_save, name="rule_create"),
    path("new/check", views.rule_check, name="rule_check_new"),
    path("<int:pk>", views.rule_edit, name="rule_edit"),
    path("<int:pk>/save", views.rule_save, name="rule_save"),
    path("<int:pk>/check", views.rule_check, name="rule_check"),
    path("<int:pk>/delete", views.rule_delete, name="rule_delete"),
    path("export", views.rule_export_view, name="rules_export"),
]
