from django.shortcuts import render

from . import geo


def dashboard(request):
    return render(request, "events/dashboard.html", {"geo_version": geo.version()})
