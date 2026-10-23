from ninja import NinjaAPI

from apps.events.api import router as events_router
from apps.sensors.api import router as sensors_router

from . import status

api = NinjaAPI(title="thf-pot hub", version="1", urls_namespace="api", docs_url="/docs")
api.add_router("", sensors_router)
api.add_router("", events_router)


@api.get("/status", tags=["hub"])
def get_status(request):
    return status.collect()
