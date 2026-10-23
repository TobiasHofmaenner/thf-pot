from ninja import NinjaAPI

from apps.sensors.api import router as sensors_router

from . import status

api = NinjaAPI(title="thf-pot hub", version="1", urls_namespace="api", docs_url="/docs")
api.add_router("", sensors_router)


@api.get("/status", tags=["hub"])
def get_status(request):
    return status.collect()
