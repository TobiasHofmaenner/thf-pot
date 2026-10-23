from ninja import NinjaAPI

from apps.events.api import router as events_router
from apps.rules.api import router as rules_router
from apps.nodes.api import router as nodes_router

from . import status

api = NinjaAPI(title="thf-pot hub", version="1", urls_namespace="api", docs_url="/docs")
api.add_router("", nodes_router)
api.add_router("", events_router)
api.add_router("", rules_router)


@api.get("/status", tags=["hub"])
def get_status(request):
    return status.collect()
