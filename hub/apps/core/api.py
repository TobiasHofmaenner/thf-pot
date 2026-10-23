from ninja import NinjaAPI

from . import status

api = NinjaAPI(title="thf-pot hub", version="1", urls_namespace="api", docs_url="/docs")


@api.get("/status")
def get_status(request):
    return status.collect()
