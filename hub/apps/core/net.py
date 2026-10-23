import ipaddress


def client_ip(request) -> str | None:
    """The address a request is really from. Behind the tunnel Cloudflare sets CF-Connecting-IP
    and the ingress X-Forwarded-For; nothing else can reach this app, so they are trusted."""
    for cand in (
        request.headers.get("CF-Connecting-IP", ""),
        request.headers.get("X-Forwarded-For", "").split(",")[0],
        request.META.get("REMOTE_ADDR", ""),
    ):
        cand = cand.strip()
        if cand:
            try:
                return str(ipaddress.ip_address(cand))
            except ValueError:
                continue
    return None
