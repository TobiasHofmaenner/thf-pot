"""Which of a node's sensors (hostnames) a request was aimed at. `*.example.org` matches any
single or multi-label name under it; a bare name matches exactly. Returns the matched entry, or ""."""


def match_host(host: str, domains) -> str:
    h = (host or "").lower().rstrip(".")
    if not h:
        return ""
    for d in domains or []:
        d = d.lower()
        if d.startswith("*."):
            if h.endswith(d[1:]) and h != d[2:]:
                return d
        elif h == d:
            return d
    return ""
