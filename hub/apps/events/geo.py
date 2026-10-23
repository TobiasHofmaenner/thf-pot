"""IP geolocation from the DB-IP Lite databases baked into the image (CC BY 4.0; the map carries
the attribution). Readers are mmap-backed and opened once per process; a missing file simply
means no geo, never an error."""

import logging
import os
from functools import lru_cache

from django.conf import settings

log = logging.getLogger(__name__)


@lru_cache(maxsize=None)
def _reader(name: str):
    path = os.path.join(settings.GEOIP_DIR, name)
    if not os.path.exists(path):
        log.warning("geo database missing: %s", path)
        return None
    import maxminddb

    return maxminddb.open_database(path)


def lookup(ip: str) -> dict:
    """cc, city, lat, lon, asn, as_name — whichever of the two databases know the address."""
    out: dict = {}
    city = _reader("dbip-city-lite.mmdb")
    if city is not None:
        try:
            d = city.get(ip) or {}
        except ValueError:
            d = {}
        if d:
            out["cc"] = ((d.get("country") or {}).get("iso_code") or "")[:2]
            names = (d.get("city") or {}).get("names") or {}
            subdiv = ((d.get("subdivisions") or [{}])[0].get("names") or {})
            out["city"] = (names.get("en") or subdiv.get("en") or "")[:100]
            loc = d.get("location") or {}
            out["lat"], out["lon"] = loc.get("latitude"), loc.get("longitude")
    asn = _reader("dbip-asn-lite.mmdb")
    if asn is not None:
        try:
            d = asn.get(ip) or {}
        except ValueError:
            d = {}
        if d:
            out["asn"] = d.get("autonomous_system_number")
            out["as_name"] = (d.get("autonomous_system_organization") or "")[:200]
    return out


def version() -> str:
    try:
        with open(os.path.join(settings.GEOIP_DIR, "VERSION")) as f:
            return f.read().strip()
    except OSError:
        return "none"
