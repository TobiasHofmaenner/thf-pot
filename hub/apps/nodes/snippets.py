"""The copy-paste material a new node needs. Rendered once, when the token is in hand."""

import ipaddress

from django.conf import settings

# The node replaces its own default (RFC 1918 + loopback) when SELF_NETS is set, so keep those.
DEFAULT_SELF_NETS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128"


def hub_url(request) -> str:
    return (settings.HUB_PUBLIC_URL or request.build_absolute_uri("/")).rstrip("/")


def split_self(entries) -> tuple[str, str]:
    """Plain addresses go to SELF_IPS, networks to SELF_NETS (on top of the node's defaults)."""
    ips, nets = [], []
    for s in entries or []:
        try:
            ipaddress.ip_address(s)
            ips.append(s)
        except ValueError:
            nets.append(s)
    return ",".join(ips), (DEFAULT_SELF_NETS + "," + ",".join(nets)) if nets else ""


def env_lines(node, token: str, hub: str) -> list[str]:
    self_ips, self_nets = split_self(node.self_ips)
    lines = [f"HUB_URL={hub}", f"NODE_TOKEN={token}", f"DOMAINS={','.join(node.domains)}"]
    proxied = getattr(node, "proxied", False)
    if not proxied:
        lines.append(f"ACME_EMAIL={node.acme_email}" if node.acme_email else "# ACME_EMAIL=you@example.org")
    if self_ips:
        lines.append(f"SELF_IPS={self_ips}")
    if self_nets:
        lines.append(f"SELF_NETS={self_nets}")
    if proxied:
        lines += ["HTTP_ONLY=1", "TRUST_PROXY=1"]
    return lines


def build(node, token: str, hub: str) -> dict:
    image = settings.SENSOR_IMAGE
    env = env_lines(node, token, hub)
    proxied = getattr(node, "proxied", False)
    # Behind the operator's proxy only loopback is published; the proxy forwards to 127.0.0.1:8081.
    ports_run = "-p 127.0.0.1:8081:8080" if proxied else "-p 80:8080 -p 443:8443"
    ports_compose = '      - "127.0.0.1:8081:8080"' if proxied else '      - "80:8080"\n      - "443:8443"'
    run_lines = ["docker run -d --name thf-pot-node --restart unless-stopped"]
    run_lines += [f"  -e {line}" for line in env if not line.startswith("#")]
    run_lines += [
        f"  {ports_run} -v thf-pot-data:/data",
        "  --read-only --cap-drop ALL --security-opt no-new-privileges --memory 256m --pids-limit 64",
        f"  {image}",
    ]
    docker_run = " \\\n".join(run_lines)

    compose = f"""services:
  node:
    image: {image}
    container_name: thf-pot-node
    restart: unless-stopped
    env_file: .env
    ports:
{ports_compose}
    volumes:
      - data:/data
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 256m
    pids_limit: 64
    logging:
      driver: json-file
      options: {{ max-size: "10m", max-file: "3" }}

volumes:
  data:
"""
    return {"docker_run": docker_run, "compose": compose, "env": "\n".join(env) + "\n", "hub": hub, "image": image}
