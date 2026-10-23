"""The copy-paste material a new node needs. Rendered once, when the token is in hand."""

from django.conf import settings


def hub_url(request) -> str:
    return (settings.HUB_PUBLIC_URL or request.build_absolute_uri("/")).rstrip("/")


def build(sensor, token: str, hub: str) -> dict:
    domains = ",".join(sensor.domains)
    image = settings.SENSOR_IMAGE
    acme = f"ACME_EMAIL={sensor.acme_email}\n" if sensor.acme_email else "# ACME_EMAIL=you@example.org\n"
    env = f"HUB_URL={hub}\nSENSOR_TOKEN={token}\nDOMAINS={domains}\n{acme}"

    run_lines = [
        "docker run -d --name thf-pot-sensor --restart unless-stopped",
        f"  -e HUB_URL={hub} -e SENSOR_TOKEN={token}",
        f"  -e DOMAINS={domains}",
    ]
    if sensor.acme_email:
        run_lines.append(f"  -e ACME_EMAIL={sensor.acme_email}")
    run_lines += [
        "  -p 80:8080 -p 443:8443 -v thf-pot-data:/data",
        "  --read-only --cap-drop ALL --security-opt no-new-privileges --memory 256m --pids-limit 64",
        f"  {image}",
    ]
    docker_run = " \\\n".join(run_lines)

    compose = f"""services:
  sensor:
    image: {image}
    container_name: thf-pot-sensor
    restart: unless-stopped
    env_file: .env
    ports:
      - "80:8080"
      - "443:8443"
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
    return {"docker_run": docker_run, "compose": compose, "env": env, "hub": hub, "image": image}
