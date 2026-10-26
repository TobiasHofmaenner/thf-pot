# thf-pot sensor

A sensor node answers HTTP(S) like a small PHP site, writes every request it receives as one JSON
line on local disk, and ships those lines to the hub. It contains no detection logic, no
interpreter and no shell: one static binary and a directory of HTML files.

## Deploy

Point one or more hostnames at the box, open 80 and 443, then:

```sh
mkdir thf-pot && cd thf-pot
curl -fsSLO https://raw.githubusercontent.com/tobiashofmaenner/thf-pot/main/sensor/docker-compose.yml
cat > .env <<EOF
SENSOR_TOKEN=<token issued by the hub>
DOMAINS=example.org,www.example.org
ACME_EMAIL=you@example.org
EOF
docker compose up -d
```

Before it opens a port the node asks the hub which address it is calling from and checks that
every name in `DOMAINS` resolves to it. If one does not, it reports `dns_failed` (with what the
name actually resolved to), keeps every port closed, and re-checks every minute — fix the record
and it carries on by itself. The hub's nodes page shows the phases live:
`deployed → dns → certs → live`.

Certificates are obtained and renewed automatically (TLS-ALPN-01 on 443; nothing else to open).
Events land in the `data` volume as `events-YYYY-MM-DD.jsonl` (`docker compose exec` is not
available in a scratch image; read them with `docker run --rm -v thf-pot_data:/d alpine cat /d/events-2026-10-23.jsonl`
or bind-mount a host directory as the compose file describes) and are shipped to the hub within
seconds. If the hub is unreachable they wait on disk and are sent later, in order, with no loss.
Day files are deleted after `RETAIN_DAYS` (30) only once fully shipped.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `HUB_URL` | required | hub base URL, e.g. `https://pot.thfops.net` |
| `NODE_TOKEN` | required | bearer token issued by the hub for this node (`SENSOR_TOKEN` still accepted) |
| `DOMAINS` | required | comma-separated hostnames this node serves |
| `ACME_EMAIL` | – | contact for the CA (expiry notices) |
| `ACME_STAGING` | `0` | use Let's Encrypt staging (no rate limits, untrusted certs) |
| `HTTP_ONLY` | `0` | plain HTTP on `HTTP_PORT` only; `DOMAINS` optional |
| `HTTP_PORT` / `HTTPS_PORT` | `8080` / `8443` | listen ports inside the container |
| `SELF_IPS` | – | your own addresses; their requests are logged with `self: true` |
| `SELF_NETS` | RFC1918 + loopback | networks treated as self |
| `TRUST_PROXY` | `0` | take the source from `X-Real-IP` / `X-Forwarded-For` (only behind your own proxy) |
| `MAX_READ_BYTES` | 64 MiB | body bytes read from the client at most |
| `MAX_STORE_BYTES` | 64 MiB (= everything read) | body bytes kept in the record |
| `LOG_DIR` | `/data` | events, shipper cursor and certificate cache |
| `RETAIN_DAYS` | `30` | delete day files older than this once shipped; `0` keeps all |
| `PROFILES_FILE` | `/profiles.toml` | persona selection (see below) |

## Personas

`profiles.toml` picks a persona per request from source network, hostname and path prefix; a
persona is a *bundle* directory of static files under `bundles/`. Mount your own over the
defaults to change what a given network or hostname sees:

```yaml
volumes:
  - ./profiles.toml:/profiles.toml:ro
  - ./bundles:/bundles:ro
```

Tiers trade exposure for signal: `bare` (placeholder, no version header), `header` (site plus
`X-Powered-By`), `full` (plus an info page and an upload form).

## Build locally

```sh
cargo test
HUB_URL=http://127.0.0.1:9999 SENSOR_TOKEN=t HTTP_ONLY=1 LOG_DIR=./data \
  BUNDLES_DIR=./bundles PROFILES_FILE=./profiles.toml cargo run --release
```

The event schema and the hub endpoints are in [`../docs/PROTOCOL.md`](../docs/PROTOCOL.md).
