# Sensor → hub protocol, v1

All calls are HTTPS to `HUB_URL` (the node's `NODE_TOKEN`, formerly `SENSOR_TOKEN`) with `Authorization: Bearer <NODE_TOKEN>`. The hub maps the
token to a sensor; the sensor never names itself. Anything in a request body is attacker-derived
data and is treated as untrusted on the hub.

## `POST /api/v1/ingest`

- `Content-Type: application/x-ndjson`, `Content-Encoding: gzip`
- Body: up to 500 event records, one JSON object per line, schema v1 below.
- Response `202 Accepted` with `{"accepted": n, "duplicates": m}`. Any 2xx acknowledges the
  whole batch. Non-2xx means the sensor keeps the batch and retries with backoff; it will resend
  the same records, so the hub **must** dedupe on `id`.

## `POST /api/v1/heartbeat`

Every 60 s regardless of traffic, and immediately on every state change. JSON:
`ts, version, domains, cursor_file, cursor_offset, uptime_s, state, detail`.
Reply: `{"ok": true, "your_ip": "<address the hub saw the call from>"}`.
A sensor whose heartbeat stops is itself a signal.

`state` is the node's lifecycle, `detail` a free-form object the hub shows next to it:

| state | meaning | detail |
|---|---|---|
| `starting` | process up, hub not yet consulted | – |
| `dns_failed` | a domain does not resolve to `your_ip`; **the node does not open any port** and re-checks every 60 s | `public_ip`, `domains: {name: {ok, resolved: [...]}}`, `attempt` |
| `dns_ok` | every domain resolves to the node | same |
| `cert_pending` | listeners up, waiting for the CA (TLS-ALPN-01 on 443) | same |
| `cert_error` | an ACME order or renewal failed; serving continues on whatever certificate exists | + `error` |
| `ready` | certificate deployed, serving, shipping | + `certs: [domains]`; or `tls: disabled, dns: skipped` under `HTTP_ONLY` |

## Event record, schema v1

```json
{
  "v": 1,
  "id": "01JAX...",                  // ULID minted on the sensor; dedupe key
  "ts": "2026-10-23T12:00:00.123Z",  // sensor clock, UTC; hub also stores received_at
  "src": "203.0.113.9", "src_port": 51234,
  "self": false,                     // true for the operator's own probes (SELF_IPS / SELF_NETS)
  "http": {
    "scheme": "https", "version": "HTTP/1.1", "method": "POST",
    "target": "/index.php?page=upload", "path": "/index.php", "query": "page=upload",
    "headers": [["host","..."],["user-agent","..."], ...],   // wire order, names lowercased
    "hdr_fp": "9f3c1a0b2d4e6f70"      // sha256 of ordered header names; identifies the client software
  },
  "host": "example.org",
  "body": { "declared_len": 321, "read_len": 321, "truncated": false,
            "sha256": "...", "sample_b64": "..." },           // sample = first MAX_STORE_BYTES
  "multipart": { "boundary": "...", "parts": 4, "preamble_len": 0, "epilogue_len": 2,
                 "max_headers_in_part": 2, "max_name_depth": 0, "file_parts": 1,
                 "empty_file_parts": 0, "session_upload_progress": true, "names_sample": [...] },
  "flags": ["multipart", "mp:upload_progress_field", "cookie:phpsessid"],
  "resp": { "status": 200, "profile": "php-full", "bundle": "php", "tier": "full", "kind": "upload" },
  "dur_ms": 3
}
```

Flags are structural observations, never campaign names: `multipart`, `mp:upload_progress_field`,
`mp:excessive_part_headers`, `mp:many_empty_file_parts`, `mp:deep_nesting`, `mp:huge_part_count`,
`mp:preamble`, `no_content_length`, `large_body`, `cookie:phpsessid`. Labelling is the hub's job.

## Migrating the old `requests-*.jsonl`

The hub importer maps old records onto v1: `id` = ULID derived from `ts` plus a hash of
(src, method, path, body_sha256); `php2shell:*` flags become `mp:*`; `has_phpsessid` becomes
`cookie:phpsessid`; `resp` is reconstructed from the old tier config; `self` from the file name.
