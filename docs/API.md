# API

## Health

- `GET /healthz`
- `GET /api/v1/status`

## Investigation

- `GET /api/v1/incidents`
- `GET /api/v1/incidents/{pid}`
- `GET /api/v1/proc/{pid}`
- `GET /api/v1/net/{target}`
- `GET /api/v1/file?path=/abs/path`
- `GET /api/v1/file-chain?path=/abs/path`

Notes:

- `GET /api/v1/proc/{pid}` includes `dns_events` when `net_packet_dns_request` telemetry is present
- `GET /api/v1/incidents/{pid}` includes aggregated `dns_events`

## Ring0

- `GET /api/v1/ring0`
- `GET /api/v1/ring0/findings`

## EDR

- `GET /api/v1/edr/events`
- `GET /api/v1/edr/alerts`
- `GET /api/v1/integrations/edr`
- `POST /api/v1/ingest/edr/{adapter}`
- `POST /api/v1/ingest/edr/{adapter}/events`
- `POST /api/v1/ingest/edr/{adapter}/alerts`
- `POST /api/v1/import/edr/{adapter}`

## Web pages

- `GET /`
- `GET /incident/{pid}`
- `GET /ring0`
- `GET /edr`
- `GET /net`
- `GET /file`
