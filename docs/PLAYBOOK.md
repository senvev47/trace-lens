# PLAYBOOK

## 1. Start collection

```bash
trace-lens tracee ingest --input samples/tracee-events.ndjson --db-path db/trace-lens.db
trace-lens ring0 check --db-path db/trace-lens.db
trace-lens canary setup
trace-lens canary check --db-path db/trace-lens.db
```

Stable foreground canary listeners:

```bash
trace-lens canary serve
```

Live Tracee capture after the `tracee` binary is installed:

```bash
bash scripts/run-tracee-live.sh
```

## 2. Investigate a suspicious PID

```bash
trace-lens proc 4242 --db-path db/trace-lens.db
trace-lens incident 4242 --db-path db/trace-lens.db
```

## 3. Investigate network and file evidence

```bash
trace-lens net 10.0.0.9 --db-path db/trace-lens.db
trace-lens file /etc/shadow --db-path db/trace-lens.db
trace-lens file /tmp/dropper --chain --db-path db/trace-lens.db
```

## 4. Investigate Ring0 integrity

```bash
trace-lens hunt ring0
trace-lens ring0 findings --db-path db/trace-lens.db
```

## 5. Ingest EDR evidence

Generic webhook:

```bash
curl -X POST http://127.0.0.1:18084/api/v1/ingest/edr/generic \
  -H 'content-type: application/json' \
  -d '{"adapter":"generic","payload":{"event_name":"edr_process_alert","alert_name":"suspicious_bash","host_id":"blue-host","hostname":"blue","pid":4242,"process_guid":"proc-guid-1","severity":8,"observed_at":1718611205,"summary":"sample"}}'
```

Batch import:

```bash
curl -X POST http://127.0.0.1:18084/api/v1/import/edr/generic \
  -H 'content-type: application/json' \
  -d '{"payloads":[{"event_name":"import_event","host_id":"blue-host","hostname":"blue","pid":4242,"process_guid":"proc-guid-1","severity":5,"observed_at":1718611605,"summary":"import"}]}'
```

## 6. Export and replay

```bash
trace-lens export report --pid 4242 --db-path db/trace-lens.db
trace-lens export timeline --pid 4242 --db-path db/trace-lens.db
trace-lens export package --pid 4242 --db-path db/trace-lens.db
trace-lens replay 4242 --db-path db/trace-lens.db
```

Artifacts:

- `runtime/exports/incident-4242-report.md`
- `runtime/exports/incident-4242-timeline.json`
- `runtime/exports/incident-4242-package/`

## 6.1 Track file delivery and execution

```bash
trace-lens file /tmp/dropper --chain --db-path db/trace-lens.db
```

Expected output:

- one or more `writes` entries for the file path
- zero or more `executions` entries when the same path is later executed

## 7. Validate `curl|bash`

```bash
bash scripts/validate-h1-01-curl-bash.sh
```

Expected outputs:

- `db/trace-lens-h1-01.db`
- `runtime/h1-01-curl-bash/incident.txt`
- `runtime/h1-01-curl-bash/exports/incident-<pid>-report.md`
- `runtime/h1-01-curl-bash/exports/incident-<pid>-timeline.json`

## 8. Validate `bash -i`

```bash
bash scripts/validate-h1-02-bash-i.sh
```

Expected outputs:

- `db/trace-lens-h1-02.db`
- `runtime/h1-02-bash-i/incident.txt`
- `runtime/h1-02-bash-i/exports/incident-<pid>-report.md`
- `runtime/h1-02-bash-i/exports/incident-<pid>-timeline.json`

## 9. Validate `nc`

```bash
bash scripts/validate-h1-03-nc.sh
```

Expected outputs:

- `db/trace-lens-h1-03.db`
- `runtime/h1-03-nc/incident.txt`
- `runtime/h1-03-nc/exports/incident-<pid>-report.md`
- `runtime/h1-03-nc/exports/incident-<pid>-timeline.json`

## 10. Validate `busybox nc`

```bash
bash scripts/validate-h1-04-busybox-nc.sh
```

Expected outputs:

- `db/trace-lens-h1-04.db`
- `runtime/h1-04-busybox-nc/incident.txt`
- `runtime/h1-04-busybox-nc/exports/incident-<pid>-report.md`
- `runtime/h1-04-busybox-nc/exports/incident-<pid>-timeline.json`

## 11. Validate cron persistence

```bash
bash scripts/validate-h1-05-cron.sh
```

Expected outputs:

- `db/trace-lens-h1-05.db`
- `runtime/h1-05-cron/incident.txt`
- `runtime/h1-05-cron/exports/incident-<pid>-report.md`
- `runtime/h1-05-cron/exports/incident-<pid>-timeline.json`

## 12. Validate systemd persistence

```bash
bash scripts/validate-h1-06-systemd.sh
```

Expected outputs:

- `db/trace-lens-h1-06.db`
- `runtime/h1-06-systemd/incident.txt`
- `runtime/h1-06-systemd/exports/incident-<pid>-report.md`
- `runtime/h1-06-systemd/exports/incident-<pid>-timeline.json`

## 13. Validate unhide chain

```bash
bash scripts/validate-h2-02-unhide.sh
```

Expected outputs:

- `db/trace-lens-h2-02.db`
- `runtime/h2-02-unhide/ring0-check.txt`

## 14. Validate DNS entropy detection

```bash
bash scripts/validate-nice-04-dns-entropy.sh
```

Expected outputs:

- `db/trace-lens-nice-04.db`
- `runtime/nice-04-dns-entropy/incident.txt`
- `runtime/nice-04-dns-entropy/exports/incident-7000-report.md`
