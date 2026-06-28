# Trace Lens

Trace Lens is a Rust-based blue team investigation tool for Ubuntu 24.04 that combines:

- Tracee event ingestion
- Ring0 integrity inspection
- EDR webhook/import normalization
- Process, file, network, and incident investigation
- Lightweight web views

## Quick start

1. Build:

```bash
source "$HOME/.cargo/env"
cargo build
```

2. Start service locally:

```bash
source "$HOME/.cargo/env"
cargo run -- serve --listen 127.0.0.1:18084 --db-path db/trace-lens.db
```

3. Open:

- `/`
- `/incident/4242`
- `/ring0`
- `/edr`
- `/net`
- `/file`

## Core CLI

```bash
trace-lens proc 4242 --db-path db/trace-lens.db
trace-lens incident 4242 --db-path db/trace-lens.db
trace-lens net 10.0.0.9 --db-path db/trace-lens.db
trace-lens file /etc/shadow --db-path db/trace-lens.db
trace-lens file /tmp/dropper --chain --db-path db/trace-lens.db
trace-lens hunt ring0
trace-lens export report --pid 4242 --db-path db/trace-lens.db
trace-lens export timeline --pid 4242 --db-path db/trace-lens.db
trace-lens export package --pid 4242 --db-path db/trace-lens.db
trace-lens replay 4242 --db-path db/trace-lens.db
```

## Tracee live capture

After installing a `tracee` binary to `/usr/local/bin/tracee`, run:

```bash
bash scripts/run-tracee-live.sh
```

This will:

1. capture a short live NDJSON stream from Tracee
2. ingest it into `db/trace-lens.db`
3. print recent Tracee event counts from SQLite

## Canary modes

Best-effort setup:

```bash
trace-lens canary setup
```

Stable foreground ghost-port listeners for a dedicated terminal or systemd unit:

```bash
trace-lens canary serve
```

## Forensic package export

```bash
trace-lens export package --pid 4242 --db-path db/trace-lens.db --output-dir runtime/exports
```

This writes `runtime/exports/incident-4242-package/` with:

- `report.md`
- `timeline.json`
- `incident.json`
- `ioc-hits.json`
- `attack-tags.json`
- `ring0-findings.json`
- `edr-evidence.json`
- `manifest.json`

## File propagation chain

```bash
trace-lens file /tmp/dropper --chain --db-path db/trace-lens.db
```

This summarizes:

- which process wrote the file
- which process later executed the same path
- timestamps and parent PID context for each step

## Validated adversary scenarios

`H1-01 curl|bash`:

```bash
bash scripts/validate-h1-01-curl-bash.sh
```

`H1-02 bash -i`:

```bash
bash scripts/validate-h1-02-bash-i.sh
```

`H1-03 nc`:

```bash
bash scripts/validate-h1-03-nc.sh
```

`H1-04 busybox nc`:

```bash
bash scripts/validate-h1-04-busybox-nc.sh
```

`H1-05 cron persistence`:

```bash
bash scripts/validate-h1-05-cron.sh
```

`H1-06 systemd persistence`:

```bash
bash scripts/validate-h1-06-systemd.sh
```

`H2-02 unhide chain`:

```bash
bash scripts/validate-h2-02-unhide.sh
```

`NICE-04 dns entropy`:

```bash
bash scripts/validate-nice-04-dns-entropy.sh
```

Artifacts are written under:

- `db/trace-lens-h1-01.db`
- `runtime/h1-01-curl-bash/incident.txt`
- `runtime/h1-01-curl-bash/exports/incident-<pid>-report.md`
- `runtime/h1-01-curl-bash/exports/incident-<pid>-timeline.json`
- `db/trace-lens-h1-02.db`
- `runtime/h1-02-bash-i/incident.txt`
- `runtime/h1-02-bash-i/exports/incident-<pid>-report.md`
- `runtime/h1-02-bash-i/exports/incident-<pid>-timeline.json`
- `db/trace-lens-h1-03.db`
- `runtime/h1-03-nc/incident.txt`
- `runtime/h1-03-nc/exports/incident-<pid>-report.md`
- `runtime/h1-03-nc/exports/incident-<pid>-timeline.json`
- `db/trace-lens-h1-04.db`
- `runtime/h1-04-busybox-nc/incident.txt`
- `runtime/h1-04-busybox-nc/exports/incident-<pid>-report.md`
- `runtime/h1-04-busybox-nc/exports/incident-<pid>-timeline.json`
- `db/trace-lens-h1-05.db`
- `runtime/h1-05-cron/incident.txt`
- `runtime/h1-05-cron/exports/incident-<pid>-report.md`
- `runtime/h1-05-cron/exports/incident-<pid>-timeline.json`
- `db/trace-lens-h1-06.db`
- `runtime/h1-06-systemd/incident.txt`
- `runtime/h1-06-systemd/exports/incident-<pid>-report.md`
- `runtime/h1-06-systemd/exports/incident-<pid>-timeline.json`
- `db/trace-lens-h2-02.db`
- `runtime/h2-02-unhide/ring0-check.txt`
- `db/trace-lens-nice-04.db`
- `runtime/nice-04-dns-entropy/incident.txt`
- `runtime/nice-04-dns-entropy/exports/incident-7000-report.md`

## Current scope

This first phase prioritizes:

- single-host workflow
- SQLite storage
- generic EDR integration
- web views over heavy frontend framework

It does not include distributed correlation, full SIEM integration, or a custom eBPF sensor stack.
