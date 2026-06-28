# Trace Lens

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-edition%202024-orange)](https://www.rust-lang.org/)

A Rust-based **blue team tracing, attribution, and investigation system** for single-host Ubuntu 24.04 deployments. Trace Lens ingests kernel-level events, correlates them into process trees and incident bundles, detects IOCs, and provides both CLI tools and a lightweight web UI for forensic analysis.

## Architecture

```
 Tracee (eBPF) ──NDJSON──> collector/tracee.rs ──> raw_events (SQLite)
                                                     │
 System tools ──────────> collector/ring0.rs ────────┤  (bpftool, unhide, etc.)
                                                     │
 EDR Webhook ──> connectors/edr/webhook.rs ─────────┤
                                                     ▼
                                          engine/proc_tree.rs   (Process tree)
                                          engine/incident.rs    (Incident aggregation)
                                          engine/trust.rs       (Trust scoring)
                                          engine/ioc.rs         (IOC + ATT&CK)
                                                     │
                                    ┌────────────────┼────────────────┐
                                    ▼                                 ▼
                              app.rs (CLI)                   api/server.rs (Axum HTTP)
                           trace-lens proc/                  Web UI (vanilla JS)
                           incident/net/file/
                           export/replay
```

## Features

- **eBPF Event Collection** — Ingests `sched_process_exec`, `sched_process_fork`, `sched_process_exit`, `security_file_open`, `net_tcp_connect`, and `net_packet_dns_request` via [Aqua Tracee](https://github.com/aquasecurity/tracee)
- **Ring0 Integrity Checks** — Kernel tainted flag, process/network cross-view comparison (`/proc` vs `ps`, `ss` vs `netstat`), bpftool inspection, unhide hidden process detection, mirror-trap file canaries, ghost-port canaries
- **EDR Adapter System** — Pluggable trait-based adapter; reference `GenericWebhookAdapter` normalizes external EDR events into the unified data model
- **Process Tree Construction** — Parent/child lineage up to 16 ancestors and 64 descendants with file/network/DNS event association
- **File Propagation Chain** — Tracks files from write source to execution target
- **IOC Detection** — Rules for curl-pipe-bash, reverse shells, netcat, busybox LOLBins, sensitive file access, cron/systemd persistence, lateral movement, and high-entropy DNS
- **ATT&CK Tagging** — Maps detected behaviors to MITRE ATT&CK tactics
- **Trust Scoring** — Per-process trust (5–100) based on path, UID, and command-line; host trust levels L0 (clean) through L3 (compromised)
- **Reports & Export** — Markdown reports, JSON timelines, and full forensic packages
- **Web UI** — Server-rendered HTML dashboard with dark/light theme support (Chinese-language UI)

## Dependencies

### Build

| Dependency       | Purpose                          |
|------------------|----------------------------------|
| Rust toolchain   | Compilation (edition 2024)       |
| `build-essential`| C compiler for `rusqlite` bindings |
| `libsqlite3-dev` | SQLite development headers       |
| `pkg-config`     | Library detection                |

```bash
sudo apt install build-essential libsqlite3-dev pkg-config
```

### Runtime

| Tool              | Purpose                                    |
|-------------------|--------------------------------------------|
| [Aqua Tracee](https://github.com/aquasecurity/tracee) | eBPF kernel event sensor (v0.24.1+) |
| `bpftool`         | eBPF program inspection for Ring0 checks   |
| `unhide`          | Hidden process detection                   |
| `ps`, `ss`, `netstat` | Standard Linux tools for cross-view integrity |
| `sqlite3`         | Optional: direct database inspection       |

```bash
sudo bash scripts/install.sh           # System dependencies + build trace-lens
sudo bash scripts/install-tracee.sh    # Install Aqua Tracee binary
```

### Rust Crates

| Crate              | Version | Purpose               |
|--------------------|---------|-----------------------|
| `anyhow`           | 1.0     | Error handling        |
| `axum`             | 0.8     | HTTP server           |
| `clap` (derive)    | 4.5     | CLI argument parsing  |
| `rusqlite`         | 0.37    | SQLite bindings       |
| `serde` / `serde_json` | 1.0 | JSON serialization    |
| `tokio`            | 1.48    | Async runtime         |
| `tracing` / `tracing-subscriber` | 0.1/0.3 | Structured logging |
| `tower-http`       | 0.6     | Static file serving middleware |

## Quick Start

```bash
# 1. Install system dependencies + build
sudo bash scripts/install.sh

# 2. Install Aqua Tracee (eBPF sensor)
sudo bash scripts/install-tracee.sh

# 3. Initialize the database
target/debug/trace-lens init-db --db-path db/trace-lens.db

# 4. Start the API server
target/debug/trace-lens serve --listen 127.0.0.1:18084 --db-path db/trace-lens.db

# 5. Open the dashboard
#    http://127.0.0.1:18084/
```

### One-shot Tracee capture + ingest

```bash
sudo bash scripts/run-tracee-live.sh
```

### Run as systemd service

```bash
sudo cp systemd/trace-lens.service /etc/systemd/system/
sudo cp systemd/tracee.service /etc/systemd/system/
sudo systemctl enable trace-lens tracee
sudo systemctl start trace-lens tracee
```

## CLI Reference

### Investigation

```bash
trace-lens proc <PID>                    # Process tree + ancestry
trace-lens proc <PID> --descendants      # Include descendants
trace-lens incident <PID>                # Full incident analysis
trace-lens incident <PID> --json         # JSON output
trace-lens net <IP|IP:PORT>              # Network lookup
trace-lens file <PATH>                   # File event lookup
trace-lens file <PATH> --chain           # File propagation chain
```

### Collection & Integrity

```bash
trace-lens tracee ingest --input events.ndjson
trace-lens ring0 check
trace-lens canary setup
trace-lens canary check
trace-lens canary serve                  # Foreground ghost-port listener
```

### Export & Replay

```bash
trace-lens export report --pid <PID>
trace-lens export timeline --pid <PID>
trace-lens export package --pid <PID> --output-dir runtime/exports
trace-lens replay <PID>
```

### Service

```bash
trace-lens serve
trace-lens serve --ring0 --ring0-interval 60
trace-lens serve --listen 0.0.0.0:8080
```

## API Endpoints

| Method | Path                              | Description                  |
|--------|-----------------------------------|------------------------------|
| GET    | `/api/v1/status`                  | System status                |
| GET    | `/api/v1/events`                  | Recent events                |
| GET    | `/api/v1/incidents`               | Incident list                |
| GET    | `/api/v1/incidents/{pid}`         | Incident detail              |
| GET    | `/api/v1/proc/{pid}`              | Process detail               |
| GET    | `/api/v1/net/{target}`            | Network search               |
| GET    | `/api/v1/file?path=/etc/passwd`   | File event search            |
| GET    | `/api/v1/file-chain?path=/tmp/x`  | File propagation chain       |
| GET    | `/api/v1/ring0`                   | Ring0 findings               |
| GET    | `/api/v1/edr/events`              | EDR event list               |
| POST   | `/api/v1/ingest/edr/{adapter}`    | EDR webhook ingest           |
| POST   | `/api/v1/import/edr/{adapter}`    | EDR batch import             |

### Authentication

Set `TRACE_LENS_API_TOKEN` to enable API authentication. Requests must include the header:

```
x-trace-lens-token: <token>
```
or
```
Authorization: Bearer <token>
```

Copy `.env.example` to `.env` and set your token for server-mode use.

## Configuration

| File                              | Purpose                                    |
|-----------------------------------|--------------------------------------------|
| `configs/tracee-policy.yaml`      | Tracee eBPF event capture policy           |
| `configs/edr-mapping.yaml`        | EDR adapter field mapping                  |
| `configs/profiles.yaml`           | Run profiles (light / full / deep)         |
| `configs/watch_paths.yaml`        | Sensitive & suspicious file paths for IOC  |

## Database Schema

14 SQLite tables (see `db/schema.sql`):

`schema_meta`, `raw_events`, `normalized_events`, `processes`, `process_edges`, `file_events`, `network_events`, `incidents`, `ioc_hits`, `ring0_findings`, `edr_events`, `edr_alerts`, `reports`, `integration_jobs`

## Validated Adversary Scenarios

```bash
bash scripts/validate-h1-01-curl-bash.sh      # curl|bash attack
bash scripts/validate-h1-02-bash-i.sh          # Interactive reverse shell
bash scripts/validate-h1-03-nc.sh              # Netcat backdoor
bash scripts/validate-h1-04-busybox-nc.sh      # Busybox LOLBin
bash scripts/validate-h1-05-cron.sh            # Cron persistence
bash scripts/validate-h1-06-systemd.sh         # Systemd persistence
bash scripts/validate-h2-02-unhide.sh          # Hidden process detection
bash scripts/validate-nice-04-dns-entropy.sh   # High-entropy DNS (DGA)
```

## Documentation

- [`docs/README.md`](docs/README.md) — Quick-start guide and CLI reference
- [`docs/API.md`](docs/API.md) — API endpoint reference
- [`docs/BEGINNER_GUIDE.md`](docs/BEGINNER_GUIDE.md) — Comprehensive beginner guide (Chinese)
- [`docs/PLAYBOOK.md`](docs/PLAYBOOK.md) — Operator playbook

## Acknowledgments

Trace Lens stands on the shoulders of several excellent open-source projects:

- **[Aqua Tracee](https://github.com/aquasecurity/tracee)** (Apache 2.0) — The eBPF-based runtime security and forensics sensor that provides kernel-level event capture. Trace Lens relies on Tracee as its primary data source for process execution, file access, network connection, and DNS query events.
- **[Mermaid.js](https://mermaid.js.org/)** — Process graph syntax used for generating visual process tree diagrams.
- **[Rust](https://www.rust-lang.org/)** and its ecosystem — The entire application is written in Rust, leveraging tokio, axum, rusqlite, serde, clap, and other foundational crates.

## License

This project is licensed under the [MIT License](LICENSE).

Third-party tools used by Trace Lens have their own licenses:
- Aqua Tracee: [Apache License 2.0](https://github.com/aquasecurity/tracee/blob/main/LICENSE)
