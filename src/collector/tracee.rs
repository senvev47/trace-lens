#![allow(dead_code)]

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use serde_json::Value;

use crate::model::event::RawEvent;
use crate::storage::sqlite;

#[derive(Debug, Default)]
pub struct TraceeCollector;

#[derive(Debug, Clone)]
pub struct IngestSummary {
    pub input: String,
    pub read_lines: usize,
    pub parsed_events: usize,
    pub inserted_events: usize,
}

pub fn recommended_runbook() -> String {
    [
        "Tracee ingestion runbook:",
        "1. Ensure the Tracee binary is available on the host.",
        "2. Use the bundled policy at configs/tracee-policy.yaml.",
        "3. Start Tracee with JSON output and parsed arguments:",
        "   tracee --policy configs/tracee-policy.yaml --output json --output option:parse-arguments",
        "4. Persist output to a file or pipe it into the ingestor:",
        "   tracee --policy configs/tracee-policy.yaml --output json --output option:parse-arguments > runtime/tracee-events.ndjson",
        "5. Ingest the NDJSON stream into SQLite:",
        "   trace-lens tracee ingest --input runtime/tracee-events.ndjson --db-path db/trace-lens.db",
        "6. For service deployment, see systemd/tracee.service.",
    ]
    .join("\n")
}

pub fn ingest_to_db(input: &str, db_path: &Path) -> Result<IngestSummary> {
    let reader = open_reader(input)?;
    let mut events = Vec::new();
    let mut read_lines = 0usize;

    for (index, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("failed reading line {}", index + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        read_lines += 1;
        let event = parse_ndjson_line(trimmed, index + 1)
            .with_context(|| format!("failed parsing Tracee JSON at line {}", index + 1))?;
        events.push(event);
    }

    let inserted_events = sqlite::insert_raw_events(db_path, &events)?;

    Ok(IngestSummary {
        input: input.to_string(),
        read_lines,
        parsed_events: events.len(),
        inserted_events,
    })
}

fn open_reader(input: &str) -> Result<Box<dyn BufRead>> {
    if input == "-" {
        return Ok(Box::new(BufReader::new(io::stdin())));
    }

    let file = File::open(input).with_context(|| format!("failed to open input: {input}"))?;
    Ok(Box::new(BufReader::new(file)))
}

fn parse_ndjson_line(line: &str, line_no: usize) -> Result<RawEvent> {
    let value: Value = serde_json::from_str(line)?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("Tracee event must be a JSON object"))?;

    let event_name = get_string(object, &["eventName", "event_name"])
        .unwrap_or_else(|| "unknown_event".to_string());
    let observed_at = get_i64(object, &["timestamp", "ts"]).unwrap_or_else(now_unix_seconds);
    let pid = get_i64(
        object,
        &[
            "processId",
            "process_id",
            "hostProcessId",
            "host_process_id",
        ],
    );

    let process_key = pid.map(|pid| format!("tracee:{pid}:{observed_at}"));
    let host_id = get_string(object, &["hostName", "host_name"]);
    let severity = classify_severity(&event_name);
    let id = format!(
        "tracee:{}:{}:{}:{}",
        observed_at,
        event_name,
        pid.unwrap_or_default(),
        line_no
    );

    Ok(RawEvent {
        id,
        source_kind: "tracee".to_string(),
        source_name: "tracee".to_string(),
        event_name,
        observed_at,
        host_id: host_id.clone(),
        hostname: host_id,
        process_key,
        severity: Some(severity),
        payload_ref: None,
        payload_json: Some(line.to_string()),
        ingest_method: "tracee-ndjson".to_string(),
        ingest_job_id: None,
        created_at: now_unix_seconds(),
    })
}

fn get_string(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        object.get(*key).and_then(|value| match value {
            Value::String(s) => Some(s.to_string()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
    })
}

fn get_i64(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|key| {
        object.get(*key).and_then(|value| match value {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.parse::<i64>().ok(),
            _ => None,
        })
    })
}

fn classify_severity(event_name: &str) -> i32 {
    match event_name {
        "hooked_syscall" | "hidden_kernel_module" => 9,
        "security_file_open" | "security_inode_rename" | "security_inode_unlink" => 6,
        "net_packet_dns_request" => 6,
        "sched_process_exec" | "tcp_connect" | "net_tcp_connect" | "security_socket_connect" => 5,
        "sched_process_fork" | "sched_process_exit" => 3,
        _ => 4,
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::parse_ndjson_line;

    #[test]
    fn parse_tracee_exec_event_to_raw_event() {
        let line = r#"{"timestamp":1718611200,"eventName":"sched_process_exec","hostName":"blue","processId":4242,"processName":"bash","args":[{"name":"pathname","value":"/usr/bin/bash"}]}"#;
        let event = parse_ndjson_line(line, 1).expect("tracee event should parse");

        assert_eq!(event.source_kind, "tracee");
        assert_eq!(event.event_name, "sched_process_exec");
        assert_eq!(event.hostname.as_deref(), Some("blue"));
        assert_eq!(event.process_key.as_deref(), Some("tracee:4242:1718611200"));
        assert_eq!(event.severity, Some(5));
        assert!(event.payload_json.is_some());
    }
}
