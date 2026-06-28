#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EDREvent {
    pub id: String,
    pub vendor: String,
    pub adapter_name: String,
    pub external_event_id: Option<String>,
    pub host_id: Option<String>,
    pub agent_id: Option<String>,
    pub hostname: Option<String>,
    pub process_guid: Option<String>,
    pub pid: Option<i64>,
    pub ppid: Option<i64>,
    pub exe_path: Option<String>,
    pub cmdline: Option<String>,
    pub file_path: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<i64>,
    pub severity: Option<i32>,
    pub event_name: String,
    pub observed_at: i64,
    pub raw_event_id: Option<String>,
    pub normalized_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EDRAlert {
    pub id: String,
    pub vendor: String,
    pub adapter_name: String,
    pub external_alert_id: Option<String>,
    pub host_id: Option<String>,
    pub hostname: Option<String>,
    pub alert_name: String,
    pub severity: i32,
    pub status: String,
    pub process_guid: Option<String>,
    pub pid: Option<i64>,
    pub tactic_tags_json: Option<String>,
    pub summary: Option<String>,
    pub observed_at: i64,
    pub raw_event_id: Option<String>,
}
