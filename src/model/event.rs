#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub id: String,
    pub source_kind: String,
    pub source_name: String,
    pub event_name: String,
    pub observed_at: i64,
    pub host_id: Option<String>,
    pub hostname: Option<String>,
    pub process_key: Option<String>,
    pub severity: Option<i32>,
    pub payload_ref: Option<String>,
    pub payload_json: Option<String>,
    pub ingest_method: String,
    pub ingest_job_id: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub id: String,
    pub raw_event_id: Option<String>,
    pub source_kind: String,
    pub vendor: Option<String>,
    pub category: String,
    pub action: String,
    pub host_id: Option<String>,
    pub agent_id: Option<String>,
    pub hostname: Option<String>,
    pub process_guid: Option<String>,
    pub pid: Option<i64>,
    pub ppid: Option<i64>,
    pub uid: Option<i64>,
    pub gid: Option<i64>,
    pub user_name: Option<String>,
    pub exe_path: Option<String>,
    pub comm: Option<String>,
    pub cmdline: Option<String>,
    pub cwd: Option<String>,
    pub file_path: Option<String>,
    pub file_hash: Option<String>,
    pub src_ip: Option<String>,
    pub src_port: Option<i64>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<i64>,
    pub protocol: Option<String>,
    pub namespace_pid: Option<i64>,
    pub namespace_mnt: Option<i64>,
    pub namespace_net: Option<i64>,
    pub severity: Option<i32>,
    pub confidence: Option<f32>,
    pub observed_at: i64,
    pub tags_json: Option<String>,
}
