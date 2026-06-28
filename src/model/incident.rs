#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub incident_key: String,
    pub title: String,
    pub summary: String,
    pub severity: i32,
    pub confidence: f32,
    pub status: String,
    pub root_pid: Option<i64>,
    pub root_process_guid: Option<String>,
    pub host_id: Option<String>,
    pub hostname: Option<String>,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub source_count: i32,
    pub event_count: i32,
    pub tactic_tags_json: Option<String>,
    pub evidence_json: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentEDREvidence {
    pub event_id: String,
    pub alert_id: Option<String>,
    pub vendor: String,
    pub adapter_name: String,
    pub event_name: String,
    pub alert_name: Option<String>,
    pub pid: Option<i64>,
    pub process_guid: Option<String>,
    pub severity: Option<i32>,
    pub observed_at: i64,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayLine {
    pub observed_at: i64,
    pub source: String,
    pub title: String,
    pub detail: String,
}
