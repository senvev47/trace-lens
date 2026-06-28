#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ring0Finding {
    pub id: String,
    pub finding_type: String,
    pub detector: String,
    pub severity: i32,
    pub trust_level: String,
    pub host_id: Option<String>,
    pub hostname: Option<String>,
    pub pid: Option<i64>,
    pub object_ref: Option<String>,
    pub summary: String,
    pub detail_json: Option<String>,
    pub observed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ring0CheckSummary {
    pub host_id: Option<String>,
    pub hostname: Option<String>,
    pub findings: Vec<Ring0Finding>,
}
