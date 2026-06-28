#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub process_key: String,
    pub pid: i64,
    pub ppid: Option<i64>,
    pub process_guid: Option<String>,
    pub parent_process_key: Option<String>,
    pub exe_path: Option<String>,
    pub comm: Option<String>,
    pub cmdline: Option<String>,
    pub cwd: Option<String>,
    pub uid: Option<i64>,
    pub gid: Option<i64>,
    pub loginuid: Option<i64>,
    pub session_id: Option<i64>,
    pub start_time: i64,
    pub exit_time: Option<i64>,
    pub namespace_pid: Option<i64>,
    pub namespace_mnt: Option<i64>,
    pub namespace_net: Option<i64>,
    pub trust_score: i32,
    pub trust_reasons_json: Option<String>,
    pub flags_json: Option<String>,
}
