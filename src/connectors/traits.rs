#![allow(dead_code)]

use anyhow::Result;
use serde_json::Value;

use crate::model::edr::{EDRAlert, EDREvent};
use crate::model::event::NormalizedEvent;

pub trait Connector {
    fn name(&self) -> &'static str;
}

pub trait EDRAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn normalize_event(&self, payload: &Value) -> Result<Option<EDREvent>>;
    fn normalize_alert(&self, payload: &Value) -> Result<Option<EDRAlert>>;
    fn normalize_activity(
        &self,
        payload: &Value,
        raw_event_id: &str,
    ) -> Result<Option<NormalizedEvent>>;
}
