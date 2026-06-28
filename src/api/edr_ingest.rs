use axum::{Json, extract::Path, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::app::AppState;
use crate::connectors::edr::default_registry;
use crate::connectors::edr::webhook::EDRWebhookEnvelope;
use crate::model::event::RawEvent;
use crate::storage::sqlite;

#[derive(Debug, Serialize)]
pub struct EDRIngestResponse {
    pub adapter: String,
    pub event_normalized: bool,
    pub alert_normalized: bool,
}

#[derive(Debug, Serialize)]
pub struct EDRImportResponse {
    pub adapter: String,
    pub accepted: usize,
}

#[derive(Debug, Deserialize)]
pub struct EDRImportRequest {
    pub payloads: Vec<Value>,
}

#[derive(Debug, Clone, Copy)]
pub enum EDRIngestKind {
    Generic,
    EventOnly,
    AlertOnly,
}

pub async fn ingest_edr_webhook(
    State(state): State<AppState>,
    Path(adapter): Path<String>,
    Json(envelope): Json<EDRWebhookEnvelope>,
) -> Result<Json<EDRIngestResponse>, StatusCode> {
    ingest_edr_webhook_kind(state, adapter, envelope, EDRIngestKind::Generic).await
}

pub async fn ingest_edr_event_webhook(
    State(state): State<AppState>,
    Path(adapter): Path<String>,
    Json(envelope): Json<EDRWebhookEnvelope>,
) -> Result<Json<EDRIngestResponse>, StatusCode> {
    ingest_edr_webhook_kind(state, adapter, envelope, EDRIngestKind::EventOnly).await
}

pub async fn ingest_edr_alert_webhook(
    State(state): State<AppState>,
    Path(adapter): Path<String>,
    Json(envelope): Json<EDRWebhookEnvelope>,
) -> Result<Json<EDRIngestResponse>, StatusCode> {
    ingest_edr_webhook_kind(state, adapter, envelope, EDRIngestKind::AlertOnly).await
}

pub async fn import_edr_payloads(
    State(state): State<AppState>,
    Path(adapter): Path<String>,
    Json(request): Json<EDRImportRequest>,
) -> Result<Json<EDRImportResponse>, StatusCode> {
    let mut accepted = 0usize;

    for payload in request.payloads {
        let envelope = EDRWebhookEnvelope {
            adapter: adapter.clone(),
            payload,
        };
        let _ = ingest_edr_webhook_kind(
            state.clone(),
            adapter.clone(),
            envelope,
            EDRIngestKind::Generic,
        )
        .await?;
        accepted += 1;
    }

    Ok(Json(EDRImportResponse { adapter, accepted }))
}

async fn ingest_edr_webhook_kind(
    state: AppState,
    adapter: String,
    envelope: EDRWebhookEnvelope,
    ingest_kind: EDRIngestKind,
) -> Result<Json<EDRIngestResponse>, StatusCode> {
    let registry = default_registry();
    let Some(handler) = registry.get(&adapter) else {
        return Err(StatusCode::NOT_FOUND);
    };

    sqlite::init_database(&state.db_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let raw_event = RawEvent {
        id: format!("raw:edr:{}:{}", adapter, now_unix_nanos()),
        source_kind: "edr".to_string(),
        source_name: adapter.clone(),
        event_name: envelope
            .payload
            .get("event_name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("generic_edr")
            .to_string(),
        observed_at: envelope
            .payload
            .get("observed_at")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or_else(now_unix_seconds),
        host_id: envelope
            .payload
            .get("host_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        hostname: envelope
            .payload
            .get("hostname")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        process_key: envelope
            .payload
            .get("process_guid")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        severity: envelope
            .payload
            .get("severity")
            .and_then(serde_json::Value::as_i64)
            .map(|v| v as i32),
        payload_ref: None,
        payload_json: Some(envelope.payload.to_string()),
        ingest_method: "edr-webhook".to_string(),
        ingest_job_id: None,
        created_at: now_unix_seconds(),
    };

    sqlite::insert_raw_events(&state.db_path, std::slice::from_ref(&raw_event))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let event = match ingest_kind {
        EDRIngestKind::AlertOnly => None,
        EDRIngestKind::Generic | EDRIngestKind::EventOnly => handler
            .normalize_event(&envelope.payload)
            .map_err(|_| StatusCode::BAD_REQUEST)?,
    };
    let alert = match ingest_kind {
        EDRIngestKind::EventOnly => None,
        EDRIngestKind::Generic | EDRIngestKind::AlertOnly => handler
            .normalize_alert(&envelope.payload)
            .map_err(|_| StatusCode::BAD_REQUEST)?,
    };
    let normalized = handler
        .normalize_activity(&envelope.payload, &raw_event.id)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if let Some(normalized_event) = normalized.clone() {
        sqlite::insert_normalized_events(&state.db_path, &[normalized_event])
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    if let Some(mut event_row) = event.clone() {
        event_row.raw_event_id = Some(raw_event.id.clone());
        if event_row.external_event_id.is_none() {
            event_row.id = format!("{}:{}", event_row.id, raw_event.id);
        }
        if let Some(normalized_event) = &normalized {
            event_row.normalized_event_id = Some(normalized_event.id.clone());
        }
        sqlite::insert_edr_events(&state.db_path, &[event_row])
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    if let Some(mut alert_row) = alert.clone() {
        alert_row.raw_event_id = Some(raw_event.id.clone());
        if alert_row.external_alert_id.is_none() {
            alert_row.id = format!("{}:{}", alert_row.id, raw_event.id);
        }
        sqlite::insert_edr_alerts(&state.db_path, &[alert_row])
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    Ok(Json(EDRIngestResponse {
        adapter,
        event_normalized: event.is_some(),
        alert_normalized: alert.is_some(),
    }))
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn now_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}
