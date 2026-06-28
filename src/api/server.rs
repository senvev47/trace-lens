use anyhow::Result;
use axum::{
    Json, Router,
    extract::Request,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Html,
    routing::get,
};
use serde::Serialize;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;

use crate::api::edr_ingest::{
    import_edr_payloads, ingest_edr_alert_webhook, ingest_edr_event_webhook, ingest_edr_webhook,
};
use crate::app::AppState;
use crate::connectors::edr::default_registry;
use crate::engine::incident::aggregate_incident_for_pid;
use crate::engine::proc_tree::{
    FilePropagationChain, ProcessTree, dns_events_for_pid, file_events_for_path,
    file_events_for_pid, file_propagation_for_path, network_events_for_pid,
    network_events_for_target,
};
use crate::engine::trust::{assess_host_trust, assess_process_trust};
use crate::storage::sqlite;

const INDEX_HTML: &str = include_str!("../../web/templates/index.html");
const INCIDENT_HTML: &str = include_str!("../../web/templates/incident.html");
const RING0_HTML: &str = include_str!("../../web/templates/ring0.html");
const EDR_HTML: &str = include_str!("../../web/templates/edr.html");
const NET_HTML: &str = include_str!("../../web/templates/net.html");
const FILE_HTML: &str = include_str!("../../web/templates/file.html");

pub async fn run(listen: String, state: AppState) -> Result<()> {
    let app = router(state);
    let listener = TcpListener::bind(&listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/status", get(status))
        .route("/events", get(events))
        .route("/incidents", get(incidents))
        .route("/proc/{pid}", get(proc_detail))
        .route("/net/{target}", get(net_detail))
        .route("/file", get(file_detail))
        .route("/file-chain", get(file_chain_detail))
        .route("/incidents/{pid}", get(incident_detail))
        .route("/ring0", get(ring0_summary))
        .route("/ring0/findings", get(ring0_findings))
        .route("/edr/events", get(edr_events))
        .route("/edr/alerts", get(edr_alerts))
        .route("/integrations/edr", get(edr_integrations))
        .route(
            "/ingest/edr/{adapter}",
            axum::routing::post(ingest_edr_webhook),
        )
        .route(
            "/ingest/edr/{adapter}/events",
            axum::routing::post(ingest_edr_event_webhook),
        )
        .route(
            "/ingest/edr/{adapter}/alerts",
            axum::routing::post(ingest_edr_alert_webhook),
        )
        .route(
            "/import/edr/{adapter}",
            axum::routing::post(import_edr_payloads),
        )
        .route_layer(middleware::from_fn_with_state(
            ApiAuthState::from_env(),
            api_token_auth,
        ));

    Router::new()
        .route("/", get(index_page))
        .route("/incident/{pid}", get(incident_page))
        .route("/ring0", get(ring0_page))
        .route("/edr", get(edr_page))
        .route("/net", get(net_page))
        .route("/file", get(file_page))
        .route("/healthz", get(healthz))
        .nest("/api/v1", api)
        .nest_service("/static", ServeDir::new("web/static"))
        .with_state(state)
}

#[derive(Clone, Debug)]
struct ApiAuthState {
    token: Option<String>,
}

impl ApiAuthState {
    fn from_env() -> Self {
        let token = std::env::var("TRACE_LENS_API_TOKEN")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        Self { token }
    }
}

async fn api_token_auth(
    State(auth): State<ApiAuthState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let Some(expected_token) = auth.token.as_deref() else {
        return Ok(next.run(request).await);
    };

    if has_valid_api_token(&headers, expected_token) {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn has_valid_api_token(headers: &HeaderMap, expected_token: &str) -> bool {
    headers
        .get("x-trace-lens-token")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|token| token == expected_token)
        || headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|token| token == expected_token)
}

async fn index_page() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn incident_page(Path(_pid): Path<i64>) -> Html<&'static str> {
    Html(INCIDENT_HTML)
}

async fn ring0_page() -> Html<&'static str> {
    Html(RING0_HTML)
}

async fn edr_page() -> Html<&'static str> {
    Html(EDR_HTML)
}

async fn net_page() -> Html<&'static str> {
    Html(NET_HTML)
}

async fn file_page() -> Html<&'static str> {
    Html(FILE_HTML)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn status(State(state): State<AppState>) -> Result<Json<ApiStatus>, axum::http::StatusCode> {
    let db_status = sqlite::database_status(&state.db_path)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let raw_events = sqlite::all_raw_events(&state.db_path)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let derived_processes = derived_process_count(&raw_events);
    let derived_incident_candidates = derived_incident_candidate_count(&raw_events);

    Ok(Json(ApiStatus {
        service: "trace-lens",
        database_path: state.db_path.display().to_string(),
        database_exists: db_status.database_exists,
        schema_version: db_status.schema_version,
        raw_events: db_status.raw_events,
        processes: db_status.processes,
        incidents: db_status.incidents,
        derived_processes,
        derived_incident_candidates,
        status_note: "processes/incidents are persisted table counts; derived_* values are computed from raw_events",
        ring0_findings: db_status.ring0_findings,
    }))
}

fn derived_process_count(raw_events: &[crate::model::event::RawEvent]) -> usize {
    raw_events
        .iter()
        .filter(|event| event.source_kind == "tracee" && event.event_name == "sched_process_exec")
        .filter_map(|event| event.process_key.as_deref())
        .filter_map(|process_key| process_key.split(':').nth(1))
        .filter_map(|pid| pid.parse::<i64>().ok())
        .collect::<std::collections::HashSet<_>>()
        .len()
}

fn derived_incident_candidate_count(raw_events: &[crate::model::event::RawEvent]) -> usize {
    raw_events
        .iter()
        .filter(|event| event.source_kind == "tracee" && event.event_name == "sched_process_exec")
        .filter(|event| event.severity.unwrap_or_default() >= 5)
        .filter_map(|event| event.process_key.as_deref())
        .filter_map(|process_key| process_key.split(':').nth(1))
        .filter_map(|pid| pid.parse::<i64>().ok())
        .collect::<std::collections::HashSet<_>>()
        .len()
}

async fn events(
    State(state): State<AppState>,
) -> Result<Json<Vec<ApiEvent>>, axum::http::StatusCode> {
    let rows = sqlite::latest_raw_events(&state.db_path, 20)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(
        rows.into_iter()
            .map(|event| ApiEvent {
                id: event.id,
                event_name: event.event_name,
                source_kind: event.source_kind,
                observed_at: event.observed_at,
                process_key: event.process_key,
                severity: event.severity,
            })
            .collect(),
    ))
}

async fn incidents(
    State(state): State<AppState>,
) -> Result<Json<Vec<ApiIncidentListItem>>, axum::http::StatusCode> {
    let raw_events = sqlite::all_raw_events(&state.db_path)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let ring0_findings = sqlite::latest_ring0_findings(&state.db_path, 32)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let tree = ProcessTree::build(&raw_events)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut exec_pids = Vec::new();
    for event in &raw_events {
        if event.source_kind == "tracee"
            && event.event_name == "sched_process_exec"
            && let Some(process_key) = &event.process_key
            && let Some(pid) = process_key
                .split(':')
                .nth(1)
                .and_then(|value| value.parse::<i64>().ok())
        {
            exec_pids.push(pid);
        }
    }

    exec_pids.sort_unstable();
    exec_pids.dedup();

    let mut items = Vec::new();
    for pid in exec_pids {
        if tree.get_by_pid(pid).is_none() {
            continue;
        }

        if let Ok(bundle) =
            aggregate_incident_for_pid(pid, &state.db_path, &raw_events, &ring0_findings)
        {
            if bundle.incident.severity < 5
                && bundle.ioc_hits.is_empty()
                && bundle.edr_evidence.is_empty()
            {
                continue;
            }

            items.push(ApiIncidentListItem {
                incident_id: bundle.incident.id,
                pid,
                title: bundle.incident.title,
                severity: bundle.incident.severity,
                confidence: bundle.incident.confidence,
                status: bundle.incident.status,
                summary: bundle.incident.summary,
                root_exe_path: bundle.root_process.exe_path,
                host_trust_level: bundle.host_trust.level,
                edr_evidence_count: bundle.edr_evidence.len(),
                observed_at: bundle.incident.first_seen_at,
            });
        }
    }

    items.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.confidence.total_cmp(&a.confidence))
            .then_with(|| b.observed_at.cmp(&a.observed_at))
    });
    items.truncate(20);
    Ok(Json(items))
}

async fn proc_detail(
    State(state): State<AppState>,
    Path(pid): Path<i64>,
) -> Result<Json<ApiProcDetail>, axum::http::StatusCode> {
    let raw_events = sqlite::all_raw_events(&state.db_path)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let ring0_findings = sqlite::latest_ring0_findings(&state.db_path, 32)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let tree = ProcessTree::build(&raw_events)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let process = tree
        .get_by_pid(pid)
        .cloned()
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;
    let ancestry = tree.ancestry_by_pid(pid, 16);
    let descendants = tree.descendants_by_pid(pid, 32);
    let file_events = file_events_for_pid(&raw_events, pid);
    let network_events = network_events_for_pid(&raw_events, pid);
    let dns_events = dns_events_for_pid(&raw_events, pid);
    let process_trust = assess_process_trust(&process, &file_events, &network_events, &dns_events);
    let host_trust = assess_host_trust(&ring0_findings);

    Ok(Json(ApiProcDetail {
        process: ApiProcessNode::from(process),
        ancestry: ancestry.into_iter().map(ApiProcessNode::from).collect(),
        descendants: descendants.into_iter().map(ApiProcessNode::from).collect(),
        file_events: file_events
            .into_iter()
            .map(|event| ApiFileEvent {
                event_name: event.event_name,
                file_path: event.file_path,
                flags: event.flags,
                sensitive: event.sensitive,
                observed_at: event.observed_at,
            })
            .collect(),
        network_events: network_events
            .into_iter()
            .map(|event| ApiNetworkEvent {
                event_name: event.event_name,
                remote_addr: event.remote_addr,
                remote_port: event.remote_port,
                external: event.external,
                lateral_movement_hint: event.lateral_movement_hint,
                observed_at: event.observed_at,
            })
            .collect(),
        dns_events: dns_events
            .into_iter()
            .map(|event| ApiDnsEvent {
                event_name: event.event_name,
                query: event.query,
                query_type: event.query_type,
                query_class: event.query_class,
                entropy: event.entropy,
                high_entropy: event.high_entropy,
                observed_at: event.observed_at,
            })
            .collect(),
        process_trust_score: process_trust.score,
        process_trust_reasons: process_trust.reasons,
        host_trust_level: host_trust.level,
        host_trust_reasons: host_trust.reasons,
    }))
}

async fn net_detail(
    State(state): State<AppState>,
    Path(target): Path<String>,
) -> Result<Json<Vec<ApiNetworkLookupItem>>, axum::http::StatusCode> {
    let raw_events = sqlite::all_raw_events(&state.db_path)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let items = network_events_for_target(&raw_events, &target)
        .into_iter()
        .map(|event| ApiNetworkLookupItem {
            pid: event.pid,
            event_name: event.event_name,
            remote_addr: event.remote_addr,
            remote_port: event.remote_port,
            external: event.external,
            lateral_movement_hint: event.lateral_movement_hint,
            observed_at: event.observed_at,
        })
        .collect();
    Ok(Json(items))
}

async fn file_detail(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Vec<ApiFileLookupItem>>, axum::http::StatusCode> {
    let Some(path) = params.get("path") else {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    };

    let raw_events = sqlite::all_raw_events(&state.db_path)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let items = file_events_for_path(&raw_events, path)
        .into_iter()
        .map(|event| ApiFileLookupItem {
            pid: event.pid,
            event_name: event.event_name,
            file_path: event.file_path,
            flags: event.flags,
            sensitive: event.sensitive,
            observed_at: event.observed_at,
        })
        .collect();
    Ok(Json(items))
}

async fn file_chain_detail(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<FilePropagationChain>, axum::http::StatusCode> {
    let Some(path) = params.get("path") else {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    };

    let raw_events = sqlite::all_raw_events(&state.db_path)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(file_propagation_for_path(&raw_events, path)))
}

async fn incident_detail(
    State(state): State<AppState>,
    Path(pid): Path<i64>,
) -> Result<Json<ApiIncidentDetail>, axum::http::StatusCode> {
    let raw_events = sqlite::all_raw_events(&state.db_path)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let ring0_findings = sqlite::latest_ring0_findings(&state.db_path, 32)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let bundle = aggregate_incident_for_pid(pid, &state.db_path, &raw_events, &ring0_findings)
        .map_err(|_| axum::http::StatusCode::NOT_FOUND)?;

    Ok(Json(ApiIncidentDetail {
        incident_id: bundle.incident.id,
        title: bundle.incident.title,
        severity: bundle.incident.severity,
        confidence: bundle.incident.confidence,
        status: bundle.incident.status,
        summary: bundle.incident.summary,
        root_process: ApiProcessNode::from(bundle.root_process),
        tactics: bundle.incident.tactic_tags_json,
        process_trust_score: bundle.process_trust.score,
        process_trust_reasons: bundle.process_trust.reasons,
        host_trust_level: bundle.host_trust.level,
        host_trust_reasons: bundle.host_trust.reasons,
        ancestry: bundle
            .ancestry
            .into_iter()
            .map(ApiProcessNode::from)
            .collect(),
        descendants: bundle
            .descendants
            .into_iter()
            .map(ApiProcessNode::from)
            .collect(),
        file_events: bundle
            .file_events
            .into_iter()
            .map(|event| ApiFileEvent {
                event_name: event.event_name,
                file_path: event.file_path,
                flags: event.flags,
                sensitive: event.sensitive,
                observed_at: event.observed_at,
            })
            .collect(),
        network_events: bundle
            .network_events
            .into_iter()
            .map(|event| ApiNetworkEvent {
                event_name: event.event_name,
                remote_addr: event.remote_addr,
                remote_port: event.remote_port,
                external: event.external,
                lateral_movement_hint: event.lateral_movement_hint,
                observed_at: event.observed_at,
            })
            .collect(),
        dns_events: bundle
            .dns_events
            .into_iter()
            .map(|event| ApiDnsEvent {
                event_name: event.event_name,
                query: event.query,
                query_type: event.query_type,
                query_class: event.query_class,
                entropy: event.entropy,
                high_entropy: event.high_entropy,
                observed_at: event.observed_at,
            })
            .collect(),
        edr_evidence: bundle
            .edr_evidence
            .into_iter()
            .map(|evidence| ApiIncidentEDREvidence {
                event_id: evidence.event_id,
                alert_id: evidence.alert_id,
                vendor: evidence.vendor,
                adapter_name: evidence.adapter_name,
                event_name: evidence.event_name,
                alert_name: evidence.alert_name,
                pid: evidence.pid,
                process_guid: evidence.process_guid,
                severity: evidence.severity,
                observed_at: evidence.observed_at,
                summary: evidence.summary,
            })
            .collect(),
        ring0_findings: bundle
            .ring0_findings
            .into_iter()
            .map(|finding| ApiRing0Finding {
                id: finding.id,
                finding_type: finding.finding_type,
                detector: finding.detector,
                trust_level: finding.trust_level,
                summary: finding.summary,
                observed_at: finding.observed_at,
            })
            .collect(),
        summary_lines: bundle.summary_lines,
        process_graph_mermaid: bundle.process_graph_mermaid,
    }))
}

async fn ring0_findings(
    State(state): State<AppState>,
) -> Result<Json<Vec<ApiRing0Finding>>, axum::http::StatusCode> {
    let rows = sqlite::latest_ring0_findings(&state.db_path, 20)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(
        rows.into_iter()
            .map(|finding| ApiRing0Finding {
                id: finding.id,
                finding_type: finding.finding_type,
                detector: finding.detector,
                trust_level: finding.trust_level,
                summary: finding.summary,
                observed_at: finding.observed_at,
            })
            .collect(),
    ))
}

async fn ring0_summary(
    State(state): State<AppState>,
) -> Result<Json<ApiRing0Summary>, axum::http::StatusCode> {
    let rows = sqlite::latest_ring0_findings(&state.db_path, 20)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let trust = assess_host_trust(&rows);
    Ok(Json(ApiRing0Summary {
        host_trust_level: trust.level,
        host_trust_reasons: trust.reasons,
        findings: rows
            .into_iter()
            .map(|finding| ApiRing0Finding {
                id: finding.id,
                finding_type: finding.finding_type,
                detector: finding.detector,
                trust_level: finding.trust_level,
                summary: finding.summary,
                observed_at: finding.observed_at,
            })
            .collect(),
    }))
}

async fn edr_events(
    State(state): State<AppState>,
) -> Result<Json<Vec<ApiEDREvent>>, axum::http::StatusCode> {
    let rows = sqlite::latest_edr_events(&state.db_path, 20)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(
        rows.into_iter()
            .map(|event| ApiEDREvent {
                id: event.id,
                vendor: event.vendor,
                adapter_name: event.adapter_name,
                event_name: event.event_name,
                pid: event.pid,
                process_guid: event.process_guid,
                severity: event.severity,
                observed_at: event.observed_at,
                raw_event_id: event.raw_event_id,
                normalized_event_id: event.normalized_event_id,
            })
            .collect(),
    ))
}

async fn edr_alerts(
    State(state): State<AppState>,
) -> Result<Json<Vec<ApiEDRAlert>>, axum::http::StatusCode> {
    let rows = sqlite::latest_edr_alerts(&state.db_path, 20)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(
        rows.into_iter()
            .map(|alert| ApiEDRAlert {
                id: alert.id,
                vendor: alert.vendor,
                adapter_name: alert.adapter_name,
                alert_name: alert.alert_name,
                pid: alert.pid,
                severity: alert.severity,
                status: alert.status,
                observed_at: alert.observed_at,
                raw_event_id: alert.raw_event_id,
            })
            .collect(),
    ))
}

async fn edr_integrations() -> Json<Vec<ApiEDRIntegration>> {
    let registry = default_registry();
    let integrations = registry
        .into_keys()
        .map(|adapter| ApiEDRIntegration {
            adapter_name: adapter.clone(),
            webhook_path: format!("/api/v1/ingest/edr/{adapter}"),
            event_webhook_path: format!("/api/v1/ingest/edr/{adapter}/events"),
            alert_webhook_path: format!("/api/v1/ingest/edr/{adapter}/alerts"),
            health: "ready".to_string(),
        })
        .collect();

    Json(integrations)
}

#[derive(Debug, Serialize)]
struct ApiStatus {
    service: &'static str,
    database_path: String,
    database_exists: bool,
    schema_version: i64,
    raw_events: i64,
    processes: i64,
    incidents: i64,
    derived_processes: usize,
    derived_incident_candidates: usize,
    status_note: &'static str,
    ring0_findings: i64,
}

#[derive(Debug, Serialize)]
struct ApiEvent {
    id: String,
    event_name: String,
    source_kind: String,
    observed_at: i64,
    process_key: Option<String>,
    severity: Option<i32>,
}

#[derive(Debug, Serialize)]
struct ApiRing0Finding {
    id: String,
    finding_type: String,
    detector: String,
    trust_level: String,
    summary: String,
    observed_at: i64,
}

#[derive(Debug, Serialize)]
struct ApiProcessNode {
    process_key: String,
    pid: i64,
    ppid: Option<i64>,
    process_guid: Option<String>,
    exe_path: Option<String>,
    comm: Option<String>,
    cmdline: Option<String>,
    start_time: i64,
    exit_time: Option<i64>,
}

impl From<crate::model::process::ProcessNode> for ApiProcessNode {
    fn from(value: crate::model::process::ProcessNode) -> Self {
        Self {
            process_key: value.process_key,
            pid: value.pid,
            ppid: value.ppid,
            process_guid: value.process_guid,
            exe_path: value.exe_path,
            comm: value.comm,
            cmdline: value.cmdline,
            start_time: value.start_time,
            exit_time: value.exit_time,
        }
    }
}

#[derive(Debug, Serialize)]
struct ApiFileEvent {
    event_name: String,
    file_path: String,
    flags: Option<String>,
    sensitive: bool,
    observed_at: i64,
}

#[derive(Debug, Serialize)]
struct ApiNetworkEvent {
    event_name: String,
    remote_addr: Option<String>,
    remote_port: Option<i64>,
    external: bool,
    lateral_movement_hint: bool,
    observed_at: i64,
}

#[derive(Debug, Serialize)]
struct ApiDnsEvent {
    event_name: String,
    query: String,
    query_type: Option<String>,
    query_class: Option<String>,
    entropy: f64,
    high_entropy: bool,
    observed_at: i64,
}

#[derive(Debug, Serialize)]
struct ApiNetworkLookupItem {
    pid: i64,
    event_name: String,
    remote_addr: Option<String>,
    remote_port: Option<i64>,
    external: bool,
    lateral_movement_hint: bool,
    observed_at: i64,
}

#[derive(Debug, Serialize)]
struct ApiFileLookupItem {
    pid: i64,
    event_name: String,
    file_path: String,
    flags: Option<String>,
    sensitive: bool,
    observed_at: i64,
}

#[derive(Debug, Serialize)]
struct ApiProcDetail {
    process: ApiProcessNode,
    ancestry: Vec<ApiProcessNode>,
    descendants: Vec<ApiProcessNode>,
    file_events: Vec<ApiFileEvent>,
    network_events: Vec<ApiNetworkEvent>,
    dns_events: Vec<ApiDnsEvent>,
    process_trust_score: i32,
    process_trust_reasons: Vec<String>,
    host_trust_level: String,
    host_trust_reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ApiIncidentEDREvidence {
    event_id: String,
    alert_id: Option<String>,
    vendor: String,
    adapter_name: String,
    event_name: String,
    alert_name: Option<String>,
    pid: Option<i64>,
    process_guid: Option<String>,
    severity: Option<i32>,
    observed_at: i64,
    summary: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApiIncidentDetail {
    incident_id: String,
    title: String,
    severity: i32,
    confidence: f32,
    status: String,
    summary: String,
    root_process: ApiProcessNode,
    tactics: Option<String>,
    process_trust_score: i32,
    process_trust_reasons: Vec<String>,
    host_trust_level: String,
    host_trust_reasons: Vec<String>,
    ancestry: Vec<ApiProcessNode>,
    descendants: Vec<ApiProcessNode>,
    file_events: Vec<ApiFileEvent>,
    network_events: Vec<ApiNetworkEvent>,
    dns_events: Vec<ApiDnsEvent>,
    edr_evidence: Vec<ApiIncidentEDREvidence>,
    ring0_findings: Vec<ApiRing0Finding>,
    summary_lines: Vec<String>,
    process_graph_mermaid: String,
}

#[derive(Debug, Serialize)]
struct ApiIncidentListItem {
    incident_id: String,
    pid: i64,
    title: String,
    severity: i32,
    confidence: f32,
    status: String,
    summary: String,
    root_exe_path: Option<String>,
    host_trust_level: String,
    edr_evidence_count: usize,
    observed_at: i64,
}

#[derive(Debug, Serialize)]
struct ApiRing0Summary {
    host_trust_level: String,
    host_trust_reasons: Vec<String>,
    findings: Vec<ApiRing0Finding>,
}

#[derive(Debug, Serialize)]
struct ApiEDREvent {
    id: String,
    vendor: String,
    adapter_name: String,
    event_name: String,
    pid: Option<i64>,
    process_guid: Option<String>,
    severity: Option<i32>,
    observed_at: i64,
    raw_event_id: Option<String>,
    normalized_event_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApiEDRAlert {
    id: String,
    vendor: String,
    adapter_name: String,
    alert_name: String,
    pid: Option<i64>,
    severity: i32,
    status: String,
    observed_at: i64,
    raw_event_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApiEDRIntegration {
    adapter_name: String,
    webhook_path: String,
    event_webhook_path: String,
    alert_webhook_path: String,
    health: String,
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::has_valid_api_token;

    #[test]
    fn api_token_auth_accepts_bearer_or_trace_lens_header() {
        let mut bearer = HeaderMap::new();
        bearer.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-token"),
        );
        assert!(has_valid_api_token(&bearer, "test-token"));

        let mut custom = HeaderMap::new();
        custom.insert("x-trace-lens-token", HeaderValue::from_static("test-token"));
        assert!(has_valid_api_token(&custom, "test-token"));
    }

    #[test]
    fn api_token_auth_rejects_missing_or_wrong_token() {
        assert!(!has_valid_api_token(&HeaderMap::new(), "test-token"));

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong-token"),
        );
        assert!(!has_valid_api_token(&headers, "test-token"));
    }
}
