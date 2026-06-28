BEGIN;

CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT OR IGNORE INTO schema_meta(version) VALUES (1);
INSERT OR IGNORE INTO schema_meta(version) VALUES (2);

CREATE TABLE IF NOT EXISTS raw_events (
    id TEXT PRIMARY KEY,
    source_kind TEXT NOT NULL,
    source_name TEXT NOT NULL,
    event_name TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    host_id TEXT,
    hostname TEXT,
    process_key TEXT,
    severity INTEGER,
    ingest_method TEXT NOT NULL,
    ingest_job_id TEXT,
    payload_ref TEXT,
    payload_json TEXT,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_raw_events_observed_at ON raw_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_raw_events_source_kind ON raw_events(source_kind);
CREATE INDEX IF NOT EXISTS idx_raw_events_host_id ON raw_events(host_id);
CREATE INDEX IF NOT EXISTS idx_raw_events_process_key ON raw_events(process_key);

CREATE TABLE IF NOT EXISTS normalized_events (
    id TEXT PRIMARY KEY,
    raw_event_id TEXT,
    source_kind TEXT NOT NULL,
    vendor TEXT,
    category TEXT NOT NULL,
    action TEXT NOT NULL,
    host_id TEXT,
    agent_id TEXT,
    hostname TEXT,
    process_guid TEXT,
    pid INTEGER,
    ppid INTEGER,
    uid INTEGER,
    gid INTEGER,
    user_name TEXT,
    exe_path TEXT,
    comm TEXT,
    cmdline TEXT,
    cwd TEXT,
    file_path TEXT,
    file_hash TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    protocol TEXT,
    namespace_pid INTEGER,
    namespace_mnt INTEGER,
    namespace_net INTEGER,
    severity INTEGER,
    confidence REAL,
    observed_at INTEGER NOT NULL,
    tags_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_normalized_events_observed_at ON normalized_events(observed_at);
CREATE INDEX IF NOT EXISTS idx_normalized_events_source_kind ON normalized_events(source_kind);
CREATE INDEX IF NOT EXISTS idx_normalized_events_host_id ON normalized_events(host_id);
CREATE INDEX IF NOT EXISTS idx_normalized_events_process_guid ON normalized_events(process_guid);

CREATE TABLE IF NOT EXISTS processes (
    process_key TEXT PRIMARY KEY,
    pid INTEGER NOT NULL,
    ppid INTEGER,
    process_guid TEXT,
    parent_process_key TEXT,
    exe_path TEXT,
    comm TEXT,
    cmdline TEXT,
    cwd TEXT,
    uid INTEGER,
    gid INTEGER,
    loginuid INTEGER,
    session_id INTEGER,
    start_time INTEGER NOT NULL,
    exit_time INTEGER,
    namespace_pid INTEGER,
    namespace_mnt INTEGER,
    namespace_net INTEGER,
    trust_score INTEGER NOT NULL DEFAULT 50,
    trust_reasons_json TEXT,
    flags_json TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid);
CREATE INDEX IF NOT EXISTS idx_processes_ppid ON processes(ppid);
CREATE INDEX IF NOT EXISTS idx_processes_start_time ON processes(start_time);
CREATE INDEX IF NOT EXISTS idx_processes_parent_process_key ON processes(parent_process_key);
CREATE INDEX IF NOT EXISTS idx_processes_process_guid ON processes(process_guid);

CREATE TABLE IF NOT EXISTS process_edges (
    id TEXT PRIMARY KEY,
    parent_process_key TEXT NOT NULL,
    child_process_key TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    raw_event_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_process_edges_parent ON process_edges(parent_process_key);
CREATE INDEX IF NOT EXISTS idx_process_edges_child ON process_edges(child_process_key);

CREATE TABLE IF NOT EXISTS file_events (
    id TEXT PRIMARY KEY,
    raw_event_id TEXT,
    normalized_event_id TEXT,
    process_key TEXT,
    pid INTEGER,
    action TEXT NOT NULL,
    file_path TEXT,
    file_hash TEXT,
    bytes_written INTEGER,
    severity INTEGER,
    observed_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_file_events_process_key ON file_events(process_key);
CREATE INDEX IF NOT EXISTS idx_file_events_file_path ON file_events(file_path);
CREATE INDEX IF NOT EXISTS idx_file_events_observed_at ON file_events(observed_at);

CREATE TABLE IF NOT EXISTS network_events (
    id TEXT PRIMARY KEY,
    raw_event_id TEXT,
    normalized_event_id TEXT,
    process_key TEXT,
    pid INTEGER,
    action TEXT NOT NULL,
    protocol TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    dns_query TEXT,
    bytes_sent INTEGER,
    bytes_recv INTEGER,
    severity INTEGER,
    observed_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_network_events_process_key ON network_events(process_key);
CREATE INDEX IF NOT EXISTS idx_network_events_dst_ip ON network_events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_network_events_dst_port ON network_events(dst_port);
CREATE INDEX IF NOT EXISTS idx_network_events_observed_at ON network_events(observed_at);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    incident_key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    summary TEXT,
    severity INTEGER NOT NULL,
    confidence REAL NOT NULL,
    status TEXT NOT NULL,
    root_pid INTEGER,
    root_process_guid TEXT,
    host_id TEXT,
    hostname TEXT,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    source_count INTEGER NOT NULL DEFAULT 0,
    event_count INTEGER NOT NULL DEFAULT 0,
    tactic_tags_json TEXT,
    evidence_json TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_host_id ON incidents(host_id);
CREATE INDEX IF NOT EXISTS idx_incidents_first_seen_at ON incidents(first_seen_at);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);

CREATE TABLE IF NOT EXISTS ioc_hits (
    id TEXT PRIMARY KEY,
    incident_id TEXT,
    process_key TEXT,
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity INTEGER,
    observed_at INTEGER NOT NULL,
    raw_event_id TEXT,
    normalized_event_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_ioc_hits_incident_id ON ioc_hits(incident_id);
CREATE INDEX IF NOT EXISTS idx_ioc_hits_process_key ON ioc_hits(process_key);

CREATE TABLE IF NOT EXISTS ring0_findings (
    id TEXT PRIMARY KEY,
    finding_type TEXT NOT NULL,
    detector TEXT NOT NULL,
    severity INTEGER NOT NULL,
    trust_level TEXT NOT NULL,
    host_id TEXT,
    hostname TEXT,
    pid INTEGER,
    object_ref TEXT,
    summary TEXT NOT NULL,
    detail_json TEXT,
    observed_at INTEGER NOT NULL,
    raw_event_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_ring0_findings_observed_at ON ring0_findings(observed_at);
CREATE INDEX IF NOT EXISTS idx_ring0_findings_finding_type ON ring0_findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_ring0_findings_trust_level ON ring0_findings(trust_level);

CREATE TABLE IF NOT EXISTS edr_events (
    id TEXT PRIMARY KEY,
    vendor TEXT NOT NULL,
    adapter_name TEXT NOT NULL,
    external_event_id TEXT,
    host_id TEXT,
    agent_id TEXT,
    hostname TEXT,
    process_guid TEXT,
    pid INTEGER,
    ppid INTEGER,
    exe_path TEXT,
    cmdline TEXT,
    file_path TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    severity INTEGER,
    event_name TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    raw_event_id TEXT,
    normalized_event_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_edr_events_vendor ON edr_events(vendor);
CREATE INDEX IF NOT EXISTS idx_edr_events_host_id ON edr_events(host_id);
CREATE INDEX IF NOT EXISTS idx_edr_events_process_guid ON edr_events(process_guid);
CREATE INDEX IF NOT EXISTS idx_edr_events_observed_at ON edr_events(observed_at);

CREATE TABLE IF NOT EXISTS edr_alerts (
    id TEXT PRIMARY KEY,
    vendor TEXT NOT NULL,
    adapter_name TEXT NOT NULL,
    external_alert_id TEXT,
    host_id TEXT,
    hostname TEXT,
    alert_name TEXT NOT NULL,
    severity INTEGER NOT NULL,
    status TEXT NOT NULL,
    process_guid TEXT,
    pid INTEGER,
    tactic_tags_json TEXT,
    summary TEXT,
    observed_at INTEGER NOT NULL,
    raw_event_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_edr_alerts_vendor ON edr_alerts(vendor);
CREATE INDEX IF NOT EXISTS idx_edr_alerts_host_id ON edr_alerts(host_id);
CREATE INDEX IF NOT EXISTS idx_edr_alerts_observed_at ON edr_alerts(observed_at);

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    incident_id TEXT,
    report_type TEXT NOT NULL,
    title TEXT NOT NULL,
    output_path TEXT,
    summary TEXT,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_incident_id ON reports(incident_id);

CREATE TABLE IF NOT EXISTS integration_jobs (
    id TEXT PRIMARY KEY,
    adapter_name TEXT NOT NULL,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    cursor_value TEXT,
    summary TEXT,
    error_text TEXT
);

CREATE INDEX IF NOT EXISTS idx_integration_jobs_adapter_name ON integration_jobs(adapter_name);
CREATE INDEX IF NOT EXISTS idx_integration_jobs_status ON integration_jobs(status);

COMMIT;
