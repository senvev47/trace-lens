use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use crate::model::edr::{EDRAlert, EDREvent};
use crate::model::event::NormalizedEvent;
use crate::model::event::RawEvent;
use crate::model::ring0::Ring0Finding;

const COUNTABLE_TABLES: &[&str] = &["raw_events", "processes", "incidents", "ring0_findings"];

const SCHEMA_SQL: &str = include_str!("../../db/schema.sql");

#[derive(Debug, Clone)]
pub struct DatabaseStatus {
    pub database_exists: bool,
    pub schema_version: i64,
    pub raw_events: i64,
    pub processes: i64,
    pub incidents: i64,
    pub ring0_findings: i64,
}

pub fn init_database(path: &Path) -> Result<()> {
    ensure_parent_dir(path)?;

    let conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database: {}", path.display()))?;

    conn.execute_batch(SCHEMA_SQL)
        .with_context(|| format!("failed to apply schema: {}", path.display()))?;

    Ok(())
}

pub fn database_status(path: &Path) -> Result<DatabaseStatus> {
    if !path.exists() {
        return Ok(DatabaseStatus {
            database_exists: false,
            schema_version: 0,
            raw_events: 0,
            processes: 0,
            incidents: 0,
            ring0_findings: 0,
        });
    }

    let conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database: {}", path.display()))?;

    let schema_version = conn
        .query_row(
            "SELECT version FROM schema_meta ORDER BY version DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0);

    Ok(DatabaseStatus {
        database_exists: true,
        schema_version,
        raw_events: count_rows(&conn, "raw_events")?,
        processes: count_rows(&conn, "processes")?,
        incidents: count_rows(&conn, "incidents")?,
        ring0_findings: count_rows(&conn, "ring0_findings")?,
    })
}

pub fn insert_raw_events(path: &Path, events: &[RawEvent]) -> Result<usize> {
    ensure_parent_dir(path)?;

    let mut conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database: {}", path.display()))?;
    let tx = conn.transaction()?;

    {
        let mut stmt = tx.prepare(
            "INSERT OR REPLACE INTO raw_events (
                id, source_kind, source_name, event_name, observed_at,
                host_id, hostname, process_key, severity, ingest_method,
                ingest_job_id, payload_ref, payload_json, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        )?;

        for event in events {
            stmt.execute((
                &event.id,
                &event.source_kind,
                &event.source_name,
                &event.event_name,
                event.observed_at,
                &event.host_id,
                &event.hostname,
                &event.process_key,
                &event.severity,
                &event.ingest_method,
                &event.ingest_job_id,
                &event.payload_ref,
                &event.payload_json,
                event.created_at,
            ))?;
        }
    }

    tx.commit()?;
    Ok(events.len())
}

pub fn insert_ring0_findings(path: &Path, findings: &[Ring0Finding]) -> Result<usize> {
    ensure_parent_dir(path)?;

    let mut conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database: {}", path.display()))?;
    let tx = conn.transaction()?;

    {
        let mut delete_stmt = tx.prepare(
            "DELETE FROM ring0_findings
             WHERE finding_type = ?1 AND detector = ?2 AND summary = ?3",
        )?;
        let mut stmt = tx.prepare(
            "INSERT OR REPLACE INTO ring0_findings (
                id, finding_type, detector, severity, trust_level,
                host_id, hostname, pid, object_ref, summary,
                detail_json, observed_at, raw_event_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL)",
        )?;

        for finding in findings {
            delete_stmt.execute((&finding.finding_type, &finding.detector, &finding.summary))?;
            stmt.execute((
                &finding.id,
                &finding.finding_type,
                &finding.detector,
                finding.severity,
                &finding.trust_level,
                &finding.host_id,
                &finding.hostname,
                &finding.pid,
                &finding.object_ref,
                &finding.summary,
                &finding.detail_json,
                finding.observed_at,
            ))?;
        }
    }

    tx.commit()?;
    Ok(findings.len())
}

pub fn latest_raw_events(path: &Path, limit: usize) -> Result<Vec<RawEvent>> {
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database: {}", path.display()))?;
    let mut stmt = conn.prepare(
        "SELECT
            id, source_kind, source_name, event_name, observed_at,
            host_id, hostname, process_key, severity, payload_ref,
            payload_json, ingest_method, ingest_job_id, created_at
         FROM raw_events
         ORDER BY observed_at DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map([limit as i64], |row| {
        Ok(RawEvent {
            id: row.get(0)?,
            source_kind: row.get(1)?,
            source_name: row.get(2)?,
            event_name: row.get(3)?,
            observed_at: row.get(4)?,
            host_id: row.get(5)?,
            hostname: row.get(6)?,
            process_key: row.get(7)?,
            severity: row.get(8)?,
            payload_ref: row.get(9)?,
            payload_json: row.get(10)?,
            ingest_method: row.get(11)?,
            ingest_job_id: row.get(12)?,
            created_at: row.get(13)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub fn all_raw_events(path: &Path) -> Result<Vec<RawEvent>> {
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database: {}", path.display()))?;
    let mut stmt = conn.prepare(
        "SELECT
            id, source_kind, source_name, event_name, observed_at,
            host_id, hostname, process_key, severity, payload_ref,
            payload_json, ingest_method, ingest_job_id, created_at
         FROM raw_events
         ORDER BY observed_at ASC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(RawEvent {
            id: row.get(0)?,
            source_kind: row.get(1)?,
            source_name: row.get(2)?,
            event_name: row.get(3)?,
            observed_at: row.get(4)?,
            host_id: row.get(5)?,
            hostname: row.get(6)?,
            process_key: row.get(7)?,
            severity: row.get(8)?,
            payload_ref: row.get(9)?,
            payload_json: row.get(10)?,
            ingest_method: row.get(11)?,
            ingest_job_id: row.get(12)?,
            created_at: row.get(13)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub fn latest_ring0_findings(path: &Path, limit: usize) -> Result<Vec<Ring0Finding>> {
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database: {}", path.display()))?;
    let mut stmt = conn.prepare(
        "SELECT
            id, finding_type, detector, severity, trust_level,
            host_id, hostname, pid, object_ref, summary,
            detail_json, observed_at
         FROM ring0_findings
         ORDER BY observed_at DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map([limit as i64], |row| {
        Ok(Ring0Finding {
            id: row.get(0)?,
            finding_type: row.get(1)?,
            detector: row.get(2)?,
            severity: row.get(3)?,
            trust_level: row.get(4)?,
            host_id: row.get(5)?,
            hostname: row.get(6)?,
            pid: row.get(7)?,
            object_ref: row.get(8)?,
            summary: row.get(9)?,
            detail_json: row.get(10)?,
            observed_at: row.get(11)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub fn insert_edr_events(path: &Path, events: &[EDREvent]) -> Result<usize> {
    ensure_parent_dir(path)?;

    let mut conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database: {}", path.display()))?;
    let tx = conn.transaction()?;

    {
        let mut stmt = tx.prepare(
            "INSERT OR REPLACE INTO edr_events (
                id, vendor, adapter_name, external_event_id, host_id,
                agent_id, hostname, process_guid, pid, ppid,
                exe_path, cmdline, file_path, src_ip, dst_ip,
                dst_port, severity, event_name, observed_at, raw_event_id, normalized_event_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        )?;

        for event in events {
            stmt.execute(params![
                &event.id,
                &event.vendor,
                &event.adapter_name,
                &event.external_event_id,
                &event.host_id,
                &event.agent_id,
                &event.hostname,
                &event.process_guid,
                &event.pid,
                &event.ppid,
                &event.exe_path,
                &event.cmdline,
                &event.file_path,
                &event.src_ip,
                &event.dst_ip,
                &event.dst_port,
                &event.severity,
                &event.event_name,
                event.observed_at,
                &event.raw_event_id,
                &event.normalized_event_id,
            ])?;
        }
    }

    tx.commit()?;
    Ok(events.len())
}

pub fn insert_edr_alerts(path: &Path, alerts: &[EDRAlert]) -> Result<usize> {
    ensure_parent_dir(path)?;

    let mut conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database: {}", path.display()))?;
    let tx = conn.transaction()?;

    {
        let mut stmt = tx.prepare(
            "INSERT OR REPLACE INTO edr_alerts (
                id, vendor, adapter_name, external_alert_id, host_id,
                hostname, alert_name, severity, status, process_guid,
                pid, tactic_tags_json, summary, observed_at, raw_event_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        )?;

        for alert in alerts {
            stmt.execute((
                &alert.id,
                &alert.vendor,
                &alert.adapter_name,
                &alert.external_alert_id,
                &alert.host_id,
                &alert.hostname,
                &alert.alert_name,
                alert.severity,
                &alert.status,
                &alert.process_guid,
                &alert.pid,
                &alert.tactic_tags_json,
                &alert.summary,
                alert.observed_at,
                &alert.raw_event_id,
            ))?;
        }
    }

    tx.commit()?;
    Ok(alerts.len())
}

pub fn insert_normalized_events(path: &Path, events: &[NormalizedEvent]) -> Result<usize> {
    ensure_parent_dir(path)?;

    let mut conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database: {}", path.display()))?;
    let tx = conn.transaction()?;

    {
        let mut stmt = tx.prepare(
            "INSERT OR REPLACE INTO normalized_events (
                id, raw_event_id, source_kind, vendor, category,
                action, host_id, agent_id, hostname, process_guid,
                pid, ppid, uid, gid, user_name,
                exe_path, comm, cmdline, cwd, file_path,
                file_hash, src_ip, src_port, dst_ip, dst_port,
                protocol, namespace_pid, namespace_mnt, namespace_net, severity,
                confidence, observed_at, tags_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33)",
        )?;

        for event in events {
            stmt.execute(params![
                &event.id,
                &event.raw_event_id,
                &event.source_kind,
                &event.vendor,
                &event.category,
                &event.action,
                &event.host_id,
                &event.agent_id,
                &event.hostname,
                &event.process_guid,
                &event.pid,
                &event.ppid,
                &event.uid,
                &event.gid,
                &event.user_name,
                &event.exe_path,
                &event.comm,
                &event.cmdline,
                &event.cwd,
                &event.file_path,
                &event.file_hash,
                &event.src_ip,
                &event.src_port,
                &event.dst_ip,
                &event.dst_port,
                &event.protocol,
                &event.namespace_pid,
                &event.namespace_mnt,
                &event.namespace_net,
                &event.severity,
                &event.confidence,
                event.observed_at,
                &event.tags_json,
            ])?;
        }
    }

    tx.commit()?;
    Ok(events.len())
}

pub fn latest_edr_events(path: &Path, limit: usize) -> Result<Vec<EDREvent>> {
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database: {}", path.display()))?;
    let mut stmt = conn.prepare(
        "SELECT
            id, vendor, adapter_name, external_event_id, host_id,
            agent_id, hostname, process_guid, pid, ppid,
            exe_path, cmdline, file_path, src_ip, dst_ip,
            dst_port, severity, event_name, observed_at, raw_event_id, normalized_event_id
         FROM edr_events
         ORDER BY observed_at DESC, id DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map([limit as i64], |row| {
        Ok(EDREvent {
            id: row.get(0)?,
            vendor: row.get(1)?,
            adapter_name: row.get(2)?,
            external_event_id: row.get(3)?,
            host_id: row.get(4)?,
            agent_id: row.get(5)?,
            hostname: row.get(6)?,
            process_guid: row.get(7)?,
            pid: row.get(8)?,
            ppid: row.get(9)?,
            exe_path: row.get(10)?,
            cmdline: row.get(11)?,
            file_path: row.get(12)?,
            src_ip: row.get(13)?,
            dst_ip: row.get(14)?,
            dst_port: row.get(15)?,
            severity: row.get(16)?,
            event_name: row.get(17)?,
            observed_at: row.get(18)?,
            raw_event_id: row.get(19)?,
            normalized_event_id: row.get(20)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub fn latest_edr_alerts(path: &Path, limit: usize) -> Result<Vec<EDRAlert>> {
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database: {}", path.display()))?;
    let mut stmt = conn.prepare(
        "SELECT
            id, vendor, adapter_name, external_alert_id, host_id,
            hostname, alert_name, severity, status, process_guid,
            pid, tactic_tags_json, summary, observed_at, raw_event_id
         FROM edr_alerts
         ORDER BY observed_at DESC, id DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map([limit as i64], |row| {
        Ok(EDRAlert {
            id: row.get(0)?,
            vendor: row.get(1)?,
            adapter_name: row.get(2)?,
            external_alert_id: row.get(3)?,
            host_id: row.get(4)?,
            hostname: row.get(5)?,
            alert_name: row.get(6)?,
            severity: row.get(7)?,
            status: row.get(8)?,
            process_guid: row.get(9)?,
            pid: row.get(10)?,
            tactic_tags_json: row.get(11)?,
            summary: row.get(12)?,
            observed_at: row.get(13)?,
            raw_event_id: row.get(14)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub fn find_edr_events_by_pid_or_guid(
    path: &Path,
    pid: Option<i64>,
    process_guid: Option<&str>,
    limit: usize,
) -> Result<Vec<EDREvent>> {
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database: {}", path.display()))?;
    let mut stmt = conn.prepare(
        "SELECT
            id, vendor, adapter_name, external_event_id, host_id,
            agent_id, hostname, process_guid, pid, ppid,
            exe_path, cmdline, file_path, src_ip, dst_ip,
            dst_port, severity, event_name, observed_at, raw_event_id, normalized_event_id
         FROM edr_events
         WHERE (?1 IS NOT NULL AND pid = ?1)
            OR (?2 IS NOT NULL AND process_guid = ?2)
         ORDER BY observed_at DESC, id DESC
         LIMIT ?3",
    )?;

    let rows = stmt.query_map(params![pid, process_guid, limit as i64], |row| {
        Ok(EDREvent {
            id: row.get(0)?,
            vendor: row.get(1)?,
            adapter_name: row.get(2)?,
            external_event_id: row.get(3)?,
            host_id: row.get(4)?,
            agent_id: row.get(5)?,
            hostname: row.get(6)?,
            process_guid: row.get(7)?,
            pid: row.get(8)?,
            ppid: row.get(9)?,
            exe_path: row.get(10)?,
            cmdline: row.get(11)?,
            file_path: row.get(12)?,
            src_ip: row.get(13)?,
            dst_ip: row.get(14)?,
            dst_port: row.get(15)?,
            severity: row.get(16)?,
            event_name: row.get(17)?,
            observed_at: row.get(18)?,
            raw_event_id: row.get(19)?,
            normalized_event_id: row.get(20)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub fn find_edr_alerts_by_pid_or_guid(
    path: &Path,
    pid: Option<i64>,
    process_guid: Option<&str>,
    limit: usize,
) -> Result<Vec<EDRAlert>> {
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open sqlite database: {}", path.display()))?;
    let mut stmt = conn.prepare(
        "SELECT
            id, vendor, adapter_name, external_alert_id, host_id,
            hostname, alert_name, severity, status, process_guid,
            pid, tactic_tags_json, summary, observed_at, raw_event_id
         FROM edr_alerts
         WHERE (?1 IS NOT NULL AND pid = ?1)
            OR (?2 IS NOT NULL AND process_guid = ?2)
         ORDER BY observed_at DESC, id DESC
         LIMIT ?3",
    )?;

    let rows = stmt.query_map(params![pid, process_guid, limit as i64], |row| {
        Ok(EDRAlert {
            id: row.get(0)?,
            vendor: row.get(1)?,
            adapter_name: row.get(2)?,
            external_alert_id: row.get(3)?,
            host_id: row.get(4)?,
            hostname: row.get(5)?,
            alert_name: row.get(6)?,
            severity: row.get(7)?,
            status: row.get(8)?,
            process_guid: row.get(9)?,
            pid: row.get(10)?,
            tactic_tags_json: row.get(11)?,
            summary: row.get(12)?,
            observed_at: row.get(13)?,
            raw_event_id: row.get(14)?,
        })
    })?;

    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn count_rows(conn: &Connection, table: &str) -> Result<i64> {
    if !COUNTABLE_TABLES.contains(&table) {
        anyhow::bail!("unsupported count table: {table}");
    }

    let sql = format!("SELECT COUNT(*) FROM {table}");
    let count = conn.query_row(&sql, [], |row| row.get(0))?;
    Ok(count)
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory: {}", parent.display()))?;
    }
    Ok(())
}
