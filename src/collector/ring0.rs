#![allow(dead_code)]

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::model::ring0::{Ring0CheckSummary, Ring0Finding};

#[derive(Debug, Default)]
pub struct Ring0Collector;

pub fn run_checks() -> Result<Ring0CheckSummary> {
    let hostname = read_hostname().ok();
    let host_id = hostname.clone();
    let mut findings = Vec::new();

    if let Some(finding) = check_tainted(host_id.clone(), hostname.clone())? {
        findings.push(finding);
    }

    let proc_ps = check_proc_vs_ps(host_id.clone(), hostname.clone())?;
    if let Some(finding) = proc_ps {
        findings.push(finding);
    }

    let ss_netstat = check_ss_vs_netstat(host_id.clone(), hostname.clone())?;
    if let Some(finding) = ss_netstat {
        findings.push(finding);
    }

    findings.extend(check_bpftool_programs(host_id.clone(), hostname.clone())?);
    findings.extend(check_unhide(host_id.clone(), hostname.clone())?);

    Ok(Ring0CheckSummary {
        host_id,
        hostname,
        findings,
    })
}

fn check_tainted(
    host_id: Option<String>,
    hostname: Option<String>,
) -> Result<Option<Ring0Finding>> {
    let value = std::fs::read_to_string("/proc/sys/kernel/tainted")
        .context("failed to read /proc/sys/kernel/tainted")?;
    let value = value.trim().parse::<i64>().unwrap_or(0);

    if value == 0 {
        return Ok(None);
    }

    Ok(Some(Ring0Finding {
        id: "ring0:tainted_kernel".to_string(),
        finding_type: "tainted_kernel".to_string(),
        detector: "procfs".to_string(),
        severity: 8,
        trust_level: "L2".to_string(),
        host_id,
        hostname,
        pid: None,
        object_ref: Some("/proc/sys/kernel/tainted".to_string()),
        summary: format!("kernel tainted value is non-zero: {value}"),
        detail_json: Some(format!(r#"{{"tainted_value":{value}}}"#)),
        observed_at: now_unix_seconds(),
    }))
}

fn check_proc_vs_ps(
    host_id: Option<String>,
    hostname: Option<String>,
) -> Result<Option<Ring0Finding>> {
    let proc_count = std::fs::read_dir("/proc")
        .context("failed to read /proc")?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .chars()
                .all(|c| c.is_ascii_digit())
        })
        .count() as i64;

    let ps_output = command_output("ps", &["-e", "-o", "pid="])?;
    let ps_count = ps_output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count() as i64;
    let diff = (proc_count - ps_count).abs();

    if diff <= 3 {
        return Ok(None);
    }

    Ok(Some(Ring0Finding {
        id: "ring0:proc_ps_mismatch".to_string(),
        finding_type: "proc_ps_mismatch".to_string(),
        detector: "cross_view".to_string(),
        severity: 6,
        trust_level: "L1".to_string(),
        host_id,
        hostname,
        pid: None,
        object_ref: Some("/proc vs ps".to_string()),
        summary: format!("process count mismatch: /proc={proc_count}, ps={ps_count}"),
        detail_json: Some(format!(
            r#"{{"proc_count":{proc_count},"ps_count":{ps_count},"diff":{diff}}}"#
        )),
        observed_at: now_unix_seconds(),
    }))
}

fn check_ss_vs_netstat(
    host_id: Option<String>,
    hostname: Option<String>,
) -> Result<Option<Ring0Finding>> {
    let ss_output = command_output("ss", &["-tln"])?;
    let netstat_output = command_output("netstat", &["-tln"])?;

    let ss_count = count_listener_lines(&ss_output);
    let netstat_count = count_listener_lines(&netstat_output);
    let diff = (ss_count - netstat_count).abs();

    if diff <= 1 {
        return Ok(None);
    }

    Ok(Some(Ring0Finding {
        id: "ring0:ss_netstat_mismatch".to_string(),
        finding_type: "ss_netstat_mismatch".to_string(),
        detector: "cross_view".to_string(),
        severity: 6,
        trust_level: "L1".to_string(),
        host_id,
        hostname,
        pid: None,
        object_ref: Some("ss vs netstat".to_string()),
        summary: format!("listener count mismatch: ss={ss_count}, netstat={netstat_count}"),
        detail_json: Some(format!(
            r#"{{"ss_count":{ss_count},"netstat_count":{netstat_count},"diff":{diff}}}"#
        )),
        observed_at: now_unix_seconds(),
    }))
}

fn check_bpftool_programs(
    host_id: Option<String>,
    hostname: Option<String>,
) -> Result<Vec<Ring0Finding>> {
    let output = command_output("bpftool", &["prog", "list"])?;
    let suspicious = output
        .lines()
        .filter(|line| line.contains(" name "))
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains(" hid_")
                || lower.contains(" hid")
                || lower.contains("rootkit")
                || lower.contains("mal")
        })
        .map(|line| line.trim().to_string())
        .collect::<Vec<_>>();

    if suspicious.is_empty() {
        return Ok(Vec::new());
    }

    let observed_at = now_unix_seconds();
    Ok(suspicious
        .into_iter()
        .enumerate()
        .map(|(index, line)| Ring0Finding {
            id: format!("ring0:bpftool:{}:{}", stable_token(&line), index),
            finding_type: "ebpf_diff".to_string(),
            detector: "bpftool".to_string(),
            severity: 8,
            trust_level: "L2".to_string(),
            host_id: host_id.clone(),
            hostname: hostname.clone(),
            pid: None,
            object_ref: Some("bpftool prog list".to_string()),
            summary: format!("suspicious eBPF program detected: {line}"),
            detail_json: Some(format!(r#"{{"bpftool_line":{:?}}}"#, line)),
            observed_at,
        })
        .collect())
}

fn check_unhide(host_id: Option<String>, hostname: Option<String>) -> Result<Vec<Ring0Finding>> {
    let output = command_output("timeout", &["12s", "unhide", "quick"])?;
    let suspicious = parse_unhide_suspicious_lines(&output);

    if suspicious.is_empty() {
        return Ok(Vec::new());
    }

    let observed_at = now_unix_seconds();
    Ok(suspicious
        .into_iter()
        .enumerate()
        .map(|(index, line)| Ring0Finding {
            id: format!("ring0:unhide:{}:{}", stable_token(&line), index),
            finding_type: "hidden_process".to_string(),
            detector: "unhide".to_string(),
            severity: 7,
            trust_level: "L2".to_string(),
            host_id: host_id.clone(),
            hostname: hostname.clone(),
            pid: None,
            object_ref: Some("unhide quick".to_string()),
            summary: format!("unhide reported suspicious result: {line}"),
            detail_json: Some(format!(r#"{{"unhide_line":{:?}}}"#, line)),
            observed_at,
        })
        .collect())
}

fn parse_unhide_suspicious_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            !lower.starts_with("[*]searching")
                && !lower.starts_with("[*]starting")
                && !lower.starts_with("unhide ")
                && !lower.starts_with("used options:")
                && !lower.starts_with("copyright")
                && !lower.starts_with("license")
                && !lower.starts_with("http://")
                && !lower.starts_with("note :")
                && (lower.contains("hidden process")
                    || lower.contains("suspicious")
                    || lower.contains("mismatch")
                    || lower.contains("tampered")
                    || lower.contains("hidden port")
                    || lower.contains("hidden module"))
        })
        .map(str::to_string)
        .collect::<Vec<_>>()
}

fn command_output(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {cmd}"))?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn read_hostname() -> Result<String> {
    Ok(std::fs::read_to_string("/etc/hostname")?.trim().to_string())
}

fn count_listener_lines(output: &str) -> i64 {
    output
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty()
                && !trimmed.starts_with("State")
                && !trimmed.starts_with("Active")
                && !trimmed.starts_with("Proto")
        })
        .count() as i64
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn stable_token(input: &str) -> String {
    input
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .chars()
        .take(48)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_unhide_suspicious_lines;

    #[test]
    fn parse_unhide_suspicious_lines_keeps_hits_and_drops_banner_noise() {
        let output = r#"Unhide 20211016
Copyright © 2010-2021 Yago Jesus & Patrick Gouin
License GPLv3+ : GNU GPL version 3 or later
http://www.unhide-forensics.info
NOTE : This version of unhide is for systems using Linux >= 2.6
Used options:
[*]Searching for Hidden processes through comparison of results of system calls, proc, dir and ps
Hidden process found: /proc/4242 mismatch
suspicious TCP/31337 hidden port
"#;

        let lines = parse_unhide_suspicious_lines(output);

        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("Hidden process found"));
        assert!(lines[1].contains("hidden port"));
    }

    #[test]
    fn parse_unhide_suspicious_lines_returns_empty_for_clean_banner_only_output() {
        let output = r#"Unhide 20211016
Used options:
[*]Searching for Hidden processes through comparison of results of system calls, proc, dir and ps
"#;

        let lines = parse_unhide_suspicious_lines(output);

        assert!(lines.is_empty());
    }
}
