#![allow(dead_code)]

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::model::ring0::Ring0Finding;

const MIRROR_TRAP_PATHS: [&str; 2] = [
    "/tmp/trace_lens_singularity_canary",
    "/tmp/trace_lens_bds_canary",
];

const GHOST_PORTS: [u16; 2] = [8081, 31337];
const GHOST_PORT_STATE_DIR: &str = "/tmp/trace_lens_canary";

#[derive(Debug, Default)]
pub struct CanaryCollector;

pub fn setup_mirror_traps() -> Result<Vec<String>> {
    let mut created = Vec::new();

    for path in mirror_trap_paths() {
        fs::write(&path, b"trace-lens-canary\n")
            .with_context(|| format!("failed to create mirror trap: {path}"))?;
        created.push(path);
    }

    Ok(created)
}

pub fn setup_ghost_ports() -> Result<Vec<u16>> {
    fs::create_dir_all(ghost_port_state_dir())
        .context("failed to create ghost port state directory")?;

    let mut active = Vec::new();
    for port in ghost_ports() {
        if ghost_port_alive(port) || port_is_listening(port) {
            active.push(port);
            continue;
        }

        if spawn_ghost_port_listener(port).is_ok()
            && (ghost_port_alive(port) || port_is_listening(port))
        {
            active.push(port);
        }
    }

    Ok(active)
}

pub fn serve_canaries() -> Result<()> {
    let _ = setup_mirror_traps()?;
    let mut listeners = Vec::new();
    for port in ghost_ports() {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .with_context(|| format!("failed to bind foreground ghost port listener on {port}"))?;
        listeners.push(listener);
    }

    loop {
        thread::sleep(Duration::from_secs(60));
        let _ = &listeners;
    }
}

pub fn check_mirror_traps() -> Result<Vec<Ring0Finding>> {
    let mut findings = Vec::new();

    for path in mirror_trap_paths() {
        if let Some(finding) = evaluate_mirror_trap(&path, None)? {
            findings.push(finding);
        }
    }

    Ok(findings)
}

pub fn check_ghost_ports() -> Result<Vec<Ring0Finding>> {
    let mut findings = Vec::new();

    for port in ghost_ports() {
        if let Some(finding) = evaluate_ghost_port(port, None, None)? {
            findings.push(finding);
        }
    }

    Ok(findings)
}

pub fn mirror_trap_paths() -> Vec<String> {
    MIRROR_TRAP_PATHS
        .iter()
        .map(|path| path.to_string())
        .collect()
}

pub fn ghost_ports() -> Vec<u16> {
    GHOST_PORTS.to_vec()
}

fn ghost_port_state_dir() -> PathBuf {
    PathBuf::from(GHOST_PORT_STATE_DIR)
}

fn ghost_port_pid_path(port: u16) -> PathBuf {
    ghost_port_state_dir().join(format!("ghost-port-{port}.pid"))
}

fn spawn_ghost_port_listener(port: u16) -> Result<()> {
    let pid_path = ghost_port_pid_path(port);
    let shell =
        format!("nohup python3 -m http.server {port} --bind 127.0.0.1 >/dev/null 2>&1 & echo $!");
    let output = Command::new("sh")
        .args(["-lc", &shell])
        .output()
        .with_context(|| format!("failed to spawn ghost port listener on {port}"))?;
    let pid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if pid.is_empty() {
        anyhow::bail!("ghost port listener returned empty pid on {port}");
    }

    fs::write(&pid_path, &pid).with_context(|| {
        format!(
            "failed to write ghost port pid file: {}",
            pid_path.display()
        )
    })?;

    thread::sleep(Duration::from_millis(200));
    if !ghost_port_alive(port) || !port_is_listening(port) {
        let _ = fs::remove_file(&pid_path);
        anyhow::bail!("ghost port listener did not stay active on {port}");
    }

    Ok(())
}

fn ghost_port_alive(port: u16) -> bool {
    let pid_path = ghost_port_pid_path(port);
    let Ok(pid_str) = fs::read_to_string(pid_path) else {
        return false;
    };
    let Ok(pid) = pid_str.trim().parse::<u32>() else {
        return false;
    };

    Path::new(&format!("/proc/{pid}")).exists()
}

fn port_is_listening(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_err()
}

fn ls_lists_path(path: &str) -> Result<bool> {
    let parent = Path::new(path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| Path::new("/tmp").to_path_buf());
    let filename = Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();

    let output = std::process::Command::new("ls")
        .arg("-1")
        .arg(&parent)
        .output()
        .with_context(|| format!("failed to list directory: {}", parent.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().any(|line| line.trim() == filename))
}

fn evaluate_mirror_trap(
    path: &str,
    visible_override: Option<bool>,
) -> Result<Option<Ring0Finding>> {
    if !Path::new(path).exists() {
        return Ok(None);
    }

    let visible_in_ls = match visible_override {
        Some(value) => value,
        None => ls_lists_path(path)?,
    };

    if visible_in_ls {
        return Ok(None);
    }

    let hostname = read_hostname().ok();
    Ok(Some(Ring0Finding {
        id: format!("ring0:mirror_trap:{}", stable_token(path)),
        finding_type: "mirror_trap_hit".to_string(),
        detector: "mirror_trap".to_string(),
        severity: 8,
        trust_level: "L2".to_string(),
        host_id: hostname.clone(),
        hostname,
        pid: None,
        object_ref: Some(path.to_string()),
        summary: format!("mirror trap exists on disk but is hidden from ls: {path}"),
        detail_json: Some(format!(r#"{{"path":{:?},"ls_visible":false}}"#, path)),
        observed_at: now_unix_seconds(),
    }))
}

fn evaluate_ghost_port(
    port: u16,
    ss_visible_override: Option<bool>,
    netstat_visible_override: Option<bool>,
) -> Result<Option<Ring0Finding>> {
    if !ghost_port_alive(port) && !port_is_listening(port) {
        return Ok(None);
    }

    let ss_visible = match ss_visible_override {
        Some(value) => value,
        None => ss_lists_port(port)?,
    };
    let netstat_visible = match netstat_visible_override {
        Some(value) => value,
        None => netstat_lists_port(port)?,
    };

    if ss_visible && netstat_visible {
        return Ok(None);
    }

    let hostname = read_hostname().ok();
    let summary = if !ss_visible && !netstat_visible {
        format!("ghost port listener is active but hidden from both ss and netstat: {port}")
    } else if !ss_visible {
        format!("ghost port listener is active but hidden from ss: {port}")
    } else {
        format!("ghost port listener is active but hidden from netstat: {port}")
    };

    Ok(Some(Ring0Finding {
        id: format!("ring0:ghost_port:{port}"),
        finding_type: "ghost_port_hit".to_string(),
        detector: "ghost_port".to_string(),
        severity: 8,
        trust_level: "L2".to_string(),
        host_id: hostname.clone(),
        hostname,
        pid: None,
        object_ref: Some(format!("tcp:{port}")),
        summary,
        detail_json: Some(format!(
            r#"{{"port":{port},"ss_visible":{ss_visible},"netstat_visible":{netstat_visible}}}"#
        )),
        observed_at: now_unix_seconds(),
    }))
}

fn ss_lists_port(port: u16) -> Result<bool> {
    command_lists_port("ss", &["-tln"], port)
}

fn netstat_lists_port(port: u16) -> Result<bool> {
    command_lists_port("netstat", &["-tln"], port)
}

fn command_lists_port(cmd: &str, args: &[&str], port: u16) -> Result<bool> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {cmd}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let needle = format!(":{port}");
    Ok(stdout.lines().any(|line| line.contains(&needle)))
}

fn read_hostname() -> Result<String> {
    Ok(std::fs::read_to_string("/etc/hostname")?.trim().to_string())
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
        .to_string()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        evaluate_ghost_port, evaluate_mirror_trap, ghost_port_pid_path, ghost_ports,
        mirror_trap_paths,
    };

    #[test]
    fn mirror_trap_paths_are_stable() {
        let paths = mirror_trap_paths();
        assert_eq!(paths.len(), 2);
        assert!(
            paths
                .iter()
                .all(|path| path.starts_with("/tmp/trace_lens_"))
        );
    }

    #[test]
    fn ghost_port_list_is_stable() {
        assert_eq!(ghost_ports(), vec![8081, 31337]);
    }

    #[test]
    fn mirror_trap_hidden_state_produces_finding() {
        let path = "/tmp/trace_lens_test_hidden_canary";
        fs::write(path, b"trace-lens-canary\n").expect("should create canary file");

        let finding = evaluate_mirror_trap(path, Some(false))
            .expect("mirror trap evaluation should succeed")
            .expect("hidden trap should produce finding");

        assert_eq!(finding.finding_type, "mirror_trap_hit");
        assert_eq!(finding.detector, "mirror_trap");
        assert_eq!(finding.object_ref.as_deref(), Some(path));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn ghost_port_hidden_state_produces_finding() {
        let pid_path = ghost_port_pid_path(43137);
        let parent = pid_path.parent().expect("pid path should have parent");
        fs::create_dir_all(parent).expect("state dir should exist");
        fs::write(&pid_path, std::process::id().to_string()).expect("pid file should be written");

        let finding = evaluate_ghost_port(43137, Some(false), Some(true))
            .expect("ghost port evaluation should succeed")
            .expect("hidden ghost port should produce finding");

        assert_eq!(finding.finding_type, "ghost_port_hit");
        assert_eq!(finding.detector, "ghost_port");
        assert_eq!(finding.object_ref.as_deref(), Some("tcp:43137"));

        let _ = fs::remove_file(pid_path);
    }
}
