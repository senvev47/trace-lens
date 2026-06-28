# B 阶段统一事件模型与 Schema 设计

> 对应任务：`Todo.md` -> `B2. 统一事件模型设计`、`B3. 数据库 schema 设计`
>
> 目标：在不写实现代码的前提下，先把 `Tracee / Ring0 / EDR` 三类来源统一到一套 Rust 领域模型和 SQLite 表结构中，避免后续编码阶段反复改边界。

---

## 1. 设计约束

本阶段遵循以下约束：

1. 第一阶段只做单机 SQLite，不引入 PostgreSQL / ClickHouse / 图数据库
2. 主机原始事件以 `Tracee` 为主
3. Ring0 风险结果来自 `bpftool`、`unhide`、`tainted`、跨视图脚本
4. EDR 接入通过归一化模型处理，不直接把厂商字段塞进核心表
5. 进程血缘仍是主索引，文件、网络、Ring0、EDR 都是围绕进程和 incident 聚合

---

## 2. 统一事件层次

统一模型按三层组织：

1. `RawEvent`
   - 保留原始输入
   - 来源可能是 Tracee JSON、Ring0 巡检结果、EDR webhook/pull/import
2. `NormalizedEvent`
   - 统一字段命名
   - 用于关联、搜索、UI 和 incident 聚合
3. `Incident`
   - 高一层聚合结果
   - 用于呈现攻击链、风险摘要、报告导出

---

## 3. Rust 领域模型设计

以下为字段级设计，不代表现在就开始编码。

### 3.1 RawEvent

用途：

- 无损记录外部来源
- 保留回放和追责需要的原始 payload

建议字段：

```text
RawEvent
- id: String
- source_kind: String
- source_name: String
- event_name: String
- observed_at: i64
- host_id: Option<String>
- hostname: Option<String>
- process_key: Option<String>
- severity: Option<i32>
- payload_ref: Option<String>
- payload_json: Option<String>
- ingest_method: String
- ingest_job_id: Option<String>
- created_at: i64
```

字段说明：

- `source_kind`
  - `tracee`
  - `ring0_guard`
  - `edr`
- `source_name`
  - 具体来源名，如 `tracee`, `bpftool`, `unhide`, `crowdstrike`, `wazuh-import`
- `event_name`
  - 如 `sched_process_exec`, `hidden_process_detected`, `process_alert`
- `process_key`
  - 首阶段允许为空
  - 有值时优先使用 `host_id + pid + start_time` 或 EDR 的 process guid
- `payload_ref`
  - 大 payload 可只存文件引用
- `payload_json`
  - 小 payload 直接存原文

### 3.2 NormalizedEvent

用途：

- 作为统一查询和关联分析主模型
- 支撑 UI 和 API 输出

建议字段：

```text
NormalizedEvent
- id: String
- raw_event_id: Option<String>
- source_kind: String
- vendor: Option<String>
- category: String
- action: String
- host_id: Option<String>
- agent_id: Option<String>
- hostname: Option<String>
- process_guid: Option<String>
- pid: Option<i64>
- ppid: Option<i64>
- uid: Option<i64>
- gid: Option<i64>
- user_name: Option<String>
- exe_path: Option<String>
- comm: Option<String>
- cmdline: Option<String>
- cwd: Option<String>
- file_path: Option<String>
- file_hash: Option<String>
- src_ip: Option<String>
- src_port: Option<i64>
- dst_ip: Option<String>
- dst_port: Option<i64>
- protocol: Option<String>
- namespace_pid: Option<i64>
- namespace_mnt: Option<i64>
- namespace_net: Option<i64>
- severity: Option<i32>
- confidence: Option<f32>
- observed_at: i64
- tags_json: Option<String>
```

分类建议：

- `category`
  - `process`
  - `file`
  - `network`
  - `ring0`
  - `edr`
  - `alert`
- `action`
  - `fork`
  - `exec`
  - `exit`
  - `open`
  - `write`
  - `connect`
  - `dns_query`
  - `hidden_process`
  - `ebpf_program_added`
  - `alert_triggered`

### 3.3 Incident

用途：

- 聚合同一条攻击链或同一轮异常活动

建议字段：

```text
Incident
- id: String
- incident_key: String
- title: String
- summary: String
- severity: i32
- confidence: f32
- status: String
- root_pid: Option<i64>
- root_process_guid: Option<String>
- host_id: Option<String>
- hostname: Option<String>
- first_seen_at: i64
- last_seen_at: i64
- source_count: i32
- event_count: i32
- tactic_tags_json: Option<String>
- evidence_json: Option<String>
- created_at: i64
- updated_at: i64
```

### 3.4 ProcessNode

用途：

- 表示进程血缘图节点

建议字段：

```text
ProcessNode
- process_key: String
- pid: i64
- ppid: Option<i64>
- process_guid: Option<String>
- parent_process_key: Option<String>
- exe_path: Option<String>
- comm: Option<String>
- cmdline: Option<String>
- cwd: Option<String>
- uid: Option<i64>
- gid: Option<i64>
- loginuid: Option<i64>
- session_id: Option<i64>
- start_time: i64
- exit_time: Option<i64>
- namespace_pid: Option<i64>
- namespace_mnt: Option<i64>
- namespace_net: Option<i64>
- trust_score: i32
- trust_reasons_json: Option<String>
- flags_json: Option<String>
```

### 3.5 Ring0Finding

用途：

- 把所有主机完整性巡检结果统一表示

建议字段：

```text
Ring0Finding
- id: String
- finding_type: String
- detector: String
- severity: i32
- trust_level: String
- host_id: Option<String>
- hostname: Option<String>
- pid: Option<i64>
- object_ref: Option<String>
- summary: String
- detail_json: Option<String>
- observed_at: i64
```

建议 `finding_type`：

- `ebpf_diff`
- `hidden_process`
- `hidden_port`
- `tainted_kernel`
- `lsmod_mismatch`
- `proc_ps_mismatch`
- `ss_netstat_mismatch`
- `mirror_trap_hit`

### 3.6 EDREvent

用途：

- 接收第三方 EDR 事件后落到统一表

建议字段：

```text
EDREvent
- id: String
- vendor: String
- adapter_name: String
- external_event_id: Option<String>
- host_id: Option<String>
- agent_id: Option<String>
- hostname: Option<String>
- process_guid: Option<String>
- pid: Option<i64>
- ppid: Option<i64>
- exe_path: Option<String>
- cmdline: Option<String>
- file_path: Option<String>
- src_ip: Option<String>
- dst_ip: Option<String>
- dst_port: Option<i64>
- severity: Option<i32>
- event_name: String
- observed_at: i64
- raw_event_id: Option<String>
- normalized_event_id: Option<String>
```

### 3.7 EDRAlert

用途：

- 对接厂商告警而非底层事件

建议字段：

```text
EDRAlert
- id: String
- vendor: String
- adapter_name: String
- external_alert_id: Option<String>
- host_id: Option<String>
- hostname: Option<String>
- alert_name: String
- severity: i32
- status: String
- process_guid: Option<String>
- pid: Option<i64>
- tactic_tags_json: Option<String>
- summary: Option<String>
- observed_at: i64
- raw_event_id: Option<String>
```

---

## 4. Tracee / Ring0 / EDR 映射原则

### 4.1 Tracee -> RawEvent

映射原则：

1. 每条 Tracee JSON 先原样进入 `raw_events`
2. 保留 Tracee 原始事件名
3. 从中提取 `pid / ppid / comm / cmdline / pathname / addresses` 等字段生成 `normalized_events`

建议映射：

| Tracee 类别 | `category` | `action` |
| --- | --- | --- |
| `sched_process_fork` | `process` | `fork` |
| `sched_process_exec` | `process` | `exec` |
| `sched_process_exit` | `process` | `exit` |
| `security_file_open` / open 类 | `file` | `open` |
| `security_file_permission` / write 类 | `file` | `write` |
| `tcp_connect` | `network` | `connect` |
| `udp_sendmsg` + dns 语义 | `network` | `dns_query` |

### 4.2 Ring0 -> NormalizedEvent / Ring0Finding

映射原则：

1. 巡检结果保留原始文本输出
2. 同时抽象为结构化 finding
3. Ring0 finding 既要能独立展示，也要能影响 incident 风险和主机信任等级

### 4.3 EDR -> NormalizedEvent

映射原则：

1. 厂商 payload 先写 `raw_events`
2. 适配器将其转成 `edr_events` 或 `edr_alerts`
3. 再映射到统一 `normalized_events`
4. 尽量保留 `process_guid`，这是跨系统关联的关键键值之一

---

## 5. SQLite Schema 设计

### 5.1 raw_events

用途：

- 保存所有来源的原始输入

建议字段：

```text
raw_events
- id TEXT PRIMARY KEY
- source_kind TEXT NOT NULL
- source_name TEXT NOT NULL
- event_name TEXT NOT NULL
- observed_at INTEGER NOT NULL
- host_id TEXT
- hostname TEXT
- process_key TEXT
- severity INTEGER
- ingest_method TEXT NOT NULL
- ingest_job_id TEXT
- payload_ref TEXT
- payload_json TEXT
- created_at INTEGER NOT NULL
```

索引建议：

- `idx_raw_events_observed_at`
- `idx_raw_events_source_kind`
- `idx_raw_events_host_id`
- `idx_raw_events_process_key`

### 5.2 processes

用途：

- 存储进程节点快照

建议字段：

```text
processes
- process_key TEXT PRIMARY KEY
- pid INTEGER NOT NULL
- ppid INTEGER
- process_guid TEXT
- parent_process_key TEXT
- exe_path TEXT
- comm TEXT
- cmdline TEXT
- cwd TEXT
- uid INTEGER
- gid INTEGER
- loginuid INTEGER
- session_id INTEGER
- start_time INTEGER NOT NULL
- exit_time INTEGER
- namespace_pid INTEGER
- namespace_mnt INTEGER
- namespace_net INTEGER
- trust_score INTEGER DEFAULT 50
- trust_reasons_json TEXT
- flags_json TEXT
- created_at INTEGER NOT NULL
- updated_at INTEGER NOT NULL
```

索引建议：

- `idx_processes_pid`
- `idx_processes_ppid`
- `idx_processes_start_time`
- `idx_processes_parent_process_key`
- `idx_processes_process_guid`

### 5.3 process_edges

用途：

- 独立记录父子关系和事件来源

建议字段：

```text
process_edges
- id TEXT PRIMARY KEY
- parent_process_key TEXT NOT NULL
- child_process_key TEXT NOT NULL
- edge_type TEXT NOT NULL
- observed_at INTEGER NOT NULL
- raw_event_id TEXT
```

说明：

- `edge_type` 第一阶段先固定 `fork_exec`

### 5.4 file_events

用途：

- 存储重要文件活动

建议字段：

```text
file_events
- id TEXT PRIMARY KEY
- raw_event_id TEXT
- normalized_event_id TEXT
- process_key TEXT
- pid INTEGER
- action TEXT NOT NULL
- file_path TEXT
- file_hash TEXT
- bytes_written INTEGER
- severity INTEGER
- observed_at INTEGER NOT NULL
```

索引建议：

- `idx_file_events_process_key`
- `idx_file_events_file_path`
- `idx_file_events_observed_at`

### 5.5 network_events

用途：

- 存储网络连接与 DNS 活动

建议字段：

```text
network_events
- id TEXT PRIMARY KEY
- raw_event_id TEXT
- normalized_event_id TEXT
- process_key TEXT
- pid INTEGER
- action TEXT NOT NULL
- protocol TEXT
- src_ip TEXT
- src_port INTEGER
- dst_ip TEXT
- dst_port INTEGER
- dns_query TEXT
- bytes_sent INTEGER
- bytes_recv INTEGER
- severity INTEGER
- observed_at INTEGER NOT NULL
```

索引建议：

- `idx_network_events_process_key`
- `idx_network_events_dst_ip`
- `idx_network_events_dst_port`
- `idx_network_events_observed_at`

### 5.6 incidents

用途：

- 聚合后的事件主表

建议字段：

```text
incidents
- id TEXT PRIMARY KEY
- incident_key TEXT NOT NULL UNIQUE
- title TEXT NOT NULL
- summary TEXT
- severity INTEGER NOT NULL
- confidence REAL NOT NULL
- status TEXT NOT NULL
- root_pid INTEGER
- root_process_guid TEXT
- host_id TEXT
- hostname TEXT
- first_seen_at INTEGER NOT NULL
- last_seen_at INTEGER NOT NULL
- source_count INTEGER DEFAULT 0
- event_count INTEGER DEFAULT 0
- tactic_tags_json TEXT
- evidence_json TEXT
- created_at INTEGER NOT NULL
- updated_at INTEGER NOT NULL
```

索引建议：

- `idx_incidents_host_id`
- `idx_incidents_first_seen_at`
- `idx_incidents_status`
- `idx_incidents_severity`

### 5.7 ioc_hits

用途：

- 记录 IOC 和软规则命中

建议字段：

```text
ioc_hits
- id TEXT PRIMARY KEY
- incident_id TEXT
- process_key TEXT
- indicator_type TEXT NOT NULL
- indicator_value TEXT NOT NULL
- rule_name TEXT NOT NULL
- severity INTEGER
- observed_at INTEGER NOT NULL
- raw_event_id TEXT
- normalized_event_id TEXT
```

### 5.8 ring0_findings

用途：

- 保存所有主机完整性异常

建议字段：

```text
ring0_findings
- id TEXT PRIMARY KEY
- finding_type TEXT NOT NULL
- detector TEXT NOT NULL
- severity INTEGER NOT NULL
- trust_level TEXT NOT NULL
- host_id TEXT
- hostname TEXT
- pid INTEGER
- object_ref TEXT
- summary TEXT NOT NULL
- detail_json TEXT
- observed_at INTEGER NOT NULL
- raw_event_id TEXT
```

索引建议：

- `idx_ring0_findings_observed_at`
- `idx_ring0_findings_finding_type`
- `idx_ring0_findings_trust_level`

### 5.9 edr_events

用途：

- 存放第三方 EDR 归一化事件

建议字段：

```text
edr_events
- id TEXT PRIMARY KEY
- vendor TEXT NOT NULL
- adapter_name TEXT NOT NULL
- external_event_id TEXT
- host_id TEXT
- agent_id TEXT
- hostname TEXT
- process_guid TEXT
- pid INTEGER
- ppid INTEGER
- exe_path TEXT
- cmdline TEXT
- file_path TEXT
- src_ip TEXT
- dst_ip TEXT
- dst_port INTEGER
- severity INTEGER
- event_name TEXT NOT NULL
- observed_at INTEGER NOT NULL
- raw_event_id TEXT
- normalized_event_id TEXT
```

索引建议：

- `idx_edr_events_vendor`
- `idx_edr_events_host_id`
- `idx_edr_events_process_guid`
- `idx_edr_events_observed_at`

### 5.10 edr_alerts

用途：

- 存放第三方 EDR 告警

建议字段：

```text
edr_alerts
- id TEXT PRIMARY KEY
- vendor TEXT NOT NULL
- adapter_name TEXT NOT NULL
- external_alert_id TEXT
- host_id TEXT
- hostname TEXT
- alert_name TEXT NOT NULL
- severity INTEGER NOT NULL
- status TEXT NOT NULL
- process_guid TEXT
- pid INTEGER
- tactic_tags_json TEXT
- summary TEXT
- observed_at INTEGER NOT NULL
- raw_event_id TEXT
```

### 5.11 reports

用途：

- 保存导出报告的元数据

建议字段：

```text
reports
- id TEXT PRIMARY KEY
- incident_id TEXT
- report_type TEXT NOT NULL
- title TEXT NOT NULL
- output_path TEXT
- summary TEXT
- created_at INTEGER NOT NULL
```

### 5.12 integration_jobs

用途：

- 记录 pull/import 任务执行情况

建议字段：

```text
integration_jobs
- id TEXT PRIMARY KEY
- adapter_name TEXT NOT NULL
- job_type TEXT NOT NULL
- status TEXT NOT NULL
- started_at INTEGER NOT NULL
- finished_at INTEGER
- cursor_value TEXT
- summary TEXT
- error_text TEXT
```

---

## 6. 关键查询路径

第一阶段必须保证以下查询路径能被当前 schema 支撑：

1. 给定 `PID` / `process_key` 查父链与子链
2. 给定 `PID` 查文件访问
3. 给定 `PID` 查网络连接
4. 给定 `IP` 查关联进程和 incident
5. 给定 incident 查时间线
6. 查最近 `Ring0Finding`
7. 查某个 EDR 告警关联的本地进程链

因此当前 schema 的关键点是：

1. `process_key` 作为本地主关联键
2. `process_guid` 作为 EDR 跨系统关联键
3. `observed_at` 作为统一时间排序键
4. `raw_event_id` 作为回溯原文入口

---

## 7. 当前阶段结论

本设计阶段可以判定已完成的事项：

1. `RawEvent` 定义完成
2. `NormalizedEvent` 定义完成
3. `Incident` 定义完成
4. `ProcessNode` 定义完成
5. `Ring0Finding` 定义完成
6. `EDRAlert` 定义完成
7. `EDREvent` 定义完成
8. `Tracee -> RawEvent` 映射原则完成
9. `EDR -> NormalizedEvent` 映射原则完成
10. SQLite 主表与索引设计完成

尚未完成的事项：

1. 真实 `schema.sql` 文件落地
2. 实际初始化数据库并验证
3. Rust 结构体与 DAO 实现
4. Tracee / Ring0 / EDR 解析器编码

结论：

- `Todo.md` 中 `B2` 设计项可以进入已完成状态
- `Todo.md` 中 `B3` 除“schema 初始化验证”外，其余设计项可以进入已完成状态
