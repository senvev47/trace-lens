# Goal.md

> 项目名称：Trace Lens  
> 目标：基于综合方案设计文档落地一个 **Rust 实现**、**支持 EDR 接入**、**具备可视化能力**、并且适合 **Ubuntu 24.04.4 LTS / kernel 6.8.0-117** 的单机追踪溯源系统。  
> 当前阶段：只输出实现计划，不生成代码。

---

## 1. 总目标

在 3-4 天内完成一个可演示、可验证、可扩展的蓝队可视化追踪溯源系统，满足以下核心能力：

1. 持续采集主机事件，不丢主链路
2. 能按 incident 聚合事件
3. 能从进程追到文件和网络
4. 能展示进程血缘图
5. 能展示攻击时间线
6. 能展示 Ring0 风险状态
7. 能接入至少一种 EDR 事件源
8. 能导出报告
9. 能在单机 Ubuntu 上稳定运行

---

## 2. 项目总原则

### 2.1 设计原则

1. 复用成熟传感器，不自研全套 eBPF 采集器
2. 用 Rust 统一实现 CLI、API、关联分析、EDR 适配层
3. 以进程血缘为主索引，以文件、网络、Ring0、EDR 为辅证据
4. 以单机部署为第一阶段目标，但接口要为后续扩展留边界
5. 优先完成主链路，再做增强项

### 2.2 第一阶段明确不做

1. 不做多厂商深度 EDR SDK 定制
2. 不做分布式多主机
3. 不做完整 SIEM
4. 不做全量自研 eBPF 传感器
5. 不做自动内存转储
6. 不做复杂图数据库
7. 不做逐事件哈希链
8. 不默认启用 Ghost Port 端口蜜罐

---

## 3. 交付物总清单

第一阶段目标交付物应包括：

1. `trace-lens` Rust 项目骨架
2. 可运行的 CLI
3. 可运行的 HTTP API
4. Tracee 事件接入链路
5. Ring0 巡检链路
6. EDR 接口层与一个参考适配器
7. SQLite 数据库与 schema
8. Web 可视化页面
9. Markdown 报告导出能力
10. systemd 启动文件
11. 运维和对抗操作文档

---

## 4. 大计划总览

整个实现计划分为 8 个大阶段：

1. 阶段 A：环境与基础设施准备
2. 阶段 B：项目骨架与统一数据模型
3. 阶段 C：主机事件采集与存储落库
4. 阶段 D：关联分析与信任体系
5. 阶段 E：EDR 接口层与归一化
6. 阶段 F：CLI / API / Web 可视化
7. 阶段 G：报告、回放与导出
8. 阶段 H：联调、验证、收尾

每个阶段下面再拆小计划、依赖关系和验收标准。

---

## 5. 阶段 A：环境与基础设施准备

### A1. 系统能力确认

目标：

- 确认 Ubuntu、kernel、BTF、bpftool、bpftrace 可用
- 确认 Tracee 可以运行的前置条件

小计划：

1. 检查内核版本
2. 检查 `/sys/kernel/btf/vmlinux`
3. 检查 `bpftool` 是否可用
4. 检查 `bpftrace` 是否可用
5. 记录系统信息作为基线

验收标准：

- 输出一份环境检查结果
- 确认系统满足 Tracee 与 Rust 开发条件

### A2. Rust 工具链安装

目标：

- 具备 Rust 开发、构建、调试能力

小计划：

1. 安装 `build-essential`
2. 安装 `clang`、`llvm`
3. 安装 `pkg-config`
4. 安装 `libsqlite3-dev`
5. 安装 `libelf-dev`
6. 安装 `rustup`
7. 安装稳定版 Rust

验收标准：

- `rustc --version` 可用
- `cargo --version` 可用
- 能执行最小 Rust 构建

### A3. 第三方工具准备

目标：

- 补齐本方案所需外部工具

小计划：

1. 安装 Tracee 或准备 Tracee release 包
2. 安装 `sqlite3`
3. 安装 `graphviz`
4. 安装 `unhide`
5. 规划前端静态资源接入方式

验收标准：

- Tracee 可执行
- SQLite CLI 可用
- Graphviz 可用于导图
- Unhide 可执行

---

## 6. 阶段 B：项目骨架与统一数据模型

### B1. Rust 项目初始化

目标：

- 建立可长期扩展的 Rust 项目结构

小计划：

1. 初始化 `Cargo.toml`
2. 建立 `src/main.rs`
3. 建立 `src/cli`
4. 建立 `src/api`
5. 建立 `src/collector`
6. 建立 `src/connectors`
7. 建立 `src/engine`
8. 建立 `src/model`
9. 建立 `src/storage`

验收标准：

- 项目结构完整
- `cargo build` 可通过

### B2. 统一事件模型设计

目标：

- 统一本地事件与 EDR 外部事件的数据表示

小计划：

1. 定义原始事件结构 `RawEvent`
2. 定义归一化事件结构 `NormalizedEvent`
3. 定义 Incident 结构
4. 定义进程节点 `ProcessNode`
5. 定义 Ring0 Finding 结构
6. 定义 EDR Alert / EDR Event 结构

验收标准：

- 事件模型覆盖 Tracee、Ring0、EDR 三类来源
- 结构体字段可以支撑 UI、API、关联分析

### B3. 数据库 schema 设计

目标：

- 设计 SQLite schema，为采集、查询、导出服务

小计划：

1. 设计 `raw_events`
2. 设计 `processes`
3. 设计 `process_edges`
4. 设计 `file_events`
5. 设计 `network_events`
6. 设计 `incidents`
7. 设计 `ioc_hits`
8. 设计 `ring0_findings`
9. 设计 `edr_events`
10. 设计 `edr_alerts`
11. 设计 `reports`
12. 设计 `integration_jobs`

验收标准：

- schema 可以初始化成功
- 关键查询路径有索引

---

## 7. 阶段 C：主机事件采集与存储落库

### C1. Tracee 接入

目标：

- 把 Tracee 输出接入 Rust 引擎

小计划：

1. 确定 Tracee 输出格式
2. 确定 Tracee 启动参数和 policy
3. 编写 Tracee reader
4. 编写 JSON 事件解析器
5. 映射到内部 `RawEvent`
6. 批量写入 SQLite

验收标准：

- 执行普通命令后，数据库中可见进程事件
- 事件字段完整且能按时间排序

### C2. Ring0 巡检链路

目标：

- 建立本地主机可信度判断基础

小计划：

1. 封装 `bpftool` 差异检查
2. 封装 `unhide` 检查
3. 封装 `tainted` 检查
4. 封装 `/proc` vs `ps` 差异检查
5. 封装 `ss` vs `netstat` 差异检查
6. 统一写入 `ring0_findings`

验收标准：

- 能周期性产出 Ring0 巡检结果
- 巡检结果可供 API 查询

### C3. 蜜罐与专项增强

目标：

- 为已知 rootkit 行为增加低成本专项检测

小计划：

1. 实现 Mirror Trap 文件蜜罐
2. 设计是否启用 Ghost Port 的配置项
3. 把蜜罐命中写入 Ring0 findings

验收标准：

- Mirror Trap 可正常创建、检查、报警

---

## 8. 阶段 D：关联分析与信任体系

### D1. 进程血缘树构建

目标：

- 以进程为主线组织所有主机证据

小计划：

1. 处理 fork/exec/exit 事件
2. 构建 `ProcessTree`
3. 建立 parent/children 关系
4. 保存进程生命周期
5. 支持祖先链回溯
6. 支持后代链展开

验收标准：

- 给定 PID 能回溯父链
- 给定 PID 能枚举子链

### D2. 文件与网络关联

目标：

- 把主机行为和进程节点关联起来

小计划：

1. 关联文件事件到进程
2. 关联网络事件到进程
3. 标记敏感路径访问
4. 标记外联 IP
5. 标记横向移动线索

验收标准：

- 给定 PID 可看到其文件与网络行为

### D3. Incident 聚合

目标：

- 将离散事件归并成调查对象

小计划：

1. 定义 incident 生成规则
2. 以进程链和时间窗口聚合
3. 以 IOC 命中强化聚合
4. 以 Ring0 异常影响 incident 标记

验收标准：

- 多条关联事件能归并为同一 incident

### D4. TrustScore 与主机信任等级

目标：

- 为排序、告警和 deep 模式触发提供基础

小计划：

1. 定义进程 TrustScore 规则
2. 定义主机级信任等级 `L0-L3`
3. 将 Ring0 findings 映射到主机信任等级
4. 将主机信任等级反向影响 incident 风险

验收标准：

- 可疑进程具备可解释分数
- Ring0 异常会影响 incident 风险与证据权重

### D5. IOC 与攻击链推断

目标：

- 形成更高层的安全语义

小计划：

1. 导入硬 IOC
2. 导入软 IOC
3. 实现基本匹配逻辑
4. 实现 ATT&CK 阶段标注
5. 生成攻击剧本初版

验收标准：

- 能识别常见高价值命令链
- 能输出叙事化攻击步骤

---

## 9. 阶段 E：EDR 接口层与归一化

### E1. EDR 接入边界设计

目标：

- 建立稳定的外部事件接入接口

小计划：

1. 定义 adapter trait
2. 定义 webhook 接口
3. 定义 pull 任务接口
4. 定义 import 接口

验收标准：

- 接口层与核心关联引擎解耦

### E2. 归一化逻辑实现

目标：

- 把不同格式 EDR 数据映射到统一事件模型

小计划：

1. 定义字段映射规则
2. 解析厂商字段
3. 输出 `NormalizedEvent`
4. 保存原始 payload 引用

验收标准：

- 一类 EDR 样例数据可稳定入库

### E3. 参考适配器

目标：

- 至少完成一个参考 EDR 适配器

小计划：

1. 选定一个样例 EDR 事件格式
2. 实现 webhook 接收
3. 实现归一化
4. 写入 `edr_events` / `edr_alerts`
5. 提供 `edr test` 检查

验收标准：

- 能成功接收并查询一类 EDR 事件

### E4. EDR 与本地事件关联

目标：

- 让 EDR 成为补充证据，而不是孤立视图

小计划：

1. 按主机名、host_id、agent_id 对齐
2. 按 pid / process_guid 做弱关联
3. 按时间窗口做补充匹配
4. 将 EDR 告警挂接到 incident

验收标准：

- 在 incident 视图中可看到外部 EDR 证据

---

## 10. 阶段 F：CLI / API / Web 可视化

### F1. CLI 能力

目标：

- 提供统一命令行入口

小计划：

1. `serve`
2. `proc`
3. `net`
4. `file`
5. `hunt`
6. `export`
7. `replay`
8. `edr`

验收标准：

- CLI 可完成核心查询与运维动作

### F2. HTTP API

目标：

- 提供稳定的程序化访问方式

小计划：

1. `GET /api/proc/:pid`
2. `GET /api/net/:ip`
3. `GET /api/file`
4. `GET /api/incidents`
5. `GET /api/ring0`
6. `POST /api/v1/ingest/edr/{adapter}/alerts`
7. `POST /api/v1/ingest/edr/{adapter}/events`
8. `POST /api/v1/import/edr/{adapter}`
9. `GET /api/v1/integrations/edr`

验收标准：

- API 可被 CLI 和 Web 共用

### F3. Web 页面

目标：

- 形成可演示、可调查的可视化界面

小计划：

1. Incident 列表页
2. 攻击时间线页
3. 进程血缘图页
4. 网络关系图页
5. Ring0 状态页
6. EDR 关联页

验收标准：

- 能从 incident 页面进入完整调查视图

---

## 11. 阶段 G：报告、回放与导出

### G1. Markdown 报告导出

目标：

- 生成适合复盘和汇报的报告

小计划：

1. 设计报告模板
2. 输出事件摘要
3. 输出时间线
4. 输出进程图
5. 输出 ATT&CK 映射
6. 输出 Ring0 风险说明
7. 输出 EDR 关联证据摘要

验收标准：

- 单个 incident 可导出完整报告

### G2. 攻击剧本生成

目标：

- 让输出不仅能查，还能读

小计划：

1. 设计叙事模板
2. 按时间线生成攻击步骤
3. 插入主要进程、网络、文件动作

验收标准：

- 报告能用自然语言概括攻击链

### G3. 回放与导出增强

目标：

- 支撑对抗后复盘

小计划：

1. 设计 replay 输入输出格式
2. 支持按时间窗口回放
3. 设计取证包导出结构
4. 有余力时实现 zip 打包

验收标准：

- 至少支持事件回放或结构化导出之一

---

## 12. 阶段 H：联调、验证、收尾

### H1. 对抗场景验证

目标：

- 用真实攻击动作验证主链路

小计划：

1. 验证 `curl|bash`
2. 验证 `bash -i`
3. 验证 `nc` / `busybox nc`
4. 验证 cron 持久化
5. 验证 systemd 持久化

验收标准：

- 能在 UI 或报告中还原攻击链

### H2. Ring0 验证

目标：

- 验证可信降级与专项检测

小计划：

1. 验证 bpftool 差异链路
2. 验证 unhide 链路
3. 验证 tainted 检测
4. 验证 Mirror Trap

验收标准：

- Ring0 异常可见、可记录、可影响 incident 权重

### H3. EDR 验证

目标：

- 验证外部证据接入能力

小计划：

1. 导入一批样例 EDR 数据
2. 检查归一化表写入
3. 检查 incident 关联
4. 检查 `edr test` / `integration health`

验收标准：

- 至少一个 EDR 接口可演示接入

### H4. 部署与文档收尾

目标：

- 形成可运行、可交付状态

小计划：

1. 编写 systemd service
2. 编写启动脚本
3. 编写安装说明
4. 编写对抗操作手册
5. 编写 API 文档

验收标准：

- 新机器按文档可以完成部署

---

## 13. 建议执行顺序

建议严格按下面顺序推进：

1. A 环境准备
2. B 项目骨架与数据模型
3. C 主机事件采集与落库
4. D 关联分析与信任体系
5. E EDR 接口层
6. F CLI / API / Web
7. G 报告与导出
8. H 联调与收尾

原因：

- 没有统一事件模型，后面的 EDR 和 UI 都会反复返工
- 没有主机采集与落库，关联分析无法开始
- 没有 incident 和 TrustScore，UI 只会变成事件浏览器
- 没有 EDR 归一化层，后续厂商扩展会失控

---

## 14. 关键里程碑

### M1：底座完成

判定条件：

- Rust 工具链可用
- 项目骨架建立
- Tracee 事件能入库
- Ring0 巡检能入库

### M2：可查

判定条件：

- 进程树可构建
- 文件和网络可关联到 PID
- CLI 能查询 `proc/net/file/hunt`

### M3：可接

判定条件：

- EDR Webhook 可接收数据
- 至少一个参考适配器可归一化入库

### M4：可看

判定条件：

- UI 有 incident、timeline、proc graph、ring0、edr 视图

### M5：可交付

判定条件：

- 报告可导出
- 至少一条攻击链可完整复现
- 至少一个 EDR 接口可演示接入
- systemd 与文档可用

---

## 15. 每日执行映射

### Day 1 对应阶段

- A1
- A2
- A3
- B1
- B2
- B3
- C1 的最小闭环
- C2 的最小闭环

### Day 2 对应阶段

- C1 完整化
- C2 完整化
- C3
- D1
- D2
- D3
- D4
- E1
- E2

### Day 3 对应阶段

- D5
- E3
- E4
- F1
- F2
- F3
- G1
- G2

### Day 4 对应阶段

- G3
- H1
- H2
- H3
- H4

---

## 16. 阶段验收总表

### 必须完成

1. Tracee 入库
2. Ring0 巡检入库
3. 进程树构建
4. 文件/网络关联
5. Incident 聚合
6. TrustScore
7. EDR 接口接入
8. API + CLI
9. Web 关键页面
10. 报告导出

### 有余力完成

1. Replay
2. 取证包导出
3. Mirror Trap 强化
4. DNS 熵值检测
5. 文件投递传播链

---

## 17. 最终执行口径

这份 `Goal.md` 不是设计说明，而是执行清单。  
后续真正开始开发时，应按阶段逐项勾掉，而不是跳着做页面或先做增强功能。

优先级顺序始终保持：

1. 先让事件进来
2. 再让事件能关联
3. 再让事件能展示
4. 最后让事件能讲故事

