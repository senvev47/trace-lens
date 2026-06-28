# Todo.md

> 用途：Trace Lens 项目执行任务板  
> 来源：由 Goal.md 拆解而来  
> 规则：  
> - `[ ]` 未开始  
> - `[-]` 进行中  
> - `[x]` 已完成  
> - 每个阶段先完成“阶段验收”，再进入下个阶段

---

## 0. 全局约束

- [x] G-01 保持第一阶段范围稳定，不引入多厂商深度 EDR SDK
- [x] G-02 不启动分布式多主机、SIEM、复杂图数据库工作
- [x] G-03 不自研全套 eBPF 传感器，优先复用 Tracee
- [x] G-04 不做自动内存转储与逐事件哈希链
- [x] G-05 默认关闭 Ghost Port，仅保留配置入口

---

## 1. 阶段 A：环境与基础设施准备

### A1. 系统能力确认

- [x] A1-01 记录 Ubuntu 版本
- [x] A1-02 记录内核版本
- [x] A1-03 检查 `/sys/kernel/btf/vmlinux`
- [x] A1-04 检查 `bpftool` 可用性
- [x] A1-05 检查 `bpftrace` 可用性
- [x] A1-06 输出环境检查结果到文档或日志

### A2. Rust 工具链安装

- [x] A2-01 安装 `build-essential`
- [x] A2-02 安装 `clang`
- [x] A2-03 安装 `llvm`
- [x] A2-04 安装 `pkg-config`
- [x] A2-05 安装 `libsqlite3-dev`
- [x] A2-06 安装 `libelf-dev`
- [x] A2-07 安装 `rustup`
- [x] A2-08 安装稳定版 Rust
- [x] A2-09 验证 `rustc --version`
- [x] A2-10 验证 `cargo --version`

### A3. 第三方工具准备

- [x] A3-01 安装或准备 Tracee
- [x] A3-02 安装 `sqlite3`
- [x] A3-03 安装 `graphviz`
- [x] A3-04 安装 `unhide`
- [x] A3-05 确认前端静态资源接入方式

### 阶段 A 验收

- [x] A-AC-01 Tracee 可执行
- [x] A-AC-02 Rust 工具链可执行
- [x] A-AC-03 SQLite CLI 可执行
- [x] A-AC-04 Graphviz 可执行
- [x] A-AC-05 Unhide 可执行

---

## 2. 阶段 B：项目骨架与统一数据模型

依赖：

- 依赖阶段 A 完成

### B1. Rust 项目初始化

- [x] B1-01 初始化 `Cargo.toml`
- [x] B1-02 创建 `src/main.rs`
- [x] B1-03 创建 `src/app.rs`
- [x] B1-04 创建 `src/cli/`
- [x] B1-05 创建 `src/api/`
- [x] B1-06 创建 `src/collector/`
- [x] B1-07 创建 `src/connectors/`
- [x] B1-08 创建 `src/engine/`
- [x] B1-09 创建 `src/model/`
- [x] B1-10 创建 `src/storage/`
- [x] B1-11 创建 `web/templates/`
- [x] B1-12 创建 `web/static/`
- [x] B1-13 创建 `configs/`
- [x] B1-14 创建 `db/`
- [x] B1-15 创建 `systemd/`
- [x] B1-16 让 `cargo build` 最小通过

### B2. 统一事件模型设计

- [x] B2-01 定义 `RawEvent`
- [x] B2-02 定义 `NormalizedEvent`
- [x] B2-03 定义 `Incident`
- [x] B2-04 定义 `ProcessNode`
- [x] B2-05 定义 `Ring0Finding`
- [x] B2-06 定义 `EDRAlert`
- [x] B2-07 定义 `EDREvent`
- [x] B2-08 明确 Tracee -> RawEvent 映射
- [x] B2-09 明确 EDR -> NormalizedEvent 映射

### B3. 数据库 schema 设计

- [x] B3-01 设计 `raw_events`
- [x] B3-02 设计 `processes`
- [x] B3-03 设计 `process_edges`
- [x] B3-04 设计 `file_events`
- [x] B3-05 设计 `network_events`
- [x] B3-06 设计 `incidents`
- [x] B3-07 设计 `ioc_hits`
- [x] B3-08 设计 `ring0_findings`
- [x] B3-09 设计 `edr_events`
- [x] B3-10 设计 `edr_alerts`
- [x] B3-11 设计 `reports`
- [x] B3-12 设计 `integration_jobs`
- [x] B3-13 为关键查询添加索引
- [x] B3-14 验证 schema 初始化成功

### 阶段 B 验收

- [x] B-AC-01 项目骨架完整
- [x] B-AC-02 `cargo build` 可通过
- [x] B-AC-03 统一事件模型可支撑 Tracee / Ring0 / EDR
- [x] B-AC-04 SQLite schema 可初始化

---

## 3. 阶段 C：主机事件采集与存储落库

依赖：

- 依赖阶段 B 完成

### C1. Tracee 接入

- [x] C1-01 确定 Tracee 输出格式
- [x] C1-02 确定 Tracee 启动方式
- [x] C1-03 生成或编写 Tracee policy
- [x] C1-04 实现 Tracee reader
- [x] C1-05 实现 Tracee JSON parser
- [x] C1-06 映射 Tracee 事件到 `RawEvent`
- [x] C1-07 实现批量写库逻辑
- [x] C1-08 验证普通命令触发事件入库

### C2. Ring0 巡检链路

- [x] C2-01 封装 `bpftool` 差异检查
- [x] C2-02 封装 `unhide` 检查
- [x] C2-03 封装 `tainted` 检查
- [x] C2-04 封装 `/proc` vs `ps` 差异检查
- [x] C2-05 封装 `ss` vs `netstat` 差异检查
- [x] C2-06 统一输出为 `Ring0Finding`
- [x] C2-07 写入 `ring0_findings`
- [x] C2-08 建立周期巡检调度

### C3. 蜜罐与专项增强

- [x] C3-01 设计 Mirror Trap 路径
- [x] C3-02 实现 Mirror Trap 创建
- [x] C3-03 实现 Mirror Trap 检查
- [x] C3-04 Mirror Trap 命中写入 findings
- [x] C3-05 设计 Ghost Port 配置项

### 阶段 C 验收

- [x] C-AC-01 Tracee 事件可持续入库
- [x] C-AC-02 Ring0 巡检结果可持续入库
- [x] C-AC-03 普通命令执行可生成主链路事件
- [x] C-AC-04 Mirror Trap 可创建并检查

---

## 4. 阶段 D：关联分析与信任体系

依赖：

- 依赖阶段 C 完成

### D1. 进程血缘树构建

- [x] D1-01 处理 fork 事件
- [x] D1-02 处理 exec 事件
- [x] D1-03 处理 exit 事件
- [x] D1-04 构建 `ProcessTree`
- [x] D1-05 建立 parent 映射
- [x] D1-06 建立 children 映射
- [x] D1-07 保存进程生命周期
- [x] D1-08 实现祖先链查询
- [x] D1-09 实现后代链查询

### D2. 文件与网络关联

- [x] D2-01 关联文件事件到 PID
- [x] D2-02 关联网络事件到 PID
- [x] D2-03 标记敏感文件访问
- [x] D2-04 标记外联 IP
- [x] D2-05 标记横向移动线索

### D3. Incident 聚合

- [x] D3-01 定义 incident 聚合规则
- [x] D3-02 实现按进程链聚合
- [x] D3-03 实现按时间窗口聚合
- [x] D3-04 实现 IOC 强化聚合
- [x] D3-05 实现 Ring0 异常影响 incident 标记

### D4. TrustScore 与主机信任等级

- [x] D4-01 定义进程 TrustScore 规则
- [x] D4-02 定义主机信任等级 `L0-L3`
- [x] D4-03 将 Ring0 findings 映射到主机信任等级
- [x] D4-04 将主机信任等级影响 incident 风险
- [x] D4-05 为进程节点输出可解释评分原因

### D5. IOC 与攻击链推断

- [x] D5-01 设计硬 IOC 导入格式
- [x] D5-02 设计软 IOC 导入格式
- [x] D5-03 实现 IOC 匹配
- [x] D5-04 实现 ATT&CK 阶段标注
- [x] D5-05 实现攻击剧本初版生成

### 阶段 D 验收

- [x] D-AC-01 给定 PID 可回溯父链和子链
- [x] D-AC-02 给定 PID 可看到文件与网络动作
- [x] D-AC-03 多条事件可归并为 incident
- [x] D-AC-04 TrustScore 和主机信任等级可工作
- [x] D-AC-05 能输出初版攻击剧本

---

## 5. 阶段 E：EDR 接口层与归一化

依赖：

- 依赖阶段 B 完成
- 建议在阶段 D 基本完成后推进关联接入

### E1. 接口边界设计

- [x] E1-01 定义 adapter trait
- [x] E1-02 定义 webhook 接口规范
- [x] E1-03 定义 pull 接口规范
- [x] E1-04 定义 import 接口规范
- [x] E1-05 设计 adapter 注册机制

### E2. 归一化逻辑实现

- [x] E2-01 设计字段映射规则
- [x] E2-02 解析厂商原始字段
- [x] E2-03 输出 `NormalizedEvent`
- [x] E2-04 保存原始 payload 引用
- [x] E2-05 写入 `edr_events`
- [x] E2-06 写入 `edr_alerts`

### E3. 参考适配器

- [x] E3-01 选定一个样例 EDR 事件格式
- [x] E3-02 实现 webhook 接收
- [x] E3-03 实现该格式归一化
- [x] E3-04 提供 `edr test`
- [x] E3-05 提供基础健康检查

### E4. EDR 与本地事件关联

- [x] E4-01 按 `host_id` / `agent_id` / `hostname` 关联
- [x] E4-02 按 `pid` / `process_guid` 弱关联
- [x] E4-03 按时间窗口补充匹配
- [x] E4-04 将 EDR 告警挂接到 incident
- [x] E4-05 当主机信任等级降低时提升 EDR 权重

### 阶段 E 验收

- [x] E-AC-01 至少一类 EDR JSON 可入库
- [x] E-AC-02 `edr test` 可运行
- [x] E-AC-03 incident 视图可看到外部 EDR 证据

---

## 6. 阶段 F：CLI / API / Web 可视化

依赖：

- 依赖阶段 C、D、E 的核心能力

### F1. CLI

- [x] F1-01 实现 `serve`
- [x] F1-02 实现 `proc`
- [x] F1-03 实现 `net`
- [x] F1-04 实现 `file`
- [x] F1-05 实现 `hunt`
- [x] F1-06 实现 `export`
- [x] F1-07 实现 `replay`
- [x] F1-08 实现 `edr`
- [x] F1-09 为 CLI 输出添加 JSON 模式

### F2. HTTP API

- [x] F2-01 实现 `GET /api/proc/:pid`
- [x] F2-02 实现 `GET /api/net/:ip`
- [x] F2-03 实现 `GET /api/file`
- [x] F2-04 实现 `GET /api/incidents`
- [x] F2-05 实现 `GET /api/ring0`
- [x] F2-06 实现 `POST /api/v1/ingest/edr/{adapter}/alerts`
- [x] F2-07 实现 `POST /api/v1/ingest/edr/{adapter}/events`
- [x] F2-08 实现 `POST /api/v1/import/edr/{adapter}`
- [x] F2-09 实现 `GET /api/v1/integrations/edr`

### F3. Web 页面

- [x] F3-01 完成 Incident 列表页
- [x] F3-02 完成攻击时间线页
- [x] F3-03 完成进程血缘图页
- [x] F3-04 完成网络关系图页
- [x] F3-05 完成 Ring0 状态页
- [x] F3-06 完成 EDR 关联页
- [x] F3-07 为图谱加入证据等级颜色

### F4. 调查页补充

- [x] F4-01 完成 Network 查询页
- [x] F4-02 完成 File 查询页
- [x] F4-03 Incident 列表支持前端筛选
- [x] F4-04 Incident 列表支持前端排序

### 阶段 F 验收

- [x] F-AC-01 CLI 可完成核心查询
- [x] F-AC-02 API 可被 CLI 与 Web 共用
- [x] F-AC-03 可从 incident 进入完整调查视图

---

## 7. 阶段 G：报告、回放与导出

依赖：

- 依赖阶段 D、E、F 完成主链路

### G1. Markdown 报告导出

- [x] G1-01 设计 Markdown 模板
- [x] G1-02 输出事件摘要
- [x] G1-03 输出时间线
- [x] G1-04 输出进程图
- [x] G1-05 输出 ATT&CK 映射
- [x] G1-06 输出 Ring0 风险说明
- [x] G1-07 输出 EDR 关联证据摘要

### G2. 攻击剧本生成

- [x] G2-01 设计叙事模板
- [x] G2-02 按时间线生成剧本
- [x] G2-03 插入关键进程动作
- [x] G2-04 插入关键网络动作
- [x] G2-05 插入关键文件动作

### G3. 回放与导出增强

- [x] G3-01 设计 replay 输入输出格式
- [x] G3-02 实现按时间窗口回放
- [x] G3-03 设计取证包目录结构
- [x] G3-04 评估 zip 打包是否纳入第一阶段

### 阶段 G 验收

- [x] G-AC-01 单个 incident 可导出完整报告
- [x] G-AC-02 报告可读且包含叙事化剧本
- [x] G-AC-03 至少支持回放或结构化导出之一

---

## 8. 阶段 H：联调、验证、收尾

依赖：

- 依赖前面所有阶段

### H1. 对抗场景验证

- [x] H1-01 验证 `curl|bash`
- [x] H1-02 验证 `bash -i`
- [x] H1-03 验证 `nc`
- [x] H1-04 验证 `busybox nc`
- [x] H1-05 验证 cron 持久化
- [x] H1-06 验证 systemd 持久化

### H2. Ring0 验证

- [x] H2-01 验证 bpftool 差异链路
- [x] H2-02 验证 unhide 链路
- [x] H2-03 验证 tainted 检测
- [x] H2-04 验证 Mirror Trap

### H3. EDR 验证

- [x] H3-01 导入样例 EDR 数据
- [x] H3-02 检查归一化表写入
- [x] H3-03 检查 incident 关联
- [x] H3-04 检查 `edr test`
- [x] H3-05 检查 `integration health`

### H4. 部署与文档收尾

- [x] H4-01 编写 systemd service
- [x] H4-02 编写启动脚本
- [x] H4-03 编写安装说明
- [x] H4-04 编写对抗操作手册
- [x] H4-05 编写 API 文档

### 阶段 H 验收

- [x] H-AC-01 UI 或报告中可还原至少一条攻击链
- [x] H-AC-02 Ring0 异常可见、可记录、可影响 incident
- [x] H-AC-03 至少一个 EDR 接口可演示接入
- [x] H-AC-04 新机器按文档可完成部署

---

## 9. 关键里程碑

- [x] M1 底座完成
  - 条件：Rust 工具链可用、项目骨架建立、Tracee 入库、Ring0 入库

- [x] M2 可查
  - 条件：进程树可构建、文件和网络可关联、CLI 可查 `proc/net/file/hunt`

- [x] M3 可接
  - 条件：EDR Webhook 可接收、参考适配器可归一化入库

- [x] M4 可看
  - 条件：UI 有 incident、timeline、proc graph、ring0、edr 视图

- [x] M5 可交付
  - 条件：报告可导出、攻击链可复现、EDR 可演示接入、systemd 与文档可用

---

## 10. 每日任务映射

### Day 1

- [ ] D1-PLAN 完成阶段 A
- [ ] D1-PLAN 完成阶段 B
- [ ] D1-PLAN 完成 C1 最小闭环
- [ ] D1-PLAN 完成 C2 最小闭环

### Day 2

- [ ] D2-PLAN 完成阶段 C
- [ ] D2-PLAN 完成阶段 D 的 D1-D4
- [ ] D2-PLAN 完成阶段 E 的 E1-E2

### Day 3

- [ ] D3-PLAN 完成 D5
- [ ] D3-PLAN 完成 E3-E4
- [ ] D3-PLAN 完成阶段 F
- [ ] D3-PLAN 完成 G1-G2

### Day 4

- [ ] D4-PLAN 完成 G3
- [ ] D4-PLAN 完成阶段 H
- [ ] D4-PLAN 冲刺 M5

---

## 11. 必须完成项

- [x] MUST-01 Tracee 入库
- [x] MUST-02 Ring0 巡检入库
- [x] MUST-03 进程树构建
- [x] MUST-04 文件/网络关联
- [x] MUST-05 Incident 聚合
- [x] MUST-06 TrustScore
- [x] MUST-07 EDR 接口接入
- [x] MUST-08 API + CLI
- [x] MUST-09 Web 关键页面
- [x] MUST-10 报告导出

---

## 12. 有余力完成项

- [x] NICE-01 Replay
- [x] NICE-02 取证包导出
- [x] NICE-03 Mirror Trap 强化
- [x] NICE-04 DNS 熵值检测
- [x] NICE-05 文件投递传播链

---

## 13. 使用方式

- [ ] U-01 每开始一个阶段，把对应验收项移动为进行中
- [ ] U-02 每完成一个子任务，立即在这里打勾
- [ ] U-03 不跳过阶段验收直接进入下一阶段
- [ ] U-04 每天结束时更新 Day 任务映射区
- [ ] U-05 若新增任务，优先挂到现有阶段下，不要破坏主顺序
