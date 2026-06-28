function formatTs(value) {
  return new Date(value * 1000).toISOString();
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function translateIncidentText(value) {
  return String(value ?? "")
    .replace(/^Process incident for pid (\d+) \((.*)\)$/u, "进程事件 进程ID $1（$2）")
    .replace(/pid (\d+) executed (.+?)(;|$)/gu, "进程ID $1 执行 $2$3")
    .replace(/expanded incident scope to (\d+) descendant process\(es\)/gu, "事件范围扩展到 $1 个后代进程")
    .replace(/aggregated event window (\d+) -> (\d+)/gu, "聚合事件窗口 $1 -> $2")
    .replace(/accessed (\d+) sensitive file event\(s\)/gu, "访问 $1 个敏感文件事件")
    .replace(/opened (\d+) external network connection\(s\)/gu, "建立 $1 个外部网络连接")
    .replace(/showed (\d+) lateral movement network hint\(s\)/gu, "出现 $1 个横向移动网络线索")
    .replace(/issued (\d+) high-entropy dns query event\(s\)/gu, "发起 $1 个高熵 DNS 查询事件")
    .replace(/host has (\d+) ring0 finding\(s\) in current database/giu, "当前数据库中主机存在 $1 个内核态发现")
    .replace(/matched (\d+) IOC rule\(s\)/gu, "命中 $1 条威胁指标规则")
    .replace(/matched (\d+) EDR evidence item\(s\)/gu, "匹配 $1 条终端检测证据")
    .replace(/process trust score is (\d+) and host trust level is ([A-Z0-9]+)/gu, "进程信任分为 $1，主机信任等级为 $2");
}

function eventLabel(value) {
  const labels = {
    sched_process_exec: "进程执行",
    sched_process_fork: "进程派生",
    sched_process_exit: "进程退出",
    security_file_open: "文件打开",
    tcp_connect: "TCP 连接",
    net_tcp_connect: "TCP 连接",
    udp_sendmsg: "UDP 发送",
    net_packet_dns_request: "DNS 查询",
    memfd_create: "内存文件创建",
    ptrace: "进程调试",
  };
  return labels[value] || value || "-";
}

function trustLevelLabel(level) {
  const labels = {
    L0: "零级信任",
    L1: "一级信任",
    L2: "二级信任",
    L3: "三级信任",
  };
  return labels[level] || level || "-";
}

function boolLabel(value) {
  return value ? "是" : "否";
}

function timelineLabel(meta) {
  if (meta === "edr") return "终端检测";
  if (meta === "sensitive file") return "敏感文件";
  if (meta === "file") return "文件";
  if (meta === "lateral hint") return "横向线索";
  if (meta === "network") return "网络";
  return meta;
}

function timelinePillClass(meta) {
  if (meta === "edr") return "label-edr";
  if (meta === "sensitive file" || meta === "file") return "label-file";
  if (meta === "lateral hint") return "label-lateral";
  if (meta === "network") return "label-network";
  return "";
}

function renderStack(containerId, items, renderItem) {
  const container = document.getElementById(containerId);
  container.innerHTML = "";

  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "暂无数据。";
    container.appendChild(empty);
    return;
  }

  for (const item of items) {
    const node = document.createElement("div");
    node.className = "stack-item";
    node.innerHTML = renderItem(item);
    container.appendChild(node);
  }
}

function buildTimeline(data) {
  const timeline = [];

  for (const item of data.file_events) {
    timeline.push({
      ts: item.observed_at,
      title: item.event_name,
      detail: item.file_path,
      meta: item.sensitive ? "sensitive file" : "file"
    });
  }

  for (const item of data.network_events) {
    timeline.push({
      ts: item.observed_at,
      title: item.event_name,
      detail: `${item.remote_addr || "-"}:${item.remote_port || "-"}`,
      meta: item.lateral_movement_hint ? "lateral hint" : "network"
    });
  }

  for (const item of data.edr_evidence) {
    timeline.push({
      ts: item.observed_at,
      title: item.event_name,
      detail: item.alert_name || item.summary || item.vendor,
      meta: "edr"
    });
  }

  timeline.sort((a, b) => a.ts - b.ts);
  return timeline;
}

function buildNetworkTargets(data) {
  const targets = new Map();
  for (const item of data.network_events) {
    const key = `${item.remote_addr || "-"}:${item.remote_port || "-"}`;
    if (!targets.has(key)) {
      targets.set(key, {
        target: key,
        count: 0,
        lateral: false,
        external: false,
        firstSeen: item.observed_at,
        lastSeen: item.observed_at
      });
    }

    const current = targets.get(key);
    current.count += 1;
    current.lateral = current.lateral || item.lateral_movement_hint;
    current.external = current.external || item.external;
    current.firstSeen = Math.min(current.firstSeen, item.observed_at);
    current.lastSeen = Math.max(current.lastSeen, item.observed_at);
  }

  return Array.from(targets.values()).sort((a, b) => b.lastSeen - a.lastSeen);
}

async function loadIncident() {
  const pid = window.location.pathname.split("/").pop();
  const response = await fetch(`/api/v1/incidents/${pid}`);
  if (!response.ok) {
    throw new Error(`incident request failed: ${response.status}`);
  }

  const data = await response.json();

  document.getElementById("incidentTitle").textContent = translateIncidentText(data.title);
  document.getElementById("incidentSummary").textContent = translateIncidentText(data.summary);
  document.getElementById("severityValue").textContent = data.severity;
  document.getElementById("confidenceValue").textContent = data.confidence.toFixed(2);
  document.getElementById("detailHostTrustLevel").textContent = trustLevelLabel(data.host_trust_level);

  document.getElementById("processCard").innerHTML = `
    <div class="stack-item">
      <div class="incident-title">${esc(data.root_process.exe_path || "-")}</div>
      <div class="stack-row panel-meta">
        <span>进程ID ${data.root_process.pid}</span>
        <span>父进程ID ${data.root_process.ppid ?? "-"}</span>
        <span>${formatTs(data.root_process.start_time)}</span>
      </div>
      <div>${esc(data.root_process.cmdline || "-")}</div>
    </div>
  `;

  renderStack("ancestryList", data.ancestry, (item) => `
    <div class="incident-title">${esc(item.exe_path || "-")}</div>
    <div class="stack-row panel-meta">
      <span>进程ID ${item.pid}</span>
      <span>父进程ID ${item.ppid ?? "-"}</span>
      <span>${formatTs(item.start_time)}</span>
    </div>
    <div>${esc(item.cmdline || "-")}</div>
  `);

  renderStack("descendantList", data.descendants || [], (item) => `
    <div class="incident-title">${esc(item.exe_path || "-")}</div>
    <div class="stack-row panel-meta">
      <span>进程ID ${item.pid}</span>
      <span>父进程ID ${item.ppid ?? "-"}</span>
      <span>${formatTs(item.start_time)}</span>
    </div>
    <div>${esc(item.cmdline || "-")}</div>
  `);

  renderStack("edrEvidenceList", data.edr_evidence, (item) => `
    <div class="incident-row">
      <div class="incident-title">${esc(eventLabel(item.event_name))}</div>
      <span class="pill label-edr">严重度 ${item.severity ?? "-"}</span>
    </div>
    <div class="stack-row panel-meta">
      <span>${esc(item.vendor)}</span>
      <span>${esc(item.alert_name || "-")}</span>
      <span>${formatTs(item.observed_at)}</span>
    </div>
    <div>${esc(item.summary || "-")}</div>
  `);

  renderStack("fileActivityList", data.file_events, (item) => `
    <div class="incident-row">
      <div class="incident-title">${esc(item.file_path)}</div>
      <span class="pill label-file">${esc(eventLabel(item.event_name))}</span>
      <span class="pill ${item.sensitive ? "label-file" : ""}">${item.sensitive ? "敏感" : "已观测"}</span>
    </div>
    <div class="stack-row panel-meta">
      <span>${esc(item.flags || "-")}</span>
      <span>${formatTs(item.observed_at)}</span>
    </div>
  `);

  renderStack("networkActivityList", data.network_events, (item) => `
    <div class="incident-row">
      <div class="incident-title">${esc(item.remote_addr || "-")}:${item.remote_port || "-"}</div>
      <span class="pill label-network">${esc(eventLabel(item.event_name))}</span>
      <span class="pill ${item.lateral_movement_hint ? "label-lateral" : "label-network"}">${item.lateral_movement_hint ? "横向线索" : "已观测"}</span>
    </div>
    <div class="stack-row panel-meta">
      <span>外部=${boolLabel(item.external)}</span>
      <span>${formatTs(item.observed_at)}</span>
    </div>
  `);

  renderStack("networkTargetList", buildNetworkTargets(data), (item) => `
    <div class="incident-row">
      <div class="incident-title">${esc(item.target)}</div>
      <span class="pill label-network">${item.count} 个事件</span>
      <span class="pill ${item.lateral ? "label-lateral" : "label-network"}">${item.lateral ? "横向线索" : (item.external ? "外部" : "内部")}</span>
    </div>
    <div class="stack-row panel-meta">
      <span>首次 ${formatTs(item.firstSeen)}</span>
      <span>最近 ${formatTs(item.lastSeen)}</span>
    </div>
  `);

  renderStack("timelineList", buildTimeline(data), (item) => `
    <div class="incident-row">
      <div class="incident-title">${esc(eventLabel(item.title))}</div>
      <span class="pill ${timelinePillClass(item.meta)}">${esc(timelineLabel(item.meta))}</span>
    </div>
    <div class="stack-row panel-meta">
      <span>${formatTs(item.ts)}</span>
    </div>
    <div>${esc(item.detail)}</div>
  `);

  document.getElementById("processGraph").textContent = data.process_graph_mermaid || "暂无进程图";
}

loadIncident().catch((error) => {
  console.error(error);
  document.getElementById("incidentSummary").textContent = "事件加载失败。";
});
