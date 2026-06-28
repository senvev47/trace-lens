function severityClass(severity) {
  if (severity >= 8) return "severity-high";
  if (severity >= 5) return "severity-medium";
  return "";
}

function trustClass(level) {
  return level && level !== "L0" ? "trust-low" : "";
}

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

function trustLevelLabel(level) {
  const labels = {
    L0: "零级信任",
    L1: "一级信任",
    L2: "二级信任",
    L3: "三级信任",
  };
  return labels[level] || level || "-";
}

async function loadDashboard() {
  const [incidentsRes, ring0Res] = await Promise.all([
    fetch("/api/v1/incidents"),
    fetch("/api/v1/ring0")
  ]);

  const incidents = await incidentsRes.json();
  const ring0 = await ring0Res.json();

  document.getElementById("incidentCount").textContent = incidents.length;
  document.getElementById("hostTrustLevel").textContent = trustLevelLabel(ring0.host_trust_level);
  document.getElementById("ring0Count").textContent = ring0.findings.length;
  document.getElementById("lastUpdated").textContent = `更新时间 ${new Date().toISOString()}`;

  const severityFilter = document.getElementById("severityFilter").value;
  const trustFilter = document.getElementById("trustFilter").value;
  const sortMode = document.getElementById("sortMode").value;

  let filtered = incidents.filter((incident) => {
    if (severityFilter !== "all" && incident.severity < Number(severityFilter)) {
      return false;
    }
    if (trustFilter === "L3" && incident.host_trust_level !== "L3") {
      return false;
    }
    if (trustFilter === "L2" && !["L2", "L3"].includes(incident.host_trust_level)) {
      return false;
    }
    if (trustFilter === "L1" && !["L1", "L2", "L3"].includes(incident.host_trust_level)) {
      return false;
    }
    return true;
  });

  filtered.sort((a, b) => {
    if (sortMode === "severity") {
      if (b.severity !== a.severity) return b.severity - a.severity;
      return b.observed_at - a.observed_at;
    }
    return b.observed_at - a.observed_at;
  });

  const list = document.getElementById("incidentList");
  list.innerHTML = "";

  if (!filtered.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "暂无事件。";
    list.appendChild(empty);
    return;
  }

  for (const incident of filtered) {
    const item = document.createElement("a");
    item.className = "incident-item";
    item.href = `/incident/${incident.pid}`;
    item.innerHTML = `
      <div class="incident-row">
        <div class="incident-title">${esc(translateIncidentText(incident.title))}</div>
        <span class="pill ${severityClass(incident.severity)}">严重度 ${incident.severity}</span>
        <span class="pill ${trustClass(incident.host_trust_level)}">${esc(trustLevelLabel(incident.host_trust_level))}</span>
        <span class="pill label-edr">终端检测 ${incident.edr_evidence_count}</span>
      </div>
      <div>${esc(translateIncidentText(incident.summary))}</div>
      <div class="incident-row panel-meta">
        <span>进程ID ${incident.pid}</span>
        <span>${esc(incident.root_exe_path || "-")}</span>
        <span>${formatTs(incident.observed_at)}</span>
      </div>
    `;
    list.appendChild(item);
  }
}

document.getElementById("refreshButton").addEventListener("click", loadDashboard);
document.getElementById("severityFilter").addEventListener("change", loadDashboard);
document.getElementById("trustFilter").addEventListener("change", loadDashboard);
document.getElementById("sortMode").addEventListener("change", loadDashboard);
loadDashboard().catch((error) => {
  console.error(error);
  const list = document.getElementById("incidentList");
  list.innerHTML = "";
  const empty = document.createElement("div");
  empty.className = "empty";
  empty.textContent = "事件加载失败。";
  list.appendChild(empty);
});
