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

function healthLabel(value) {
  if (value === "ready") return "就绪";
  return value || "-";
}

function eventLabel(value) {
  const labels = {
    sched_process_exec: "进程执行",
    sched_process_fork: "进程派生",
    sched_process_exit: "进程退出",
    security_file_open: "文件打开",
    tcp_connect: "TCP 连接",
    net_tcp_connect: "TCP 连接",
    net_packet_dns_request: "DNS 查询",
    generic_edr: "通用终端检测事件",
  };
  return labels[value] || value || "-";
}

async function loadEDR() {
  const [integrationsRes, eventsRes, alertsRes] = await Promise.all([
    fetch("/api/v1/integrations/edr"),
    fetch("/api/v1/edr/events"),
    fetch("/api/v1/edr/alerts")
  ]);

  const integrations = await integrationsRes.json();
  const events = await eventsRes.json();
  const alerts = await alertsRes.json();

  document.getElementById("adapterCount").textContent = integrations.length;
  document.getElementById("edrEventCount").textContent = events.length;
  document.getElementById("edrAlertCount").textContent = alerts.length;

  renderList("adapterList", integrations, (item) => `
    <div class="incident-title">${esc(item.adapter_name)}</div>
    <div class="stack-row panel-meta">
      <span>${esc(healthLabel(item.health))}</span>
      <span>${esc(item.webhook_path)}</span>
    </div>
  `);

  renderList("alertList", alerts, (item) => `
    <div class="incident-row">
      <div class="incident-title">${esc(item.alert_name)}</div>
      <span class="pill label-edr">严重度 ${item.severity}</span>
    </div>
    <div class="stack-row panel-meta">
      <span>${esc(item.vendor)}</span>
      <span>进程ID ${item.pid ?? "-"}</span>
      <span>${formatTs(item.observed_at)}</span>
    </div>
  `);

  renderList("eventList", events, (item) => `
    <div class="incident-row">
      <div class="incident-title">${esc(eventLabel(item.event_name))}</div>
      <span class="pill label-edr">严重度 ${item.severity ?? "-"}</span>
    </div>
    <div class="stack-row panel-meta">
      <span>${esc(item.vendor)}</span>
      <span>进程ID ${item.pid ?? "-"}</span>
      <span>${formatTs(item.observed_at)}</span>
    </div>
  `);
}

function renderList(containerId, items, renderItem) {
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

loadEDR().catch((error) => {
  console.error(error);
  const container = document.getElementById("adapterList");
  container.innerHTML = "";
  const empty = document.createElement("div");
  empty.className = "empty";
  empty.textContent = "适配器加载失败。";
  container.appendChild(empty);
});
