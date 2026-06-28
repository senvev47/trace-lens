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

function eventLabel(value) {
  const labels = {
    tcp_connect: "TCP 连接",
    net_tcp_connect: "TCP 连接",
    udp_sendmsg: "UDP 发送",
    net_packet_dns_request: "DNS 查询",
  };
  return labels[value] || value || "-";
}

async function loadNet() {
  const target = document.getElementById("netTargetInput").value.trim();
  const response = await fetch(`/api/v1/net/${encodeURIComponent(target)}`);
  const data = await response.json();
  const list = document.getElementById("netLookupList");
  list.innerHTML = "";

  if (!data.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "暂无网络事件。";
    list.appendChild(empty);
    return;
  }

  for (const item of data) {
    const node = document.createElement("div");
    node.className = "stack-item";
    node.innerHTML = `
      <div class="incident-row">
        <div class="incident-title">${esc(item.remote_addr || "-")}:${item.remote_port || "-"}</div>
        <span class="pill label-network">${esc(eventLabel(item.event_name))}</span>
        <span class="pill ${item.lateral_movement_hint ? "label-lateral" : "label-network"}">${item.lateral_movement_hint ? "横向线索" : "已观测"}</span>
      </div>
      <div class="stack-row panel-meta">
        <span>进程ID ${item.pid}</span>
        <span>${formatTs(item.observed_at)}</span>
      </div>
    `;
    list.appendChild(node);
  }
}

document.getElementById("netSearchButton").addEventListener("click", loadNet);
loadNet().catch((error) => {
  console.error(error);
  const list = document.getElementById("netLookupList");
  list.innerHTML = "";
  const empty = document.createElement("div");
  empty.className = "empty";
  empty.textContent = "网络事件加载失败。";
  list.appendChild(empty);
});
