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

function findingLabel(value) {
  const labels = {
    ebpf_diff: "内核探针基线差异",
    tainted_kernel: "内核污染",
    hidden_process: "疑似隐藏进程",
    mirror_trap_hit: "文件蜜罐命中",
    ghost_port_hit: "端口蜜罐命中",
    bpftool_unavailable: "内核探针检查工具不可用",
    unhide_finding: "隐藏检测工具发现异常",
  };
  return labels[value] || value;
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

function detectorLabel(value) {
  const labels = {
    bpftool: "内核探针检查工具",
    unhide: "隐藏检测工具",
    cross_view: "跨视图检查",
    canary: "蜜罐检测",
  };
  return labels[value] || value || "-";
}

function summaryLabel(value) {
  return String(value ?? "")
    .replace(/no current ring0 findings/giu, "当前没有内核态发现")
    .replace(/multiple concurrent ring0 findings/giu, "存在多个并发内核态发现")
    .replace(/ via /gu, " 来自 ");
}

async function loadRing0() {
  const response = await fetch("/api/v1/ring0");
  const data = await response.json();

  document.getElementById("ring0TrustLevel").textContent = trustLevelLabel(data.host_trust_level);
  document.getElementById("ring0FindingCount").textContent = data.findings.length;

  const list = document.getElementById("ring0FindingList");
  list.innerHTML = "";
  if (!data.findings.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "暂无内核态发现。";
    list.appendChild(empty);
    return;
  }

  for (const item of data.findings) {
    const node = document.createElement("div");
    node.className = "stack-item";
    node.innerHTML = `
      <div class="incident-row">
        <div class="incident-title">${esc(findingLabel(item.finding_type))}</div>
        <span class="pill trust-low">${esc(trustLevelLabel(item.trust_level))}</span>
      </div>
      <div class="stack-row panel-meta">
        <span>${esc(detectorLabel(item.detector))}</span>
        <span>${formatTs(item.observed_at)}</span>
      </div>
      <div>${esc(summaryLabel(item.summary))}</div>
    `;
    list.appendChild(node);
  }
}

loadRing0().catch((error) => {
  console.error(error);
  const list = document.getElementById("ring0FindingList");
  list.innerHTML = "";
  const empty = document.createElement("div");
  empty.className = "empty";
  empty.textContent = "内核态发现加载失败。";
  list.appendChild(empty);
});
