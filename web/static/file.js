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
    sched_process_exec: "进程执行",
    security_file_open: "文件打开",
    openat: "文件打开",
    write: "文件写入",
    unlink: "文件删除",
    rename: "文件改名",
    chmod: "权限修改",
  };
  return labels[value] || value || "-";
}

async function loadFile() {
  const path = document.getElementById("filePathInput").value.trim();
  const [eventsResponse, chainResponse] = await Promise.all([
    fetch(`/api/v1/file?path=${encodeURIComponent(path)}`),
    fetch(`/api/v1/file-chain?path=${encodeURIComponent(path)}`),
  ]);
  const data = await eventsResponse.json();
  const chain = await chainResponse.json();
  const list = document.getElementById("fileLookupList");
  const chainList = document.getElementById("fileChainList");
  list.innerHTML = "";
  chainList.innerHTML = "";

  if (!data.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "暂无文件事件。";
    list.appendChild(empty);
  } else {
    for (const item of data) {
      const node = document.createElement("div");
      node.className = "stack-item";
      node.innerHTML = `
        <div class="incident-row">
          <div class="incident-title">${esc(item.file_path)}</div>
          <span class="pill label-file">${esc(eventLabel(item.event_name))}</span>
          <span class="pill ${item.sensitive ? "label-file" : ""}">${item.sensitive ? "敏感" : "已观测"}</span>
        </div>
        <div class="stack-row panel-meta">
          <span>进程ID ${item.pid}</span>
          <span>${esc(item.flags || "-")}</span>
          <span>${formatTs(item.observed_at)}</span>
        </div>
      `;
      list.appendChild(node);
    }
  }

  const writeCount = chain.write_events ? chain.write_events.length : 0;
  const execCount = chain.exec_events ? chain.exec_events.length : 0;

  if (!writeCount && !execCount) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "暂无传播链。";
    chainList.appendChild(empty);
    return;
  }

  const summary = document.createElement("div");
  summary.className = "stack-item";
  summary.innerHTML = `
    <div class="incident-row">
      <div class="incident-title">${esc(chain.path)}</div>
      <span class="pill label-file">写入 ${writeCount}</span>
      <span class="pill">执行 ${execCount}</span>
    </div>
  `;
  chainList.appendChild(summary);

  for (const item of chain.write_events || []) {
    const node = document.createElement("div");
    node.className = "stack-item";
    node.innerHTML = `
      <div class="incident-row">
        <div class="incident-title">进程ID ${item.pid} 写入</div>
        <span class="pill label-file">${eventLabel(item.event_name)}</span>
        <span class="pill">写入</span>
      </div>
      <div class="stack-row panel-meta">
        <span>父进程ID ${item.ppid ?? "-"}</span>
        <span>${esc(item.process_name || "-")}</span>
        <span>${esc(item.flags || "-")}</span>
        <span>${formatTs(item.observed_at)}</span>
      </div>
    `;
    chainList.appendChild(node);
  }

  for (const item of chain.exec_events || []) {
    const node = document.createElement("div");
    node.className = "stack-item";
    node.innerHTML = `
      <div class="incident-row">
        <div class="incident-title">进程ID ${item.pid} 执行</div>
        <span class="pill label-net">${eventLabel(item.event_name)}</span>
        <span class="pill">执行</span>
      </div>
      <div class="stack-row panel-meta">
        <span>父进程ID ${item.ppid ?? "-"}</span>
        <span>${esc(item.process_name || "-")}</span>
        <span>${esc(item.exe_path || "-")}</span>
        <span>${formatTs(item.observed_at)}</span>
      </div>
    `;
    chainList.appendChild(node);
  }
}

document.getElementById("fileSearchButton").addEventListener("click", loadFile);
loadFile().catch((error) => {
  console.error(error);
  const list = document.getElementById("fileLookupList");
  list.innerHTML = "";
  const empty = document.createElement("div");
  empty.className = "empty";
  empty.textContent = "文件事件加载失败。";
  list.appendChild(empty);
});
