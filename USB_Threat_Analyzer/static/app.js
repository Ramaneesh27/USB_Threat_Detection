/**
 * USB Threat Analyzer - frontend controller.
 * Polls the Flask JSON API and drives every live element of the
 * single-page Glassmorphism dashboard: USB status, per-level counters,
 * the results table, quarantine actions, sandbox launches, and history.
 */

const POLL_INTERVAL_MS = 1500;
// Files scoring this or higher are quarantined automatically (set by the server from config.py).
const AUTO_QUARANTINE_THRESHOLD = Number(document.body.dataset.autoThreshold) || 75;
window.__activeView = "dashboard";   // read by the desktop shell to route drag & drop
let currentScanId = null;
let currentSandboxItemId = null;
let currentSandboxTarget = null;
let selectedSandboxFile = null;
let selectedSandboxPath = null;

function $(id) { return document.getElementById(id); }

function showToast(message, isError = false) {
  const toast = $("toast");
  toast.textContent = message;
  toast.style.color = isError ? "#ff5470" : "";
  toast.classList.remove("hidden");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => toast.classList.add("hidden"), 3500);
}

function fmtBytes(n) {
  if (!n && n !== 0) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${units[i]}`;
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function levelForScore(score) {
  return score >= 80 ? "Critical" : score >= 60 ? "High" : score >= 30 ? "Medium" : "Low";
}

// ---------------------------------------------------------------------
// "Why was this flagged?" panels (shared by Scan Results and Quarantine)
// ---------------------------------------------------------------------
const CATEGORY_CLASS = {
  "Signature match": "sig", "Heuristic": "heur", "Behavior indicator": "beh", "Note": "note",
};

/** "manual" if the user quarantined the item by hand, otherwise "auto" (risk score rule). */
function quarantineMode(item) {
  const mode = item.quarantine_mode || item.source;
  if (mode === "manual" || mode === "auto") return mode;
  if ((item.reasons || []).some(r => /quarantined manually/i.test(r))) return "manual";
  return (item.risk_score ?? 0) >= AUTO_QUARANTINE_THRESHOLD ? "auto" : "manual";
}

/**
 * Builds the explanation panel for one file. `item` needs risk_score and, ideally,
 * explanations[] (structured) - rows saved by older versions only have reasons[].
 * Every string is escaped: names inside evidence come from the scanned drive.
 */
function renderWhyPanel(item) {
  const score = item.risk_score ?? 0;
  const level = item.risk_level || levelForScore(score);
  const ex = item.explanations || [];
  const scored = ex.filter(e => e.points > 0);

  let intro;
  if (scored.length) {
    const total = scored.reduce((n, e) => n + e.points, 0);
    intro = `Rated <strong>${escapeHtml(level)}</strong> (${score}/100) because ${scored.length} `
      + `indicator${scored.length === 1 ? "" : "s"} matched`
      + (total > 100 ? " (score is capped at 100)" : "")
      + `. These are risk indicators, not a confirmed malware verdict.`;
  } else if (ex.length || (item.reasons || []).length) {
    intro = `Rated <strong>${escapeHtml(level)}</strong> (${score}/100).`;
  } else {
    intro = `Rated <strong>${escapeHtml(level)}</strong> (${score}/100). No risk indicators were found.`;
  }
  if (item.quarantined || item.status === "quarantined") {
    intro += quarantineMode(item) === "manual"
      ? " You quarantined this file manually."
      : ` This file was moved to quarantine automatically because its score reached ${AUTO_QUARANTINE_THRESHOLD} or more.`;
  }

  let body;
  if (ex.length) {
    body = ex.map(e => `
      <div class="why-item">
        <div class="why-head">
          <span class="why-cat ${CATEGORY_CLASS[e.category] || "heur"}">${escapeHtml(e.category)}</span>
          <strong>${escapeHtml(e.title)}</strong>
          ${e.points ? `<span class="why-points">+${e.points}</span>` : ""}
        </div>
        ${e.detail ? `<p class="why-detail">${escapeHtml(e.detail)}</p>` : ""}
        ${(e.evidence || []).length
          ? `<ul class="why-evidence">${e.evidence.map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ul>` : ""}
        ${e.why ? `<p class="why-meaning">${escapeHtml(e.why)}</p>` : ""}
      </div>`).join("");
  } else {
    // Scan saved before structured explanations existed: show the plain reasons.
    body = (item.reasons || []).map(r => `<div class="why-item"><p class="why-detail">${escapeHtml(r)}</p></div>`).join("");
  }
  return `<div class="why-panel"><p class="why-intro">${intro}</p>${body}</div>`;
}

/** One-line headline reason: the highest-scoring indicator. */
function primaryReason(item) {
  const scored = (item.explanations || []).filter(e => e.points > 0);
  if (!scored.length) return "";
  const top = scored.reduce((a, b) => (b.points > a.points ? b : a));
  return `${top.title}${top.detail ? " - " + top.detail : ""}`;
}

// ---------------------------------------------------------------------
// USB status + scan progress
// ---------------------------------------------------------------------
async function pollStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    renderUsbList(data.connected_devices || []);
    renderMonitorPill(data.active_scan);

    if (data.active_scan) {
      currentScanId = data.active_scan;
      renderProgress(data.progress);
      loadFindings(currentScanId);
    } else {
      $("scanProgressWrap").classList.add("hidden");
      if (currentScanId) {
        $("genReportBtn").disabled = false;
      }
    }
  } catch (err) {
    console.error("status poll failed", err);
  }
}

function renderMonitorPill(activeScan) {
  const pill = $("monitorState");
  if (activeScan) {
    pill.classList.add("scanning");
    pill.querySelector(".label").textContent = "Scan in progress\u2026";
  } else {
    pill.classList.remove("scanning");
    pill.querySelector(".label").textContent = "Watching for USB devices\u2026";
  }
}

function renderUsbList(devices) {
  const el = $("usbList");
  if (!devices.length) {
    el.innerHTML = `<p class="empty-hint">No removable drive connected. Insert a USB device to begin an automatic scan.</p>`;
    return;
  }
  el.innerHTML = devices.map(d => `
    <div class="usb-item">
      <div><span>USB Name</span>${escapeHtml(d.label)}</div>
      <div><span>Drive</span>${escapeHtml(d.drive_letter)}</div>
      <div><span>Capacity</span>${escapeHtml(d.capacity_human)}</div>
      <div><span>File System</span>${escapeHtml(d.file_system)}</div>
      <div><span>Connected</span>${escapeHtml(d.connected_time)}</div>
    </div>
  `).join("");
}

function renderProgress(progress) {
  const wrap = $("scanProgressWrap");
  if (!progress || !progress.total) { wrap.classList.add("hidden"); return; }
  wrap.classList.remove("hidden");
  const pct = progress.total ? Math.round((progress.done / progress.total) * 100) : 0;
  $("progressBar").style.width = pct + "%";
  $("progressCount").textContent = `${progress.done} / ${progress.total}`;
  $("progressFile").textContent = progress.current_file || "";
}

// ---------------------------------------------------------------------
// Findings / results table + per-level counters
// ---------------------------------------------------------------------
async function loadFindings(scanId) {
  try {
    const res = await fetch(`/api/scan/${scanId}/findings`);
    const data = await res.json();
    renderResults(data.findings || []);
  } catch (err) {
    console.error("findings load failed", err);
  }
}

function riskBadge(level, score) {
  const safeLevel = level || "Low";
  return `<span class="risk-badge ${safeLevel}">${score} \u00b7 ${safeLevel}</span>`;
}

let lastFindings = [];
const expandedFindings = new Set();   // keys of rows whose "Why?" panel is open (survives polling)
const findingKey = f => f.absolute_path || f.file_name;

function renderResults(findings) {
  lastFindings = findings;
  const body = $("resultsBody");
  if (!findings.length) {
    body.innerHTML = `<tr><td colspan="5" class="empty-hint">No files scanned yet.</td></tr>`;
    return;
  }

  let l1 = 0, l1f = 0, l2 = 0, l2f = 0, l3 = 0, l3f = 0;
  findings.forEach(f => {
    if (f.level === 1) { l1++; if (f.risk_score >= 30) l1f++; }
    if (f.level === 2) { l2++; if (f.risk_score >= 30) l2f++; }
    if (f.level === 3) { l3++; if (f.risk_score >= 30) l3f++; }
  });
  $("l1Count").textContent = l1; $("l1Flagged").textContent = l1f;
  $("l2Count").textContent = l2; $("l2Flagged").textContent = l2f;
  $("l3Count").textContent = l3; $("l3Flagged").textContent = l3f;

  const sorted = [...findings].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
  body.innerHTML = sorted.slice(0, 200).map(f => {
    const key = findingKey(f);
    const open = expandedFindings.has(key);
    const hasWhy = (f.explanations || []).length || (f.reasons || []).length;
    const flagged = (f.risk_score || 0) >= 30;
    const chips = (f.explanations || []).filter(e => e.points > 0).map(e =>
      `<span class="reason-chip">${escapeHtml(e.title)} <em>+${e.points}</em></span>`).join("");
    const headline = flagged ? primaryReason(f) : "";
    const reasonsCell = chips
      ? `<div class="chip-row">${chips}</div>${headline ? `<div class="why-headline">${escapeHtml(headline)}</div>` : ""}`
      : escapeHtml((f.reasons || []).slice(0, 3).join("; ") || "None");
    return `
    <tr class="${flagged ? "flagged-row" : ""}">
      <td>${escapeHtml(f.file_name)}<br><span class="reasons-cell">${escapeHtml(fmtBytes(f.size_bytes))}</span></td>
      <td>L${f.level ?? "-"}</td>
      <td>${riskBadge(f.risk_level, f.risk_score)}</td>
      <td class="reasons-cell">${reasonsCell}
        ${hasWhy ? `<button class="why-btn" data-key="${escapeHtml(key)}">${open ? "Hide details" : (flagged ? "Why flagged?" : "Details")}</button>` : ""}
      </td>
      <td>${f.quarantined ? `<span class="reasons-cell">Quarantined (${quarantineMode(f)})</span>` : ""}</td>
    </tr>
    ${open ? `<tr class="why-row"><td colspan="5">${renderWhyPanel(f)}</td></tr>` : ""}`;
  }).join("");
}

$("resultsBody").addEventListener("click", ev => {
  const btn = ev.target.closest(".why-btn");
  if (!btn) return;
  const key = btn.dataset.key;
  if (expandedFindings.has(key)) expandedFindings.delete(key); else expandedFindings.add(key);
  renderResults(lastFindings);
});

// ---------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------
async function loadQuarantine() {
  try {
    const res = await fetch("/api/quarantine");
    const items = await res.json();
    renderQuarantine(items);
  } catch (err) {
    console.error("quarantine load failed", err);
  }
}

let lastQuarantine = [];
const expandedQuarantine = new Set();   // quarantine ids whose panel is open

function renderQuarantine(items) {
  lastQuarantine = items;
  const body = $("quarantineBody");
  if (!items.length) {
    body.innerHTML = `<tr><td colspan="5" class="empty-hint">No files quarantined yet.</td></tr>`;
    return;
  }
  body.innerHTML = items.map(it => {
    const open = expandedQuarantine.has(it.id);
    const hasWhy = (it.explanations || []).length || (it.reasons || []).length;
    return `
    <tr>
      <td class="reasons-cell">${escapeHtml(it.original_path)}
        ${hasWhy ? `<br><button class="why-btn" data-qid="${it.id}">${open ? "Hide details" : "Why quarantined?"}</button>` : ""}
      </td>
      <td class="reasons-cell">${escapeHtml((it.sha256 || "").slice(0, 16))}&hellip;</td>
      <td>${riskBadge(levelForScore(it.risk_score ?? 0), it.risk_score ?? 0)}</td>
      <td class="reasons-cell">${escapeHtml(it.status)}<br>
        <span class="q-source ${it.source === "manual" ? "manual" : "auto"}">${it.source === "manual" ? "Manual" : `Auto (${AUTO_QUARANTINE_THRESHOLD}+)`}</span>
      </td>
      <td>
        <button class="btn btn-sm btn-ghost" onclick="restoreItem(${it.id})">Restore</button>
        <button class="btn btn-sm btn-ghost" onclick="exportItem(${it.id})">Export</button>
        <button class="btn btn-sm btn-primary sandbox-btn" data-id="${it.id}" data-path="${escapeHtml(it.original_path)}">Sandbox</button>
        <button class="btn btn-sm btn-danger" onclick="deleteItem(${it.id})">Delete</button>
      </td>
    </tr>
    ${open ? `<tr class="why-row"><td colspan="5">${renderWhyPanel({ ...it, status: "quarantined" })}</td></tr>` : ""}`;
  }).join("");
}

// Delegated handlers: the path is read from a data attribute, never spliced into JS source.
$("quarantineBody").addEventListener("click", ev => {
  const why = ev.target.closest(".why-btn");
  if (why) {
    const id = Number(why.dataset.qid);
    if (expandedQuarantine.has(id)) expandedQuarantine.delete(id); else expandedQuarantine.add(id);
    renderQuarantine(lastQuarantine);
    return;
  }
  const sb = ev.target.closest(".sandbox-btn");
  if (sb) openSandboxModal(Number(sb.dataset.id), sb.dataset.path);
});

async function restoreItem(id) {
  showToast("Confirm with your Windows password or PIN to restore\u2026");
  const res = await fetch(`/api/quarantine/${id}/restore`, { method: "POST" });
  const data = await res.json();
  if (res.ok) { showToast("File restored to original location."); loadQuarantine(); }
  else showToast(data.error || "Restore failed", true);
}

async function deleteItem(id) {
  if (!confirm("Permanently delete this quarantined file? This cannot be undone.")) return;
  showToast("Confirm with your Windows password or PIN to delete\u2026");
  const res = await fetch(`/api/quarantine/${id}/delete`, { method: "POST" });
  const data = await res.json();
  if (res.ok) { showToast("File permanently deleted."); loadQuarantine(); }
  else showToast(data.error || "Delete failed", true);
}

async function exportItem(id) {
  showToast("Confirm with your Windows password or PIN to export\u2026");
  const res = await fetch(`/api/quarantine/${id}/export`, { method: "POST" });
  const data = await res.json();
  if (res.ok) showToast(`Sample exported to ${data.path}`);
  else showToast(data.error || "Export failed", true);
}

// ---------------------------------------------------------------------
// Manual quarantine: in-app file browser (USB drives + this PC)
//
// Works in the desktop app and in a normal browser. The server lists folders and
// receives the chosen absolute paths; it re-validates every path itself, so this
// code only decides what the user clicked, never what is allowed.
// ---------------------------------------------------------------------
const qState = {
  browserOpen: false, path: "", parent: null, entries: [],
  selected: new Set(),     // absolute paths of ticked files (kept while navigating folders)
};

function qFiles() { return qState.entries.filter(e => !e.is_dir); }

async function qApi(url, options = {}) {
  const res = await fetch(url, options);
  let data = {};
  try { data = await res.json(); } catch (_) { /* non-JSON error page */ }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

async function qLoadRoots() {
  try {
    const roots = await qApi("/api/fs/roots");
    $("qRoots").innerHTML = roots.map(r =>
      `<button class="q-root ${escapeHtml(r.kind)}" data-path="${escapeHtml(r.path)}">${escapeHtml(r.name)}</button>`).join("");
    const usb = roots.find(r => r.kind === "usb");
    if (usb && !qState.path) qOpenFolder(usb.path);   // a USB drive is plugged in: start there
  } catch (err) {
    showToast(err.message, true);
  }
}

async function qOpenFolder(path) {
  try {
    const data = await qApi(`/api/fs/list?path=${encodeURIComponent(path)}`);
    qState.path = data.path; qState.parent = data.parent; qState.entries = data.entries;
    $("qPathInput").value = data.path;
    $("qUpBtn").disabled = !data.parent;
    if (data.truncated) showToast("This folder is large - showing the first 2000 items.");
    qRenderFiles();
  } catch (err) {
    showToast(err.message, true);
  }
}

function qRefreshCurrent() { if (qState.path) qOpenFolder(qState.path); }

function qRenderFiles() {
  const body = $("qFileBody");
  if (!qState.entries.length) {
    body.innerHTML = `<tr><td colspan="4" class="empty-hint">This folder is empty.</td></tr>`;
  } else {
    body.innerHTML = qState.entries.map(e => e.is_dir
      ? `<tr class="q-dir"><td></td><td colspan="3"><button class="q-folder" data-open="${escapeHtml(e.path)}">&#128193; ${escapeHtml(e.name)}</button></td></tr>`
      : `<tr><td class="q-check"><input type="checkbox" class="q-pick" data-path="${escapeHtml(e.path)}" ${qState.selected.has(e.path) ? "checked" : ""}></td>
             <td class="reasons-cell">${escapeHtml(e.name)}</td>
             <td class="reasons-cell">${escapeHtml(fmtBytes(e.size_bytes))}</td>
             <td class="reasons-cell">${escapeHtml(e.modified)}</td></tr>`).join("");
  }
  qUpdateSelection();
}

function qUpdateSelection() {
  const n = qState.selected.size;
  $("qSelCount").textContent = `${n} file${n === 1 ? "" : "s"} selected`;
  $("qQuarantineBtn").disabled = n === 0;
  $("qClearBtn").disabled = n === 0;
  const files = qFiles();
  const all = $("qSelectAll");
  all.checked = files.length > 0 && files.every(f => qState.selected.has(f.path));
  all.disabled = files.length === 0;
}

function qReportResult(info) {
  const done = info.quarantined || 0, failed = info.failed || 0;
  let msg = done ? `${done} file${done === 1 ? "" : "s"} moved to quarantine` : "Nothing was quarantined";
  if (failed) msg += `; ${failed} could not be quarantined`;
  if (info.errors && info.errors.length) msg += ` - ${info.errors[0]}`;
  else if (info.message) msg += ` - ${info.message}`;
  showToast(msg + ".", failed > 0 && !done);
  loadQuarantine(); loadHistory();
  if (qState.browserOpen) qRefreshCurrent();
}

async function qQuarantineSelected() {
  const paths = [...qState.selected];
  if (!paths.length) return;
  const preview = paths.slice(0, 5).map(p => "  \u2022 " + p).join("\n") + (paths.length > 5 ? `\n  \u2026 and ${paths.length - 5} more` : "");
  if (!confirm(`Move ${paths.length} file${paths.length === 1 ? "" : "s"} into quarantine?\n\n${preview}\n\nYou can restore them later from this page.`)) return;
  const btn = $("qQuarantineBtn");
  btn.disabled = true; btn.textContent = "Quarantining\u2026";
  try {
    const data = await qApi("/api/quarantine/add", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-UTA-Request": "1" },
      body: JSON.stringify({ paths }),
    });
    (data.quarantined || []).forEach(q => qState.selected.delete(q.path));
    qReportResult({ quarantined: data.quarantined.length, failed: data.failed.length,
                    errors: data.failed.slice(0, 2).map(f => f.error) });
    if (data.quarantined.some(q => !q.original_removed)) {
      showToast("A copy was quarantined but an original could not be removed (read-only media or file in use).", true);
    }
  } catch (err) {
    showToast(err.message, true);
  } finally {
    btn.textContent = "Quarantine selected";
    qUpdateSelection();
  }
}

function initQuarantineBrowser() {
  $("qBrowseBtn").addEventListener("click", () => {
    qState.browserOpen = !qState.browserOpen;
    $("qBrowser").classList.toggle("hidden", !qState.browserOpen);
    $("qBrowseBtn").textContent = qState.browserOpen ? "Hide file browser" : "Browse USB / PC files\u2026";
    if (qState.browserOpen) qLoadRoots();
  });
  $("qRoots").addEventListener("click", ev => {
    const b = ev.target.closest(".q-root");
    if (b) qOpenFolder(b.dataset.path);
  });
  $("qFileBody").addEventListener("click", ev => {
    const f = ev.target.closest(".q-folder");
    if (f) qOpenFolder(f.dataset.open);
  });
  $("qFileBody").addEventListener("change", ev => {
    const box = ev.target.closest(".q-pick");
    if (!box) return;
    if (box.checked) qState.selected.add(box.dataset.path); else qState.selected.delete(box.dataset.path);
    qUpdateSelection();
  });
  $("qSelectAll").addEventListener("change", ev => {
    qFiles().forEach(f => { if (ev.target.checked) qState.selected.add(f.path); else qState.selected.delete(f.path); });
    qRenderFiles();
  });
  $("qUpBtn").addEventListener("click", () => { if (qState.parent) qOpenFolder(qState.parent); });
  $("qGoBtn").addEventListener("click", () => { const v = $("qPathInput").value.trim(); if (v) qOpenFolder(v); });
  $("qPathInput").addEventListener("keydown", ev => { if (ev.key === "Enter") $("qGoBtn").click(); });
  $("qClearBtn").addEventListener("click", () => { qState.selected.clear(); qRenderFiles(); });
  $("qQuarantineBtn").addEventListener("click", qQuarantineSelected);
}

// ---------------------------------------------------------------------
// Sandbox modal
// ---------------------------------------------------------------------
async function openSandboxModal(itemId, filePath, target = null) {
  currentSandboxItemId = itemId;
  currentSandboxTarget = target || { kind: "quarantine", itemId };
  $("sandboxModalFile").textContent = filePath;
  $("sandboxModal").classList.remove("hidden");

  const res = await fetch("/api/sandbox/available");
  const avail = await res.json();
  const select = $("sandboxSelect");
  select.innerHTML = "";
  Object.entries(avail).forEach(([key, info]) => {
    const opt = document.createElement("option");
    opt.value = key;
    opt.textContent = `${info.name}${info.ready ? " (Ready)" : " (Not installed)"}`;
    opt.disabled = !info.ready;
    select.appendChild(opt);
  });
  const firstReady = ["vmware", "virtualbox", "windows_sandbox"]
    .map(key => [key, avail[key]]).find(([, info]) => info?.ready);
  if (firstReady) select.value = firstReady[0];
  select.onchange = () => {
    const isVm = select.value === "vmware" || select.value === "virtualbox";
    $("vmNameWrap").classList.toggle("hidden", !isVm);
    $("sandboxPasswordWrap").classList.toggle("hidden", !isVm);
    const info = avail[select.value] || {};
    $("vmNameInput").value = (info.vms || [])[0] || "";
  };
  select.onchange();
  $("sandboxRunBtn").disabled = !firstReady;
}

function closeSandboxModal() {
  $("sandboxModal").classList.add("hidden");
  currentSandboxItemId = null;
  currentSandboxTarget = null;
  $("sandboxPasswordInput").value = "";
}

async function runSandboxAnalysis() {
  const target = currentSandboxTarget;
  if (!target) return;
  const sandboxType = $("sandboxSelect").value;
  const vmName = $("vmNameInput").value;
  const guestPassword = $("sandboxPasswordInput").value;
  if ((sandboxType === "vmware" || sandboxType === "virtualbox") && !guestPassword) {
    showToast("Enter the sandbox guest password.", true);
    return;
  }
  showToast("Launching sandbox analysis\u2026 this can take up to two minutes.");
  closeSandboxModal();

  try {
    let url = `/api/quarantine/${target.itemId}/sandbox`;
    let options = { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sandbox_type: sandboxType, vm_name: vmName || null, guest_password: guestPassword || null }) };
    if (target.kind !== "quarantine") {
      url = "/api/sandbox/analyze";
      if (target.kind === "upload") {
        const form = new FormData();
        form.append("file", target.file);
        form.append("sandbox_type", sandboxType);
        form.append("vm_name", vmName);
        form.append("guest_password", guestPassword);
        options = { method: "POST", headers: { "X-UTA-Request": "1" }, body: form };
      } else {
        options = { method: "POST", headers: { "Content-Type": "application/json", "X-UTA-Request": "1" },
          body: JSON.stringify({ path: target.path, sandbox_type: sandboxType, vm_name: vmName || null, guest_password: guestPassword || null }) };
      }
    }
    const res = await fetch(url, options);
    const data = await res.json();
    if (res.ok && data.status === "completed") {
      showToast(`Sandbox run complete: ${data.verdict_notes || "see report"}`);
      if (data.report_url) {
        $("sandboxResultTitle").textContent = `Analysis complete: ${target.fileName || target.file?.name || target.path || "selected file"}`;
        $("sandboxResultNotes").textContent = data.verdict_notes || "See the PDF report for before/after details.";
        $("sandboxReportLink").href = data.report_url;
        $("sandboxRunResult").classList.remove("hidden");
        if (data.scan_id) loadSandboxSnapshotViewer(data.scan_id);
        triggerBrowserDownload(data.report_url);
      }
      loadHistory();
    } else {
      showToast(data.error || data.message || "Sandbox run did not complete.", true);
    }
  } catch (err) {
    showToast("Sandbox request failed.", true);
  } finally {
    $("sandboxAnalyzeBtn").disabled = !selectedSandboxFile && !selectedSandboxPath;
    $("sandboxManualStatus").textContent = selectedSandboxFile || selectedSandboxPath ? "Ready to analyze." : "";
  }
}

let sandboxSnapshotData = null;

function sandboxSnapshotSummary(snapshot) {
  return {
    taken_at: snapshot?.taken_at || null,
    files: (snapshot?.files || []).length,
    folders: (snapshot?.folders || []).length,
    registry_run_keys: Object.keys(snapshot?.registry_run_keys || {}).length,
    startup_entries: (snapshot?.startup_entries || []).length,
    processes: (snapshot?.processes || []).length,
    services: (snapshot?.services || []).length,
    scheduled_tasks: (snapshot?.scheduled_tasks || []).length,
    network_connections: (snapshot?.network_connections || []).length,
    open_ports: (snapshot?.open_ports || []).length,
    encrypted_files: (snapshot?.encrypted_files || []).length,
    encrypted_folders: (snapshot?.encrypted_folders || []).length,
    locked_files: (snapshot?.locked_files || []).length,
    collection_errors: snapshot?.collection_errors || []
  };
}

function renderSandboxSnapshot(view = "before") {
  if (!sandboxSnapshotData) return;
  const el = $("sandboxSnapshotDetails");
  if (view === "changes") {
    el.textContent = JSON.stringify(sandboxSnapshotData.diff || {}, null, 2);
    return;
  }
  const snap = view === "after" ? sandboxSnapshotData.after_snapshot : sandboxSnapshotData.before_snapshot;
  el.textContent = JSON.stringify(sandboxSnapshotSummary(snap), null, 2);
}

async function loadSandboxSnapshotViewer(scanId) {
  try {
    const res = await fetch(`/api/sandbox/snapshots/${encodeURIComponent(scanId)}`);
    if (!res.ok) throw new Error("Snapshot data unavailable");
    sandboxSnapshotData = await res.json();
    const baseline = sandboxSnapshotData.baseline_snapshot_name || "not recorded";
    const before = sandboxSnapshotData.before_snapshot_name || "not recorded";
    const after = sandboxSnapshotData.after_snapshot_name || "not recorded";
    sandboxSnapshotData.snapshot_names_valid = Boolean(before !== "not recorded" && after !== "not recorded");
    $("sandboxSnapshotMeta").textContent =
      `${sandboxSnapshotData.sandbox_type} | BASELINE: ${baseline} | BEFORE: ${before} | AFTER: ${after}`;
    $("sandboxSnapshotViewer").classList.remove("hidden");
    renderSandboxSnapshot("before");
  } catch (err) {
    console.warn("sandbox snapshot viewer unavailable", err);
  }
}

$("sandboxBeforeTab")?.addEventListener("click", () => renderSandboxSnapshot("before"));
$("sandboxAfterTab")?.addEventListener("click", () => renderSandboxSnapshot("after"));
$("sandboxChangesTab")?.addEventListener("click", () => renderSandboxSnapshot("changes"));

function setSandboxFile(file) {
  if (!file) return;
  selectedSandboxFile = file;
  selectedSandboxPath = null;
  $("sandboxFileName").textContent = file.name;
  $("sandboxManualStatus").textContent = "Ready to analyze.";
  $("sandboxAnalyzeBtn").disabled = false;
  $("sandboxRunResult").classList.add("hidden");
}

$("sandboxFileInput").addEventListener("change", ev => setSandboxFile(ev.target.files[0]));
$("sandboxAnalyzeBtn").addEventListener("click", () => {
  if (selectedSandboxFile) {
    openSandboxModal(null, selectedSandboxFile.name,
      { kind: "upload", file: selectedSandboxFile, fileName: selectedSandboxFile.name });
  } else if (selectedSandboxPath) {
    openSandboxModal(null, selectedSandboxPath,
      { kind: "path", path: selectedSandboxPath, fileName: selectedSandboxPath });
  }
});

// ---------------------------------------------------------------------
// Sandbox availability card
// ---------------------------------------------------------------------
async function loadSandboxAvailability() {
  try {
    const res = await fetch("/api/sandbox/available");
    const avail = await res.json();
    setSandboxStatus("wsStatus", avail.windows_sandbox?.ready);
    setSandboxStatus("vmwareStatus", avail.vmware?.ready);
    setSandboxStatus("vboxStatus", avail.virtualbox?.ready);
  } catch (err) {
    console.error("sandbox availability failed", err);
  }
}

function setSandboxStatus(elId, ready) {
  const el = $(elId);
  el.textContent = ready ? "Ready" : "Not installed";
  el.className = ready ? "ready" : "missing";
}

// ---------------------------------------------------------------------
// History
// ---------------------------------------------------------------------
async function loadHistory() {
  try {
    const res = await fetch("/api/history");
    const scans = await res.json();
    renderHistory(scans);
  } catch (err) {
    console.error("history load failed", err);
  }
}

function renderHistory(scans) {
  const body = $("historyBody");
  if (!scans.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty-hint">No previous scans.</td></tr>`;
    return;
  }
  body.innerHTML = scans.map(s => `
    <tr>
      <td>${escapeHtml(s.usb_name || "Unknown")}</td>
      <td class="reasons-cell">${escapeHtml((s.started_at || "").replace("T", " ").slice(0, 19))}</td>
      <td>${s.files_scanned ?? 0}</td>
      <td>${s.suspicious_files ?? 0}</td>
      <td>${riskBadge(s.highest_risk >= 80 ? "Critical" : s.highest_risk >= 60 ? "High" : s.highest_risk >= 30 ? "Medium" : "Low", s.highest_risk ?? 0)}</td>
      <td>${s.report_path
        ? `<a class="btn btn-sm btn-ghost" href="/api/report/${s.scan_id}/download">Download</a>`
        : `<button class="btn btn-sm btn-ghost" onclick="generateReport('${s.scan_id}')">Generate</button>`}</td>
    </tr>
  `).join("");
}

async function generateReport(scanId) {
  showToast("Generating forensic PDF report\u2026");
  const res = await fetch(`/api/scan/${scanId}/report`, { method: "POST" });
  const data = await res.json();
  if (res.ok) {
    showToast("Report generated.");
    loadHistory();

    // Auto-Download Report: re-check the live preference (not just the
    // cached value) so a change made in another tab/session is honored,
    // then trigger the download immediately with no further click.
    try {
      const prefRes = await fetch("/api/settings/preferences");
      const pref = await prefRes.json();
      if (pref.auto_download_report) {
        triggerBrowserDownload(`/api/report/${scanId}/download`);
      }
    } catch (err) {
      console.error("auto-download preference check failed", err);
    }
  } else {
    showToast(data.error || "Report generation failed.", true);
  }
}

$("genReportBtn").addEventListener("click", () => {
  if (currentScanId) generateReport(currentScanId);
});

// ---------------------------------------------------------------------
// Sidebar navigation
// ---------------------------------------------------------------------
function initSidebarNav() {
  const navItems = document.querySelectorAll(".nav-item");
  navItems.forEach(btn => {
    btn.addEventListener("click", () => {
      navItems.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const view = btn.dataset.view;
      window.__activeView = view;
      $("view-dashboard").classList.toggle("hidden", view !== "dashboard");
      $("view-sandbox").classList.toggle("hidden", view !== "sandbox");
      $("view-quarantine").classList.toggle("hidden", view !== "quarantine");
      $("view-settings").classList.toggle("hidden", view !== "settings");
      if (view === "quarantine") {
        loadQuarantine();
        if (qState.browserOpen) qRefreshCurrent();
      }
      if (view === "settings") {
        loadStartupStatus(); loadAutoDownloadPreference(); loadBackgroundPreference(); loadHidStatus();
      }
    });
  });
}

// ---------------------------------------------------------------------
// Settings: Start with Windows (HKCU Run key, user-controlled)
// ---------------------------------------------------------------------
function renderStartupStatus(status) {
  const enabled = !!status.enabled;
  $("startupCheckbox").checked = enabled;
  const label = $("startupStatusLabel");
  label.textContent = enabled ? "Enabled" : "Disabled";
  label.className = `status-pill ${enabled ? "enabled" : "disabled"}`;

  const pathEl = $("startupRegisteredPath");
  if (enabled && status.registered_path) {
    pathEl.textContent = `Registered path: ${status.registered_path}`;
  } else {
    pathEl.textContent = `Key: HKCU\\${status.key_path ? status.key_path.replace("HKCU\\", "") : ""}  \u00b7  Value name: ${status.value_name || "USBThreatAnalyzer"}`;
  }

  if (status.platform_supported === false) {
    showToast("Registry startup control is only available on Windows.", true);
  }
}

async function loadStartupStatus() {
  try {
    const res = await fetch("/api/settings/startup");
    const status = await res.json();
    renderStartupStatus(status);
  } catch (err) {
    console.error("startup status load failed", err);
  }
}

async function applyStartupSetting() {
  const enabled = $("startupCheckbox").checked;
  const btn = $("startupApplyBtn");
  btn.disabled = true;
  btn.textContent = "Applying\u2026";
  try {
    const res = await fetch("/api/settings/startup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled }),
    });
    const data = await res.json();
    if (data.success) {
      showToast(data.message || "Settings applied.");
    } else {
      showToast(data.message || "Could not apply startup setting.", true);
    }
    if (data.status) renderStartupStatus(data.status);
  } catch (err) {
    showToast("Request failed. Please try again.", true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Apply Changes";
  }
}

$("startupApplyBtn").addEventListener("click", applyStartupSetting);

// ---------------------------------------------------------------------
// Settings: Auto-Download Report
// ---------------------------------------------------------------------
let autoDownloadEnabled = false; // cached; re-synced on Settings view load and on toggle apply

function renderAutoDownloadStatus(enabled) {
  autoDownloadEnabled = !!enabled;
  $("autoDownloadCheckbox").checked = autoDownloadEnabled;
  const label = $("autoDownloadStatusLabel");
  label.textContent = autoDownloadEnabled ? "Enabled" : "Disabled";
  label.className = `status-pill ${autoDownloadEnabled ? "enabled" : "disabled"}`;
}

async function loadAutoDownloadPreference() {
  try {
    const res = await fetch("/api/settings/preferences");
    const data = await res.json();
    renderAutoDownloadStatus(data.auto_download_report);
  } catch (err) {
    console.error("preferences load failed", err);
  }
}

async function applyAutoDownloadSetting() {
  const enabled = $("autoDownloadCheckbox").checked;
  const btn = $("autoDownloadApplyBtn");
  btn.disabled = true;
  btn.textContent = "Applying\u2026";
  try {
    const res = await fetch("/api/settings/preferences", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ auto_download_report: enabled }),
    });
    const data = await res.json();
    renderAutoDownloadStatus(data.auto_download_report);
    showToast(enabled
      ? "Reports will now download automatically when generated."
      : "Auto-download turned off. Use the Download button in History instead.");
  } catch (err) {
    showToast("Request failed. Please try again.", true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Apply Changes";
  }
}

$("autoDownloadApplyBtn").addEventListener("click", applyAutoDownloadSetting);

/**
 * Triggers a same-origin file download without any user click, via a
 * hidden <a download> element. Used right after a report finishes
 * generating when Auto-Download Report is enabled.
 */
function triggerBrowserDownload(url) {
  const link = document.createElement("a");
  link.href = url;
  link.download = "";
  link.style.display = "none";
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// ---------------------------------------------------------------------
// Drag-and-drop scanning (desktop app)
//
// This page never sees real file paths (the browser hides them) and never
// decides what gets scanned. The native window in desktop.py receives the drop,
// reads the Windows paths itself, runs the scan, and reports back through
// window.onNativeDrop() below. The code here only (a) cancels the browser's
// default "open the dropped file" behaviour, (b) shows the drop overlay, and
// (c) displays the outcome.
// ---------------------------------------------------------------------
function dragHasFiles(ev) {
  const types = ev.dataTransfer && ev.dataTransfer.types;
  return !!types && Array.from(types).includes("Files");
}

function initDropScan() {
  const overlay = $("dropOverlay");
  let hideTimer = null;
  const hideOverlay = () => { clearTimeout(hideTimer); overlay.classList.add("hidden"); };

  // Capture phase so the native drop handler's propagation rules can't starve us.
  window.addEventListener("dragover", ev => {
    if (!dragHasFiles(ev)) return;
    ev.preventDefault();                  // without this the drop is refused / the window navigates
    ev.dataTransfer.dropEffect = "copy";
    const toQuarantine = window.__activeView === "quarantine";
    const toSandbox = window.__activeView === "sandbox";
    $("dropOverlayTitle").textContent = toSandbox ? "Drop for sandbox analysis" : (toQuarantine ? "Drop to quarantine" : "Drop to scan");
    $("dropOverlayText").textContent = toQuarantine
      ? "Release files from File Explorer or your USB drive to move them into quarantine"
      : (toSandbox ? "Release one file, then choose an isolated environment and start analysis"
        : "Release files or folders from File Explorer to scan them");
    overlay.classList.remove("hidden");
    clearTimeout(hideTimer);              // dragover repeats while hovering; stops when the pointer leaves
    hideTimer = setTimeout(hideOverlay, 700);
  }, true);

  window.addEventListener("drop", ev => {
    if (!dragHasFiles(ev)) return;
    ev.preventDefault();
    hideOverlay();
    if (window.__activeView === "sandbox" && !window.pywebview) {
      if (ev.dataTransfer.files.length !== 1) {
        showToast("Drop one file at a time for sandbox analysis.", true);
      } else {
        setSandboxFile(ev.dataTransfer.files[0]);
      }
      return;
    }
    if (!window.pywebview) {
      showToast(window.__activeView === "quarantine"
        ? "Drag-and-drop is only available in the desktop app - use Browse USB / PC files instead."
        : "Drag-and-drop scanning is only available in the desktop app.", true);
    }
  }, true);

  window.addEventListener("dragend", hideOverlay, true);
}

/** Called by desktop.py (via evaluate_js) with the state of a dropped-file scan. */
window.onNativeDrop = function (info) {
  if (!info) return;
  if (info.event === "started") {
    document.querySelector('.nav-item[data-view="dashboard"]')?.click();  // leave Settings if open
    currentScanId = info.scan_id;
    $("genReportBtn").disabled = true;
    showToast(`Scanning ${info.total} file${info.total === 1 ? "" : "s"}\u2026`);
    loadFindings(info.scan_id);
  } else if (info.event === "finished") {
    currentScanId = info.scan_id;
    loadFindings(info.scan_id);
    loadQuarantine();
    loadHistory();
    $("genReportBtn").disabled = false;
    let msg = `Scan complete: ${info.files_scanned} file${info.files_scanned === 1 ? "" : "s"}, `
      + `${info.suspicious} suspicious`;
    if (info.quarantined) msg += `, ${info.quarantined} quarantined`;
    if (info.skipped) msg += ` (${info.skipped} skipped)`;
    showToast(msg + ".", info.highest_risk >= 60);
  } else if (info.event === "quarantine_done") {
    qReportResult(info);
  } else if (info.event === "quarantine_cancelled") {
    showToast(info.message || "Nothing was quarantined.");
  } else if (info.event === "sandbox_file_dropped") {
    document.querySelector('.nav-item[data-view="sandbox"]')?.click();
    selectedSandboxFile = null;
    selectedSandboxPath = info.path;
    $("sandboxFileName").textContent = info.path;
    $("sandboxManualStatus").textContent = "File selected. Click Run Analysis to choose an environment.";
    $("sandboxAnalyzeBtn").disabled = false;
    $("sandboxRunResult").classList.add("hidden");
  } else if (info.event === "rejected" || info.event === "error") {
    showToast(info.message || "Could not process the dropped items.", true);
  }
};

document.addEventListener("DOMContentLoaded", initDropScan);

// ---------------------------------------------------------------------
// Settings: Background mode (system tray) - explicit user permission
// ---------------------------------------------------------------------
function renderBackgroundStatus(enabled) {
  $("backgroundCheckbox").checked = !!enabled;
  const label = $("backgroundStatusLabel");
  label.textContent = enabled ? "Enabled" : "Disabled";
  label.className = `status-pill ${enabled ? "enabled" : "disabled"}`;
}

async function loadBackgroundPreference() {
  try {
    const res = await fetch("/api/settings/background");
    const data = await res.json();
    renderBackgroundStatus(data.enabled);
    if (!data.tray_available) {
      $("backgroundCheckbox").disabled = true;
      $("backgroundStatusLabel").textContent = "Unavailable (tray support not installed)";
    }
  } catch (err) {
    console.error("background preference load failed", err);
  }
}

async function applyBackgroundSetting() {
  const enabled = $("backgroundCheckbox").checked;
  if (enabled && !confirm(
    "Allow USB Threat Analyzer to keep running in the background?\n\n" +
    "Minimizing or closing the window will hide it in the system tray instead of exiting. " +
    "You can turn this off here at any time, or choose Exit from the tray icon.")) {
    $("backgroundCheckbox").checked = false;
    return;
  }
  const btn = $("backgroundApplyBtn");
  btn.disabled = true;
  try {
    const res = await fetch("/api/settings/background", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled }),
    });
    const data = await res.json();
    renderBackgroundStatus(data.enabled);
    showToast(data.message || "Saved.", !res.ok);
  } catch (err) {
    showToast("Request failed. Please try again.", true);
  } finally {
    btn.disabled = false;
  }
}

$("backgroundApplyBtn").addEventListener("click", applyBackgroundSetting);

// ---------------------------------------------------------------------
// Settings: Keyboard protection (BadUSB / rogue HID)
// ---------------------------------------------------------------------
async function loadHidStatus() {
  try {
    const [st, alerts] = await Promise.all([
      fetch("/api/hid/status").then(r => r.json()),
      fetch("/api/hid/alerts").then(r => r.json()),
    ]);
    const label = $("hidStatusLabel");
    label.textContent = st.running ? "Active" : "Not running";
    label.className = `status-pill ${st.running ? "enabled" : "disabled"}`;
    $("hidThreshold").textContent = st.wpm_threshold;
    $("hidStatusDetail").textContent = st.running
      ? (st.can_disable_devices
          ? "Rogue devices are disabled automatically."
          : "Rogue keyboards are locked out briefly. Run the app as Administrator to also disable the device automatically.")
      : "Only available in the Windows desktop app.";
    renderHidAlerts(alerts);
  } catch (err) {
    console.error("hid status load failed", err);
  }
}

function renderHidAlerts(alerts) {
  $("hidAlertsList").innerHTML = (alerts || []).map(a => `
    <div class="hid-alert">
      <strong>${escapeHtml(a.time)}</strong> &mdash; ${escapeHtml(a.vid_pid)}
      <p>${escapeHtml(a.message)}</p>
      <p class="mono">${escapeHtml((a.actions || []).join(" \u2022 "))}</p>
      ${a.trusted ? "<p>Trusted by you.</p>"
        : `<button class="btn hid-trust-btn" data-alert-id="${escapeHtml(a.id)}">This is my keyboard - trust it</button>`}
    </div>`).join("");
}

$("hidAlertsList").addEventListener("click", async ev => {
  const btn = ev.target.closest(".hid-trust-btn");
  if (!btn) return;
  if (!confirm("Only trust this device if it is a keyboard you plugged in yourself. Trust it?")) return;
  const res = await fetch("/api/hid/trust", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ alert_id: btn.dataset.alertId }),
  });
  const data = await res.json();
  showToast(data.message || "Done.", !res.ok);
  loadHidStatus();
});

// ---------------------------------------------------------------------
// Events pushed from the desktop shell (desktop.py -> evaluate_js)
// ---------------------------------------------------------------------
window.onNativeEvent = function (info) {
  if (!info) return;
  if (info.event === "usb_inserted") {
    document.querySelector('.nav-item[data-view="dashboard"]')?.click();   // show the scan screen
    pollStatus();                                                          // don't wait for the next tick
    const name = (info.device && info.device.label) || "USB drive";
    showToast(`${name} inserted \u2014 scanning\u2026`);
  } else if (info.event === "hid_alert") {
    showToast((info.alert && info.alert.message) || "Rogue keyboard detected.", true);
    loadHidStatus();
  } else if (info.event === "background_failed") {
    showToast(info.message || "Background mode could not start.", true);
    loadBackgroundPreference();
  }
};

// ---------------------------------------------------------------------
// Modal wiring + boot
// ---------------------------------------------------------------------
$("sandboxCancelBtn").addEventListener("click", closeSandboxModal);
$("sandboxRunBtn").addEventListener("click", runSandboxAnalysis);

function bootPolling() {
  initSidebarNav();
  initQuarantineBrowser();
  loadStartupStatus();           // sync checkbox/status on launch, per spec
  loadAutoDownloadPreference();  // so auto-download works even before opening Settings
  loadBackgroundPreference();
  pollStatus();
  loadQuarantine();
  loadHistory();
  loadSandboxAvailability();
  setInterval(pollStatus, POLL_INTERVAL_MS);
  setInterval(loadQuarantine, 6000);
  setInterval(loadHistory, 8000);
}

document.addEventListener("DOMContentLoaded", bootPolling);
