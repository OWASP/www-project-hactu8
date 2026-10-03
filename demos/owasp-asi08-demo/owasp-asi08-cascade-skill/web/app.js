// HACTU8 lab console — shared by every demo, unchanged between them.
// Everything demo-specific comes from the target's console API:
//   GET  /api/meta      static labels (id, title, scenario, metric, act text)
//   GET  /api/state     {mode, baseline, ...}
//   POST /api/reset     restore baseline + vulnerable mode
//   POST /api/attack    run the demo's attack -> {events: [..]}
//   POST /api/evaluate  run the suite -> {rows, targeted_rate, overall_rate, ...}
//   POST /api/scan      static/dry-run check of the payload -> {decision, findings}
//   POST /api/mode      {mode: "vulnerable" | "hardened"}
// Open /#run to play all four acts on page load.
// All text is inserted with textContent, never innerHTML.
"use strict";

const $ = (id) => document.getElementById(id);
let meta = {};

async function api(path, body) {
  const opts = body === undefined
    ? { method: "GET" }
    : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const resp = await fetch(path, opts);
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
  return data;
}

function log(kind, text) {
  const row = document.createElement("div");
  row.className = `log-entry kind-${kind}`;
  const time = document.createElement("time");
  time.textContent = new Date().toLocaleTimeString([], { hour12: false });
  const span = document.createElement("span");
  const tag = document.createElement("b");
  tag.textContent = { attack: "ATTACK /", defense: "DEFENSE /", kpi: "KPI /", error: "ERROR /" }[kind] || "LAB /";
  span.append(tag, document.createTextNode(text));
  row.append(time, span);
  $("event-log").prepend(row);
}

function pct(x) { return `${Math.round(x)}%`; }

async function refreshState() {
  try {
    const s = await api("/api/state");
    $("system-status").textContent = "ONLINE";
    $("mode").textContent = (s.mode || "-").toUpperCase();
    $("state").textContent = s.baseline ? "BASELINE" : "ATTACKED";
  } catch (err) {
    $("system-status").textContent = "OFFLINE";
  }
}

// Statuses per act, so Act 1 / 3 / 4 sit side by side: the delta is the lesson.
const ACT_COLUMNS = ["baseline", "evaluate", "remediate"];
let history = {};

function badge(status) {
  const el = document.createElement("span");
  el.className = `signal signal-${status || "NONE"}`;
  el.textContent = status || "-";
  return el;
}

function renderResults(r, act) {
  for (const row of r.rows || []) {
    history[row.item] = history[row.item] || {};
    history[row.item][act] = row.status;
  }
  const body = $("results-body");
  body.replaceChildren();
  for (const row of r.rows || []) {
    const tr = document.createElement("tr");
    const item = document.createElement("td");
    item.textContent = row.item;
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = row.targeted ? "TARGETED" : "CONTROL";
    item.append(document.createElement("br"), tag);
    tr.append(item);
    for (const col of ACT_COLUMNS) {
      const td = document.createElement("td");
      td.className = "signal-cell";
      td.append(badge(history[row.item][col]));
      tr.append(td);
    }
    const detail = document.createElement("td");
    detail.textContent = row.detail || "";
    tr.append(detail);
    body.append(tr);
  }
  const abbr = meta.metric_abbr || "RATE";
  $("rate").textContent = `${pct(r.targeted_rate)} / ${pct(r.overall_rate)}`;
  $("result-summary").textContent = `${abbr} ${pct(r.targeted_rate)} TARGETED`;
  log("kpi", `${meta.metric_name || "Rate"}: ${pct(r.targeted_rate)} targeted, ${pct(r.overall_rate)} overall.`);
}

const actions = {
  async reset() {
    await api("/api/reset", {});
    log("lab", "Baseline restored; mode set to vulnerable.");
  },
  async baseline() {
    await actions.reset();
    history = {};
    renderResults(await api("/api/evaluate", {}), "baseline");
  },
  async attack() {
    const r = await api("/api/attack", {});
    for (const e of r.events || []) log("attack", e);
  },
  async evaluate() {
    renderResults(await api("/api/evaluate", {}), "evaluate");
  },
  async remediate() {
    const scan = await api("/api/scan", {});
    log("defense", `${meta.scan_label || "Scan"}: ${scan.decision}` +
      (scan.findings && scan.findings.length ? ` (${scan.findings.join("; ")})` : ""));
    await api("/api/mode", { mode: "hardened" });
    log("defense", `Hardened mode on. ${meta.harden_description || ""}`);
    renderResults(await api("/api/evaluate", {}), "remediate");
  },
  async sequence() {
    for (const step of ["baseline", "attack", "evaluate", "remediate"]) {
      await actions[step]();
      markDone(step);
    }
  },
};

function markDone(step) {
  const btn = document.querySelector(`.act[data-action="${step}"]`);
  if (btn) btn.classList.add("done");
}

async function run(name) {
  const buttons = document.querySelectorAll("button[data-action]");
  buttons.forEach((b) => { b.disabled = true; });
  $("busy").textContent = "RUNNING";
  if (name === "reset" || name === "baseline" || name === "sequence") {
    document.querySelectorAll(".act").forEach((b) => b.classList.remove("done"));
  }
  try {
    await actions[name]();
    markDone(name);
  } catch (err) {
    log("error", err.message);
  } finally {
    buttons.forEach((b) => { b.disabled = false; });
    $("busy").textContent = "READY";
    refreshState();
  }
}

async function init() {
  try {
    meta = await api("/api/meta");
  } catch (err) {
    log("error", `Cannot load /api/meta: ${err.message}`);
    return;
  }
  document.title = `${meta.id} | ${meta.short_title || meta.title}`;
  $("brand-id").textContent = meta.id;
  $("brand-name").textContent = (meta.short_title || meta.title).toUpperCase();
  $("framework").textContent = `${meta.framework} / ${meta.id} ${meta.risk}`.toUpperCase();
  $("title").textContent = meta.title;
  $("scenario").textContent = meta.scenario;
  $("ground-truth").textContent = meta.ground_truth;
  $("metric-label").textContent = `${meta.metric_abbr} TARGETED / OVERALL`;
  $("attack-label").textContent = meta.attack_label;
  $("attack-desc").textContent = meta.attack_description;
  $("harden-label").textContent = meta.harden_label || "Apply the mitigation";
  $("harden-desc").textContent = meta.harden_description;
  $("footer-id").textContent = `${meta.framework} / ${meta.id}`.toUpperCase();
  log("lab", "Console ready. Start with Act 1, or run the full sequence.");
  await refreshState();
  // Presenter shortcut: open /#run to play all four acts on load.
  if (location.hash === "#run") run("sequence");
}

document.addEventListener("click", (ev) => {
  const btn = ev.target.closest("button[data-action]");
  if (btn && actions[btn.dataset.action]) run(btn.dataset.action);
});
init();
