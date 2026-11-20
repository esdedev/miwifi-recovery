"use strict";

const T = window.__TAURI__;
const invoke = (cmd, args) => T.core.invoke(cmd, args);
const $ = (id) => document.getElementById(id);

const STEPS = ["firmware", "pc", "router", "flash", "finish"];
const S = {
  step: "firmware",
  platform: "windows",
  fwPath: null,
  analysis: null,
  adapters: [],
  selected: null,
  autoOk: false,
  manualDone: false,
  phase: "idle",
  phaseArgs: {},
  pct: 0,
  rate: 0,
  probeTimer: null,
  routerUp: false,
  doneTimer: null,
};

/* i18n ------------------------------------------------------------------ */
function applyLang() {
  document.documentElement.lang = LANG;
  document.querySelectorAll("[data-t]").forEach((el) => (el.innerHTML = t(el.dataset.t)));
  document.querySelectorAll("[data-lang]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.lang === LANG)));
  render();
}
document.querySelectorAll("[data-lang]").forEach((b) =>
  b.addEventListener("click", () => {
    LANG = b.dataset.lang;
    try { localStorage.setItem("lang", LANG); } catch (_) {}
    applyLang();
  })
);

/* Navigation ------------------------------------------------------------ */
function go(step) {
  const prev = S.step;
  S.step = step;
  STEPS.forEach((s) => ($("page-" + s).hidden = s !== step));
  if (prev === "flash" && step !== "finish") stopRecovery();
  if (step === "pc") loadAdapters();
  if (step === "flash") startRecovery();
  if (step === "finish") startProbe();
  else stopProbe();
  render();
  const page = $("page-" + step);
  page.scrollTop = 0;
  const h = page.querySelector("h1");
  if (h) { h.tabIndex = -1; h.focus({ preventScroll: true }); }
}

function canContinue() {
  switch (S.step) {
    case "firmware":
      return !!S.analysis && !S.analysis.blocked && $("model").value.trim() !== "";
    case "pc": {
      const a = S.adapters.find((x) => x.index === S.selected);
      return (a && hasIp(a)) || S.autoOk || S.manualDone;
    }
    case "router":
      return true;
    case "flash":
      return ["fatal", "busy", "denied", "done"].includes(S.phase);
    case "finish":
      return false;
  }
}

function render() {
  const i = STEPS.indexOf(S.step);
  document.querySelectorAll("#steps li").forEach((li, k) => {
    li.classList.toggle("current", k === i);
    li.classList.toggle("done", k < i);
    if (k === i) li.setAttribute("aria-current", "step"); else li.removeAttribute("aria-current");
  });
  const next = $("next");
  next.textContent =
    S.step === "router" ? t("start") :
    S.step === "flash" ? (S.phase === "done" ? t("next") : t("retry")) :
    t("next");
  next.disabled = !canContinue();
  next.hidden = (S.step === "flash" && !canContinue()) || S.step === "finish";
  $("back").hidden = i === 0;
  renderFirmware();
  renderPc();
  renderFlash();
  if (S.step === "finish") {
    $("probeStatus").innerHTML = S.routerUp ? t("probe_ok") : t("probe_wait");
    $("openRouter").hidden = !S.routerUp;
  }
}

$("next").addEventListener("click", () => {
  if (!canContinue()) return;
  if (S.step === "flash") {
    if (S.phase === "done") go("finish"); else startRecovery();
    return;
  }
  go(STEPS[STEPS.indexOf(S.step) + 1]);
});
$("back").addEventListener("click", () => {
  const i = STEPS.indexOf(S.step);
  go(STEPS[S.step === "finish" ? 2 : i - 1]);
});

/* Step 1: firmware ----------------------------------------------------- */
async function pickFile() {
  const path = await T.dialog.open({
    multiple: false,
    directory: false,
    filters: [{ name: "Firmware", extensions: ["bin", "img"] }, { name: "*", extensions: ["*"] }],
  });
  if (path) loadFirmware(path);
}
$("drop").addEventListener("click", pickFile);

function loadFirmware(path) {
  S.fwPath = path;
  S.analysis = null;
  $("fwResult").hidden = true;
  $("drop").querySelector(".drop-main").textContent = t("fw_reading", { name: path.split(/[\\/]/).pop() });
  analyze();
}

let analyzeSeq = 0;
async function analyze() {
  if (!S.fwPath) return;
  const seq = ++analyzeSeq;
  try {
    const a = await invoke("analyze_firmware", {
      path: S.fwPath,
      model: $("model").value.trim(),
      installed: $("installed").value.trim() || null,
    });
    if (seq !== analyzeSeq) return;
    S.analysis = a;
  } catch (e) {
    if (seq !== analyzeSeq) return;
    S.analysis = { error: String(e), blocked: true, findings: [] };
  }
  $("fwResult").hidden = false;
  render();
}
let debounce;
["model", "installed"].forEach((id) =>
  $(id).addEventListener("input", () => {
    clearTimeout(debounce);
    debounce = setTimeout(analyze, 250);
    render();
  })
);

function fmtSize(n) {
  return (n / 1048576).toFixed(1) + " MiB";
}

function renderFirmware() {
  const a = S.analysis;
  const drop = $("drop");
  drop.classList.toggle("compact", !!a);
  if (!a) return;
  drop.querySelector(".drop-main").textContent = a.file_name || S.fwPath.split(/[\\/]/).pop();
  drop.querySelector(".drop-sub").innerHTML = t("fw_drop_sub");
  const facts = $("facts");
  facts.innerHTML = "";
  if (a.info) {
    const m = a.info.meta || {};
    const rows = [
      ["fact_model", m.HARDWARE || "?"],
      ["fact_version", m.ROM || "?"],
      ["fact_built", m.BUILDTIME ? new Date(m.BUILDTIME).toLocaleDateString(LANG) : "?"],
      ["fact_size", fmtSize(a.info.size)],
      ["fact_checksum", a.info.crc_ok === null ? "—" : a.info.crc_ok ? t("checksum_ok") : t("checksum_bad"), a.info.crc_ok === false],
      ["fact_sha", a.info.sha256.slice(0, 16) + "…"],
    ];
    for (const [k, v, bad] of rows) {
      const d = document.createElement("div");
      d.innerHTML = `<dt>${t(k)}</dt><dd${bad ? ' class="bad"' : ""}>${esc(v)}</dd>`;
      if (k === "fact_sha") d.title = a.info.sha256;
      facts.appendChild(d);
    }
  }
  const box = $("findings");
  box.innerHTML = "";
  const add = (sev, html) => {
    const d = document.createElement("div");
    d.className = "finding " + sev;
    d.innerHTML = html;
    box.appendChild(d);
  };
  if (a.error) add("error", esc(a.error));
  for (const f of a.findings) add(f.severity, t("f_" + f.code, f.args));
  if (!a.error && !$("model").value.trim()) add("info", t("model_needed"));
  if (!a.error && !$("installed").value.trim() && !a.blocked) add("info", t("unknown_installed"));
}

/* Drag and drop (Tauri delivers file paths) */
T.webviewWindow.getCurrentWebviewWindow().onDragDropEvent((ev) => {
  const p = ev.payload;
  const drop = $("drop");
  if (p.type === "over" || p.type === "enter") drop.classList.add("over");
  else drop.classList.remove("over");
  if (p.type === "drop" && p.paths && p.paths.length) {
    if (S.step !== "firmware") go("firmware");
    loadFirmware(p.paths[0]);
  }
});

/* Step 2: this PC ------------------------------------------------------- */
const hasIp = (a) => a.addrs.some((x) => x.ip === "192.168.31.100");
const inSubnet = (a) => a.addrs.some((x) => x.ip.startsWith("192.168.31."));

// Real wired adapters (no VirtualBox/Hyper-V/VPN); fall back to every wired one.
function cableAdapters() {
  const wired = S.adapters.filter((a) => a.wired || hasIp(a));
  const physical = wired.filter((a) => a.physical || hasIp(a));
  return physical.length ? physical : wired;
}

async function loadAdapters() {
  S.adapters = await invoke("list_adapters");
  const wired = cableAdapters();
  if (S.selected === null || !wired.some((a) => a.index === S.selected)) {
    const best = wired.find(hasIp) || wired.find((a) => a.up) || wired[0];
    S.selected = best ? best.index : null;
  }
  render();
}
$("refreshAdapters").addEventListener("click", loadAdapters);

function renderPc() {
  if (S.step !== "pc") return;
  const list = $("adapters");
  const wired = cableAdapters();
  list.innerHTML = "";
  if (!wired.length) list.innerHTML = `<p class="status">${t("no_adapters")}</p>`;
  for (const a of wired) {
    const l = document.createElement("label");
    l.className = "adapter";
    const tags = [];
    if (hasIp(a)) tags.push(`<span class="tag ok">${t("adapter_ready")}</span>`);
    else tags.push(`<span class="tag">${a.dhcp ? t("adapter_dhcp") : t("adapter_static")}</span>`);
    tags.push(`<span class="tag">${a.up ? t("adapter_up") : t("adapter_down")}</span>`);
    l.innerHTML = `<input type="radio" name="adapter" ${a.index === S.selected ? "checked" : ""}>
      <span class="name">${esc(a.name)}</span>
      <span class="tags">${tags.join("")}</span>
      <span class="desc">${esc(a.description)}${a.addrs.length ? " — " + esc(a.addrs.map((x) => x.ip).join(", ")) : ""}</span>`;
    l.querySelector("input").addEventListener("change", () => {
      S.selected = a.index;
      S.autoOk = false;
      render();
    });
    list.appendChild(l);
  }
  const warn = $("pcWarnings");
  warn.innerHTML = "";
  for (const a of S.adapters) {
    if (a.index !== S.selected && inSubnet(a)) {
      const d = document.createElement("div");
      d.className = "finding warning";
      d.innerHTML = t("warn_same_subnet", { name: a.name });
      warn.appendChild(d);
    }
  }
  const windows = S.platform === "windows";
  $("autoIp").hidden = !windows;
  $("autoIp").disabled = S.selected === null;
  if (!windows) {
    $("manualGuide").hidden = false;
    $("manualGuide").querySelector("h2").hidden = true;
    $("manualGuide").querySelector("ol").hidden = true;
    $("pcStatus").innerHTML = t("manual_other_os");
  }
}

$("autoIp").addEventListener("click", async () => {
  if (S.selected === null) { $("pcStatus").innerHTML = t("pick_adapter"); return; }
  const a = S.adapters.find((x) => x.index === S.selected);
  $("autoIp").disabled = true;
  $("pcStatus").innerHTML = t("auto_ip_wait");
  try {
    await invoke("configure_adapter", { index: S.selected });
    S.autoOk = true;
    $("manualGuide").hidden = true;
    $("pcStatus").innerHTML = t("auto_ip_ok", { name: a ? a.name : "" });
    await loadAdapters();
  } catch (e) {
    const msg = String(e);
    $("pcStatus").innerHTML = msg === "cancelled" ? t("auto_ip_cancel") : t("auto_ip_fail", { err: msg });
    $("manualGuide").hidden = false;
  }
  $("autoIp").disabled = false;
  render();
});
$("manualIp").addEventListener("click", () => {
  $("manualGuide").hidden = false;
  $("manualGuide").scrollIntoView({ behavior: "smooth", block: "nearest" });
});
$("manualDone").addEventListener("change", (e) => {
  S.manualDone = e.target.checked;
  render();
});

/* Step 4: recovery ------------------------------------------------------ */
function setPhase(phase, args) {
  S.phase = phase;
  S.phaseArgs = args || {};
  render();
}

async function startRecovery() {
  clearTimeout(S.doneTimer);
  S.pct = 0;
  S.rate = 0;
  $("routerIp").textContent = "—";
  setPhase("starting");
  try {
    await invoke("start_recovery", { bindAny: false });
  } catch (e) {
    setPhase("fatal", { message: String(e) });
  }
}
function stopRecovery() {
  clearTimeout(S.doneTimer);
  invoke("stop_recovery").catch(() => {});
}

const PHASE_TEXT = {
  starting: ["flash_listen_t", "flash_listen_l", "listening"],
  waiting: ["flash_wait_link_t", "flash_wait_link_l", "waiting"],
  listening: ["flash_listen_t", "flash_listen_l", "listening"],
  found: ["flash_found_t", "flash_found_l", "found"],
  sending: ["flash_send_t", "flash_send_l", "sending"],
  done: ["flash_done_t", "flash_done_l", "done"],
  failed: ["flash_failed_t", "flash_failed_l", "failed"],
  busy: ["flash_busy_t", "flash_busy_l", "failed"],
  denied: ["flash_denied_t", "flash_denied_l", "failed"],
  fatal: ["flash_fatal_t", "flash_fatal_l", "failed"],
};

function renderFlash() {
  if (S.step !== "flash") return;
  const [tt, ll, vis] = PHASE_TEXT[S.phase] || PHASE_TEXT.starting;
  $("flashTitle").innerHTML = t(tt, S.phaseArgs);
  $("flashLead").innerHTML = t(ll, S.phaseArgs);
  $("link").dataset.state = vis;
  const showMeter = ["sending", "done"].includes(S.phase);
  $("meter").hidden = !showMeter;
  $("wireFill").style.width = (showMeter ? S.pct : 0) + "%";
  $("pct").textContent = S.pct + "%";
  $("rate").textContent = S.phase === "sending" && S.rate ? t("rate", { mb: (S.rate / 1e6).toFixed(1) }) : "";
  $("ledHint").innerHTML =
    ["starting", "waiting", "listening", "found"].includes(S.phase) ? t("led_waiting") :
    S.phase === "sending" ? t("led_sending") : "";
}

function log(key, args) {
  const li = document.createElement("li");
  const now = new Date().toLocaleTimeString(LANG, { hour12: false });
  li.innerHTML = `<time>${now}</time>${t(key, args)}`;
  const ol = $("log");
  ol.appendChild(li);
  ol.scrollTop = ol.scrollHeight;
}

T.event.listen("recovery", ({ payload: e }) => {
  switch (e.type) {
    case "listening":
      log("ev_listening", e);
      if (["starting", "waiting"].includes(S.phase)) setPhase("listening");
      break;
    case "waiting_link":
      log("ev_waiting_link");
      setPhase("waiting");
      break;
    case "dhcp_request":
      log("ev_dhcp_request", { ...e, vendor: e.vendor ? ", " + e.vendor : "" });
      break;
    case "dhcp_reply":
      log("ev_dhcp_reply", e);
      $("routerIp").textContent = e.ip;
      if (["starting", "waiting", "listening", "failed"].includes(S.phase)) setPhase("found", { ip: e.ip });
      break;
    case "tftp_request":
      log("ev_tftp_request", e);
      $("routerIp").textContent = e.peer.split(":")[0];
      S.pct = 0;
      setPhase("sending");
      break;
    case "tftp_progress":
      S.pct = Math.floor((e.sent * 100) / Math.max(1, e.total));
      S.rate = e.bytes_per_sec;
      renderFlash();
      break;
    case "tftp_done":
      S.pct = 100;
      log("ev_tftp_done", { secs: e.secs.toFixed(1), retransmits: e.retransmits });
      setPhase("done");
      S.doneTimer = setTimeout(() => S.step === "flash" && go("finish"), 4000);
      break;
    case "tftp_failed":
      log("ev_tftp_failed", e);
      setPhase("failed", { reason: e.reason });
      break;
    case "warning":
      log("ev_warning", e);
      break;
    case "fatal":
      log("ev_warning", e);
      setPhase(e.busy ? "busy" : e.denied ? "denied" : "fatal", { message: e.message, exe: e.exe || "miwifi-recovery" });
      break;
  }
});

/* Step 5: result -------------------------------------------------------- */
async function startProbe() {
  stopRecovery(); // the router runs its own DHCP server once it boots
  stopProbe();
  S.routerUp = false;
  render();
  $("restoreNet").hidden = !(await invoke("pending_restore"));
  const tick = async () => {
    if (S.step !== "finish") return;
    if (await invoke("probe_router")) {
      S.routerUp = true;
      render();
      return;
    }
    S.probeTimer = setTimeout(tick, 3000);
  };
  tick();
}
function stopProbe() {
  clearTimeout(S.probeTimer);
}
$("tryAgain").addEventListener("click", () => go("flash"));
$("openRouter").addEventListener("click", () => T.opener.openUrl("http://192.168.31.1"));

async function restoreNetwork(statusEl) {
  try {
    await invoke("restore_adapter");
    statusEl.innerHTML = t("restore_ok");
    $("restoreBanner").hidden = true;
    $("restoreNet").hidden = true;
    S.autoOk = false;
  } catch (e) {
    statusEl.innerHTML = t("restore_fail", { err: String(e) });
  }
}
$("restoreNet").addEventListener("click", () => restoreNetwork($("probeStatus")));
$("restoreNow").addEventListener("click", () => restoreNetwork($("restoreBanner").querySelector("p")));

/* Start ----------------------------------------------------------------- */
(async () => {
  try { S.platform = await invoke("platform"); } catch (_) {}
  applyLang();
  go("firmware");
  try {
    const name = await invoke("pending_restore");
    if (name) {
      $("restoreBanner").hidden = false;
      $("restoreBanner").querySelector("p").innerHTML = t("pending_restore", { name });
    }
  } catch (_) {}
})();
