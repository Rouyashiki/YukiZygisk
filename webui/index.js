/* SPDX-License-Identifier: MIT */
/*
 * YukiZygisk - Material WebUI and asynchronous runtime controls.
 * Derived from KOWX712/ksu-webui-demo and Kagami's static WebUI.
 * License: MIT
 * Authors: KOWX712 and Anatdx
 */
import "./assets/material.js";
import { DEFAULT_CONFIG, DEFAULT_STATUS, PATHS, api, getRuntimeMode } from "./api.js";
import { enableEdgeToEdge, setFullScreen } from "./assets/kernelsu.js";
import { LANGUAGE_OPTIONS, getNavigatorLanguage, translations } from "./i18n.js";

const TABS = [
  { id: "status", icon: "activity" },
  { id: "modules", icon: "layers" },
  { id: "settings", icon: "settings-2" },
  { id: "about", icon: "info" },
];
const params = new URLSearchParams(location.search);
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
const motionEasing = "cubic-bezier(0.2, 0.8, 0.2, 1)";
function preference(key, fallback) {
  try { return localStorage.getItem(`yukizygisk_${key}`) || fallback; }
  catch { return fallback; }
}
function storePreference(key, value) {
  try { localStorage.setItem(`yukizygisk_${key}`, value); }
  catch { /* Some hosts disable local storage. Runtime controls still work. */ }
}
const state = {
  tab: TABS.some(({ id }) => id === params.get("tab")) ? params.get("tab") : "status",
  language: preference("language", getNavigatorLanguage()),
  theme: preference("theme", "system"),
  nativeView: preference("native_view", "module"),
  moduleKind: preference("module_kind", "zygisk"),
  runtimeMode: getRuntimeMode(),
  status: { ...DEFAULT_STATUS },
  config: { ...DEFAULT_CONFIG },
  system: { model: "\u2014", android: "\u2014", kernel: "\u2014", selinux: "\u2014" },
  meta: { name: "YukiZygisk", version: "dev", author: "Anatdx" },
  statusReady: false,
  configReady: false,
  configError: "",
  refreshing: false,
  saving: false,
  savePhase: "",
  lastUpdated: "",
};
if (!LANGUAGE_OPTIONS.some(({ value }) => value === state.language)) state.language = getNavigatorLanguage();
if (!["system", "light", "dark"].includes(state.theme)) state.theme = "system";
if (!["module", "process"].includes(state.nativeView)) state.nativeView = "module";
if (!["zygisk", "native"].includes(state.moduleKind)) state.moduleKind = "zygisk";

let confirmedConfig = { ...DEFAULT_CONFIG };
let configRevision = 0;
const fieldRevisions = Object.fromEntries(Object.keys(DEFAULT_CONFIG).map((key) => [key, 0]));
const pendingKeys = new Set();
let savingKeys = new Set();
let saveTimer;
let refreshPromise;
let toastTimer;
let pollTimer;
let runtimeRevision = 0;
let deferredTelemetry = false;
let closingDialog = false;
let dialogClosePromise;
let dialogBackPending = false;
let navigationRevision = 0;
let pendingTabNavigation = null;
const scrollPositions = {};
const mountedViews = new Set();

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}
function t(key, fallback = key, values = {}) {
  return String(translations[state.language]?.[key] ?? translations.en[key] ?? fallback)
    .replace(/\{(\w+)\}/g, (_match, name) => String(values[name] ?? `{${name}}`));
}
function icon(name, className = "") {
  return `<svg class="icon ${className}" viewBox="0 0 24 24" aria-hidden="true"><use href="./assets/icons.svg#${name}"></use></svg>`;
}
function iconButton(action, name, label, extra = "") {
  return `<md-icon-button data-action="${action}" aria-label="${escapeHtml(label)}" title="${escapeHtml(label)}" ${extra}>${icon(name)}</md-icon-button>`;
}
function ripple(disabled = false, controlId = "") {
  return `<md-ripple ${controlId ? `for="${escapeHtml(controlId)}"` : ""} ${disabled || reducedMotion.matches ? "disabled" : ""}></md-ripple>`;
}
function animateSurface(element, { exiting = false, dialog = false } = {}) {
  if (reducedMotion.matches) return Promise.resolve();
  const offset = dialog ? "translateY(16px) scale(0.96)" : "translateY(10px)";
  const frames = [{ opacity: 0, transform: offset }, { opacity: 1, transform: "none" }];
  for (const animation of element.getAnimations()) animation.cancel();
  const animation = element.animate(exiting ? frames.reverse() : frames, {
    duration: exiting ? 140 : 280, easing: motionEasing,
  });
  return animation.finished.catch(() => {});
}
function showToast(message, tone = "success") {
  clearTimeout(toastTimer);
  const stack = document.getElementById("toast-stack");
  stack.innerHTML = `<div class="toast ${tone}">${icon(tone === "danger" ? "circle-alert" : "check")}<span>${escapeHtml(message)}</span><button data-action="dismiss-toast" aria-label="${escapeHtml(t("common.close"))}">${icon("x")}</button></div>`;
  const toast = stack.firstElementChild;
  requestAnimationFrame(() => toast.classList.add("visible"));
  toastTimer = setTimeout(() => toast.remove(), tone === "danger" ? 7000 : 3000);
}
function applyTheme() {
  if (state.theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = state.theme;
}
function rootImplLabel() {
  const keys = { "kernelsu-redirect": "root.ksuRedirect", kernelsu: "root.ksu", kernelpatch: "root.kernelPatch", unsupported: "root.unsupported" };
  return t(keys[state.status.root_impl] || "common.unknown");
}
function policySourceLabel() {
  const keys = { kernel: "policy.kernel", "userspace-ksu-api": "policy.ksuUserspace", "userspace-apatch-config": "policy.apatchUserspace" };
  return t(keys[state.status.root_policy_source] || "common.unknown");
}
function stateBadge(value) {
  const tones = { loaded: "success", injected: "success", failed: "danger", crashed: "danger", suspended: "warning" };
  return `<span class="badge ${tones[value] || "muted"}">${escapeHtml(t(`state.${value}`, value || t("common.unknown")))}</span>`;
}
function combinedNativeState(items, fallback = "unknown") {
  for (const candidate of ["crashed", "failed", "suspended", "injected", "unsupported32"])
    if (items.some((item) => item.state === candidate)) return candidate;
  return fallback;
}
function sectionHeader(title, trailing = "") {
  return `<div class="section-heading"><h2>${escapeHtml(title)}</h2>${trailing}</div>`;
}
function emptyState(message, symbol = "boxes") {
  return `<div class="empty-state">${icon(symbol)}<span>${escapeHtml(message)}</span></div>`;
}
function infoItem(label, value, code = false) {
  return `<div><dt>${escapeHtml(label)}</dt><dd>${code ? `<code>${escapeHtml(value)}</code>` : escapeHtml(value)}</dd></div>`;
}
function metric(label, value) {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}
function statusPresentation() {
  if (!state.statusReady) return { tone: "", icon: "loader-circle", title: t("common.loading"), description: "" };
  if (state.status.safe_mode) return { tone: "warning", icon: "shield-alert", title: t("status.safeMode"), description: t("status.safeModeDesc") };
  if (state.status.available && state.status.kernel_alive) return { tone: "success", icon: "shield-check", title: t("status.running"), description: state.status.abi };
  return { tone: "danger", icon: "circle-alert", title: t("status.unavailable"), description: state.status.error || t("status.unavailableDesc") };
}
function renderStatus() {
  const presentation = statusPresentation();
  const zygotes = state.status.zygote_monitor || [];
  return `${!state.statusReady ? '<div class="loading-line" role="progressbar" aria-label="Loading"></div>' : ""}
    <div class="runtime-overview ${presentation.tone}" role="status">
      <div class="runtime-symbol ${!state.statusReady ? "spinning" : ""}">${icon(presentation.icon)}</div>
      <div class="runtime-copy"><h2>${escapeHtml(presentation.title)}</h2><p>${escapeHtml(presentation.description)}</p><span class="status-time">${state.lastUpdated ? `${escapeHtml(t("status.lastUpdate"))} ${escapeHtml(state.lastUpdated)}` : ""}</span></div>
      ${iconButton("refresh", "refresh-cw", t("common.refresh"))}
    </div>
    ${state.status.safe_mode ? `<div class="alert warning">${icon("shield-alert")}<div><strong>${escapeHtml(t("status.safeModeTitle"))}</strong><p>${escapeHtml(t("status.safeModeBody"))}</p><p>${escapeHtml(state.status.safe_mode_zygote)} \u00b7 ${escapeHtml(state.status.zygote_crashes)}</p></div></div>` : ""}
    <div class="metrics">
      ${metric(t("status.zygiskModules"), state.statusReady ? state.status.modules.length : "\u2014")}
      ${metric(t("status.nativeModules"), state.statusReady ? nativeGroups().length : "\u2014")}
    </div>
    <section class="section">${sectionHeader(t("status.zygoteMonitor"), `<small>${zygotes.length}</small>`)}
      <div class="row-list">${zygotes.length ? zygotes.map((item) => `<div class="list-row"><div class="row-symbol plain">${icon("adb")}</div><div class="row-copy"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.abi)}</small></div><div class="row-trailing">${stateBadge(item.state)}<code>PID ${escapeHtml(item.pid)}</code></div></div>`).join("") : emptyState(t(state.statusReady ? "common.none" : "common.loading"), "adb")}</div>
    </section>
    <div class="info-columns">
      <section class="section">${sectionHeader(t("status.deviceInfo"))}<dl class="info-list">
        ${infoItem(t("status.device"), state.system.model)}${infoItem(t("status.android"), state.system.android)}${infoItem(t("status.kernel"), state.system.kernel, true)}${infoItem(t("status.selinux"), state.system.selinux)}
      </dl></section>
      <section class="section">${sectionHeader(t("status.runtimeInfo"))}<dl class="info-list">
        ${infoItem(t("status.rootImpl"), rootImplLabel())}
        ${infoItem(t("common.abi"), state.status.abi)}
      </dl></section>
    </div>`;
}
function nativeGroups() {
  const groups = new Map();
  for (const scope of state.status.native_modules || []) {
    const group = groups.get(scope.id) || { id: scope.id, scopes: [], records: [] };
    group.scopes.push(scope);
    groups.set(scope.id, group);
  }
  for (const record of state.status.native_injections || []) groups.get(record.module)?.records.push(record);
  return [...groups.values()];
}
function nativeProcesses() {
  const groups = new Map();
  for (const record of state.status.native_injections || []) {
    const key = `${record.pid}\u0000${record.process}`;
    const group = groups.get(key) || { pid: record.pid, process: record.process || record.target, abi: record.abi, records: [] };
    group.records.push(record);
    groups.set(key, group);
  }
  return [...groups.values()].sort((a, b) => String(a.process).localeCompare(String(b.process)) || Number(a.pid) - Number(b.pid));
}
function processName(value) {
  return String(value || "").split("/").pop();
}
function evidenceNote(moduleId) {
  return (state.status.crash_evidence || []).some((item) => item.module === moduleId)
    ? `<small class="evidence-note">${escapeHtml(t("status.crashEvidence"))}</small>` : "";
}
function moduleRow({ title, subtitle, symbol, value, type, index, note = "", trailing = "" }) {
  return `<button class="list-row" data-detail="${type}" data-index="${index}" data-row-key="${escapeHtml(`${type}:${title}:${trailing}`)}" aria-label="${escapeHtml(`${title}, ${t("common.details")}`)}">
    <div class="row-symbol ${type === "native" || type === "process" ? "native" : ""}">${icon(symbol)}</div><div class="row-copy"><strong>${escapeHtml(title)}</strong><small>${escapeHtml(subtitle)}</small>${note}</div><div class="row-trailing">${stateBadge(value)}${trailing}</div>${icon("chevron-right", "chevron")}${ripple()}</button>`;
}
function segmentButton(attribute, value, label, selected) {
  return `<button ${attribute}="${value}" aria-pressed="${selected}"><span class="segment-check">${icon("check")}</span><span class="segment-label">${escapeHtml(label)}</span>${ripple()}</button>`;
}
function renderModules() {
  const native = state.moduleKind === "native";
  let rows;
  if (!native) {
    rows = state.status.modules.map((module, index) => {
      const id = typeof module === "string" ? module : module.id;
      return moduleRow({ title: typeof module === "object" ? module.name || id : id, subtitle: "Zygisk API", symbol: "boxes", value: (state.status.suspended_modules || []).includes(id) ? "suspended" : "discovered", type: "zygisk", index, note: evidenceNote(id) });
    });
  } else if (state.nativeView === "module") {
    rows = nativeGroups().map((group, index) => moduleRow({ title: group.id, subtitle: t("status.nativeProcessCount", "", { count: new Set(group.records.map((record) => `${record.pid}\u0000${record.process}`)).size }), symbol: "layers", value: combinedNativeState([...group.scopes, ...group.records]), type: "native", index, note: evidenceNote(group.id) }));
  } else {
    rows = nativeProcesses().map((group, index) => moduleRow({ title: processName(group.process), subtitle: [...new Set(group.records.map(({ module }) => module))].join(" \u00b7 "), symbol: "terminal", value: combinedNativeState(group.records), type: "process", index, trailing: `<code>PID ${escapeHtml(group.pid)}</code>` }));
  }
  return `<div class="segmented module-tabs" aria-label="${escapeHtml(t("nav.modules"))}">
    ${segmentButton("data-module-kind", "zygisk", "Zygisk", !native)}${segmentButton("data-module-kind", "native", "Native", native)}
    </div><section class="section">${sectionHeader(t(native ? "status.nativeInjections" : "status.modules"), native ? `<div class="segmented" aria-label="${escapeHtml(t("status.nativeSwitchView"))}">${segmentButton("data-native-view", "module", t("status.nativeByModule"), state.nativeView === "module")}${segmentButton("data-native-view", "process", t("status.nativeByProcess"), state.nativeView === "process")}</div>` : `<small>${state.status.modules.length}</small>`)}
    <div class="row-list module-list">${rows.length ? rows.join("") : emptyState(t(!native ? "status.noModules" : state.nativeView === "module" ? "status.noNativeModules" : "status.noNativeInjections"))}</div></section>`;
}
function switchRow(key, id, symbol, title, description) {
  return `<label class="setting-row" for="${id}" data-setting="${key}" data-checked="${state.config[key]}" aria-disabled="${!state.configReady}"><span class="setting-icon">${icon(symbol)}</span><span class="row-copy"><strong id="label-${key}">${escapeHtml(title)}</strong><small id="description-${key}">${escapeHtml(description)}</small></span><md-switch id="${id}" data-config="${key}" aria-labelledby="label-${key}" aria-describedby="description-${key}" icons ${state.config[key] ? "selected" : ""} ${!state.configReady ? "disabled" : ""}></md-switch>${ripple(!state.configReady)}</label>`;
}
function denylistControls() {
  return `<div id="denylist-mode" class="segmented connected-choice" data-config="denylist_mode" role="radiogroup" aria-labelledby="denylist-label">${["Off", "Skip", "Revert"].map((name, value) => `<button data-denylist-mode="${value}" role="radio" aria-checked="${state.config.denylist_mode === value}" aria-pressed="${state.config.denylist_mode === value}" aria-label="${escapeHtml(t(`settings.denylist${name}`))}" title="${escapeHtml(t(`settings.denylist${name}`))}" ${!state.configReady ? "disabled" : ""}><span class="segment-check">${icon("check")}</span><span class="segment-label">${escapeHtml(t(`settings.denylist${name}Short`))}</span>${ripple(!state.configReady)}</button>`).join("")}</div>`;
}
function renderSettings() {
  return `<div class="config-error" id="config-error" ${!state.configError ? "hidden" : ""}><span>${escapeHtml(t("settings.loadFailed"))}</span><md-text-button data-action="retry-config">${escapeHtml(t("common.retry"))}</md-text-button></div>
    <section class="settings-group">${sectionHeader(t("settings.runtime"), '<span id="save-status" class="save-status" role="status"></span>')}
      <div class="setting-list">${switchRow("anonymous_memory", "setting-anonymous-memory", "memory-stick", t("settings.anonymousMemory"), t("settings.anonymousMemoryDesc"))}
      ${switchRow("yukilinker", "setting-yukilinker", "link", t("settings.yukilinker"), t("settings.yukilinkerDesc"))}
      ${switchRow("crash_protection", "setting-crash-protection", "shield-check", t("settings.crashProtection"), t("settings.crashProtectionDesc"))}</div>
    </section>
    <section class="settings-group"><h2>${escapeHtml(t("settings.hiding"))}</h2>
      <div class="setting-list"><div class="setting-row choice-row" data-setting="denylist_mode"><span class="setting-icon">${icon("shield-alert")}</span><div class="row-copy"><strong id="denylist-label">${escapeHtml(t("settings.denylistMode"))}</strong><small id="denylist-description">${escapeHtml(t("settings.denylistDesc", "", { root: rootImplLabel() }))}</small></div><div class="choice-field">${denylistControls()}</div></div>
      <button class="list-row" data-detail="policy"><div class="row-symbol plain">${icon("info")}</div><div class="row-copy"><strong>${escapeHtml(t("settings.policyTitle"))}</strong><small id="policy-owner">${escapeHtml(rootImplLabel())}</small></div>${icon("chevron-right", "chevron")}${ripple()}</button></div>
    </section>
    <section class="settings-group"><h2>${escapeHtml(t("settings.diagnostics"))}</h2><div class="setting-list">${switchRow("dmesg_log", "setting-dmesg", "logs", t("settings.dmesg"), t("settings.dmesgDesc"))}</div></section>
    <section class="settings-group"><h2>${escapeHtml(t("settings.appearance"))}</h2>
      <div class="setting-list"><div class="setting-row"><span class="setting-icon">${icon("monitor")}</span><div class="row-copy"><strong id="theme-label">${escapeHtml(t("common.theme"))}</strong></div><select id="theme-select" aria-labelledby="theme-label">${["system", "light", "dark"].map((value) => `<option value="${value}" ${state.theme === value ? "selected" : ""}>${escapeHtml(t(`common.${value}`))}</option>`).join("")}</select></div>
      <div class="setting-row"><span class="setting-icon">${icon("languages")}</span><div class="row-copy"><strong id="language-label">${escapeHtml(t("common.language"))}</strong></div><select id="language-select" aria-labelledby="language-label">${LANGUAGE_OPTIONS.map(({ value, label }) => `<option value="${value}" ${state.language === value ? "selected" : ""}>${escapeHtml(label)}</option>`).join("")}</select></div></div>
    </section>`;
}
function linkRow(href, title, subtitle, symbol = "external-link") {
  return `<a class="list-row" href="${href}" target="_blank" rel="noopener noreferrer"><div class="row-symbol plain">${icon(symbol)}</div><div class="row-copy"><strong>${escapeHtml(title)}</strong>${subtitle ? `<small>${escapeHtml(subtitle)}</small>` : ""}</div>${icon("external-link", "chevron")}${ripple()}</a>`;
}
function renderAbout() {
  return `<div class="about-identity"><img src="./icon.svg" alt=""><div><h2>YukiZygisk</h2><p>${escapeHtml(state.meta.version)} \u00b7 ${escapeHtml(state.status.abi)}</p></div></div>
    <p class="about-description">${escapeHtml(t("about.description"))}</p>
    <section class="section">${sectionHeader(t("about.project"))}<div class="row-list">${linkRow("https://github.com/Rouyashiki/YukiZygisk", "Rouyashiki / YukiZygisk", t("about.author") + ": " + state.meta.author)}</div></section>
    <section class="section">${sectionHeader(t("about.credits"))}<div class="row-list">
      ${linkRow("https://github.com/tiann/KernelSU", "KernelSU", "GPL-3.0")}
      ${linkRow("https://github.com/KOWX712/ksu-webui-demo", "KOWX712 / ksu-webui-demo", "MIT")}
      ${linkRow("https://github.com/material-components/material-web", "Material Web", "Apache-2.0")}
      ${linkRow("https://lucide.dev", "Lucide", "ISC")}
    </div></section><dl class="info-list">${infoItem(t("about.license"), "Apache-2.0 / GPL-2.0")}</dl>`;
}
function navItems(placement) {
  return TABS.map(({ id, icon: symbol }) => `<button id="nav-${placement}-${id}" class="nav-item" data-tab="${id}" ${id === state.tab ? 'aria-current="page"' : ""}><span class="nav-icon">${icon(symbol)}${ripple(false, `nav-${placement}-${id}`)}</span><span class="nav-label">${escapeHtml(t(`nav.${id}`))}</span></button>`).join("");
}
function mountApp() {
  const root = document.getElementById("app");
  root.className = "app-shell";
  root.innerHTML = `<div class="workspace"><nav class="side-nav" aria-label="${escapeHtml(t("nav.status"))}">${navItems("side")}</nav><main class="page"><div class="page-heading"><h1 id="page-title">${escapeHtml(t(`nav.${state.tab}`))}</h1><small id="page-version">${escapeHtml(state.meta.version)}</small></div>${TABS.map(({ id }) => `<div class="view" id="view-${id}" ${id !== state.tab ? "hidden" : ""}></div>`).join("")}</main></div>
    <nav class="bottom-nav" aria-label="${escapeHtml(t("nav.status"))}">${navItems("bottom")}</nav>`;
  mountedViews.clear();
  renderView(state.tab);
  updateChrome();
}
function renderView(tab) {
  const view = document.getElementById(`view-${tab}`);
  if (!view) return;
  const active = document.activeElement;
  const focused = view.contains(active) ? active.closest("[data-row-key], [data-action], [data-module-kind], [data-native-view]") : null;
  const focusKey = focused ? Object.entries(focused.dataset).find(([key]) => ["rowKey", "action", "moduleKind", "nativeView"].includes(key)) : null;
  const renderers = { status: renderStatus, modules: renderModules, settings: renderSettings, about: renderAbout };
  const markup = renderers[tab]();
  if (view.__markup !== markup) {
    view.innerHTML = markup;
    view.__markup = markup;
    if (focusKey) [...view.querySelectorAll("button, md-icon-button")].find((button) => button.dataset[focusKey[0]] === focusKey[1])?.focus({ preventScroll: true });
  }
  mountedViews.add(tab);
  if (tab === "settings") updateConfigControls();
  updateChrome();
}
function updateTelemetryViews() {
  // Hidden views are rendered on entry; settings controls retain their DOM and focus.
  if (document.getElementById("detail-dialog").open) deferredTelemetry = true;
  else if (state.tab !== "settings") renderView(state.tab);
  for (const tab of ["status", "modules", "about"]) if (tab !== state.tab) mountedViews.delete(tab);
  const description = document.getElementById("denylist-description");
  if (description) description.textContent = t("settings.denylistDesc", "", { root: rootImplLabel() });
  const owner = document.getElementById("policy-owner");
  if (owner) owner.textContent = rootImplLabel();
  document.getElementById("page-version").textContent = state.meta.version;
  restoreDetailFromHistory();
}
function updateChrome() {
  for (const button of document.querySelectorAll('[data-action="refresh"]')) {
    button.classList.toggle("spinning", state.refreshing);
    button.disabled = state.refreshing;
  }
}
function updateConfigControls() {
  for (const control of document.querySelectorAll("[data-config]")) {
    const key = control.dataset.config;
    control.disabled = !state.configReady;
    if (key === "denylist_mode") {
      control.setAttribute("aria-disabled", String(!state.configReady));
      for (const button of control.querySelectorAll("[data-denylist-mode]")) {
        const selected = Number(button.dataset.denylistMode) === state.config[key];
        button.disabled = !state.configReady;
        button.setAttribute("aria-checked", String(selected));
        button.setAttribute("aria-pressed", String(selected));
        button.tabIndex = selected ? 0 : -1;
        button.querySelector("md-ripple").disabled = reducedMotion.matches || !state.configReady;
      }
    } else control.selected = state.config[key];
    const row = control.closest("[data-setting]");
    row.dataset.checked = String(key === "denylist_mode" ? state.config[key] !== 0 : state.config[key]);
    row.setAttribute("aria-disabled", String(!state.configReady));
    row.setAttribute("aria-busy", String(pendingKeys.has(key) || savingKeys.has(key)));
    const rowRipple = row.querySelector(":scope > md-ripple");
    if (rowRipple) rowRipple.disabled = reducedMotion.matches || !state.configReady;
  }
  const error = document.getElementById("config-error");
  if (error) {
    error.hidden = !state.configError;
    error.querySelector("span").textContent = `${t("settings.loadFailed")}: ${state.configError}`;
  }
  const label = document.getElementById("save-status");
  if (label) {
    label.classList.toggle("error", state.savePhase === "error");
    const phase = state.saving || pendingKeys.size ? "saving" : state.savePhase;
    label.innerHTML = phase ? `${icon(phase === "saving" ? "loader-circle" : phase === "error" ? "circle-alert" : "check", phase === "saving" ? "spinning" : "")}<span>${escapeHtml(t(phase === "error" ? "settings.saveFailed" : `settings.${phase}`))}</span>` : "";
  }
  updateChrome();
}
function tabUrl(tab) {
  const url = new URL(location.href);
  url.searchParams.set("tab", tab);
  return url;
}
function initializeNavigation() {
  history.scrollRestoration = "manual";
  // Keep one home entry below a directly opened secondary page. Reloading a
  // managed page or dialog must not add another parent to the stack.
  if (history.state?.yukizygiskPage === state.tab) return;
  const detail = history.state?.yukizygiskDetail;
  history.replaceState({ yukizygiskPage: "status" }, "", tabUrl("status"));
  if (state.tab !== "status") history.pushState({ yukizygiskPage: state.tab }, "", tabUrl(state.tab));
  if (detail) history.pushState({ ...history.state, yukizygiskDetail: detail }, "", location.href);
}
function selectTab(tab) {
  if (!TABS.some(({ id }) => id === tab)) return;
  if (document.getElementById("detail-dialog").open || closingDialog || dialogBackPending) return;
  if (pendingTabNavigation !== null) { pendingTabNavigation = tab; return; }
  if (tab === state.tab) return;
  if (history.state?.yukizygiskPage !== "status") {
    // Bottom destinations are siblings. Remove the old page before inserting
    // its replacement, also discarding any forward history for old dialogs.
    pendingTabNavigation = tab;
    history.back();
    return;
  }
  if (tab !== "status") history.pushState({ yukizygiskPage: tab }, "", tabUrl(tab));
  setTab(tab);
}
function setTab(tab) {
  if (!TABS.some(({ id }) => id === tab) || tab === state.tab) return;
  scrollPositions[state.tab] = window.scrollY;
  state.tab = tab;
  for (const { id } of TABS) document.getElementById(`view-${id}`).hidden = id !== tab;
  for (const button of document.querySelectorAll("[data-tab]")) {
    if (button.dataset.tab === tab) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  document.getElementById("page-title").textContent = t(`nav.${tab}`);
  if (!mountedViews.has(tab)) renderView(tab);
  void animateSurface(document.getElementById(`view-${tab}`));
  window.scrollTo({ top: scrollPositions[tab] || 0, behavior: "instant" });
  schedulePoll();
}

async function refreshData({ includeConfig = true, manual = false, afterMutation = false } = {}) {
  if (refreshPromise) return afterMutation ? refreshPromise.then(() => refreshData({ includeConfig, manual })) : refreshPromise;
  state.refreshing = true;
  updateChrome();
  if (manual) void api.getSelinux().then((selinux) => {
    state.system.selinux = selinux;
    updateTelemetryViews();
  }).catch((error) => showToast(error.message, "danger"));
  const revision = configRevision;
  const runtimeVersion = runtimeRevision;
  const readConfig = includeConfig && !state.saving && pendingKeys.size === 0;
  const requests = [api.getStatus().then((status) => {
    if (runtimeRevision !== runtimeVersion) return;
    state.status = status;
    state.statusReady = true;
    state.lastUpdated = new Date().toLocaleTimeString(state.language, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    updateTelemetryViews();
    if (manual && status.error) showToast(status.error, "danger");
  }).catch((error) => {
    if (runtimeRevision !== runtimeVersion) return;
    state.status = { ...state.status, available: false, kernel_alive: false, error: error.message };
    state.statusReady = true;
    updateTelemetryViews();
    if (manual) showToast(`${t("common.refreshFailed")}: ${error.message}`, "danger");
  })];
  if (readConfig) requests.push(api.loadConfig().then((config) => {
    if (configRevision === revision && !state.saving && pendingKeys.size === 0) {
      confirmedConfig = { ...config };
      state.config = { ...config };
      state.configReady = true;
      state.configError = "";
      updateConfigControls();
    }
  }).catch((error) => {
    if (configRevision === revision) {
      state.configError = error.message;
      state.configReady = false;
      updateConfigControls();
    }
  }));
  refreshPromise = Promise.allSettled(requests).finally(() => {
    state.refreshing = false;
    refreshPromise = undefined;
    updateChrome();
    schedulePoll();
  });
  return refreshPromise;
}
function queueConfig(key, value) {
  if (!state.configReady || !(key in DEFAULT_CONFIG)) return;
  state.config[key] = value;
  fieldRevisions[key] += 1;
  configRevision += 1;
  pendingKeys.add(key);
  state.savePhase = "saving";
  updateConfigControls();
  clearTimeout(saveTimer);
  saveTimer = setTimeout(flushConfig, 160);
}
async function flushConfig() {
  clearTimeout(saveTimer);
  if (state.saving || !pendingKeys.size) return;
  state.saving = true;
  while (pendingKeys.size) {
    const snapshot = { ...state.config };
    const revisions = { ...fieldRevisions };
    savingKeys = new Set(pendingKeys);
    pendingKeys.clear();
    updateConfigControls();
    try {
      runtimeRevision += 1;
      confirmedConfig = { ...await api.saveConfig(snapshot) };
      state.savePhase = "saved";
      for (const key of Object.keys(DEFAULT_CONFIG)) if (fieldRevisions[key] === revisions[key]) state.config[key] = confirmedConfig[key];
    } catch (error) {
      // yzctl can persist the file before runtime reload fails. Read disk before reconciling.
      try {
        confirmedConfig = { ...await api.loadConfig() };
        state.configError = "";
      } catch (readError) {
        state.configError = readError.message;
        state.configReady = false;
        pendingKeys.clear();
      }
      for (const key of Object.keys(DEFAULT_CONFIG)) if (fieldRevisions[key] === revisions[key]) state.config[key] = confirmedConfig[key];
      state.savePhase = "error";
      showToast(`${t("settings.saveFailed")}: ${error.message}`, "danger");
    }
    savingKeys.clear();
    updateConfigControls();
  }
  state.saving = false;
  updateConfigControls();
  await refreshData({ includeConfig: false, afterMutation: true });
}
function schedulePoll() {
  clearTimeout(pollTimer);
  if (document.hidden || !["status", "modules"].includes(state.tab)) return;
  pollTimer = setTimeout(() => refreshData({ includeConfig: false }), 8000);
}

function crashEvidence(moduleId) {
  const evidence = (state.status.crash_evidence || []).filter((item) => item.module === moduleId);
  if (!evidence.length) return "";
  return `<h3>${escapeHtml(t("status.crashEvidence"))}</h3><p>${escapeHtml(t("status.crashEvidenceDesc"))}</p>${evidence.map((item) => `<div class="evidence-record"><dl class="info-list">${infoItem(t("status.process"), item.process)}${infoItem("PID", item.pid)}${infoItem(t("common.abi"), item.abi)}${infoItem(t("status.lastUpdate"), item.timestamp)}${infoItem("Tombstone", item.tombstone, true)}</dl><pre>${escapeHtml(item.frame)}</pre></div>`).join("")}`;
}
function nativeRecordDetails(record) {
  return `<dl class="info-list">${infoItem(t("nav.modules"), record.module || "\u2014")}${infoItem(t("status.process"), record.process || record.target)}${infoItem("PID", record.pid ?? "\u2014")}${infoItem(t("common.abi"), record.abi || "\u2014")}${infoItem(t("status.target"), `${record.target_type}=${record.target}`, true)}${infoItem(t("status.companion"), t(record.companion ? "status.enabled" : "status.disabled"))}</dl>${stateBadge(record.state)}`;
}
function openDetail(type, index, { updateHistory = true } = {}) {
  const dialog = document.getElementById("detail-dialog");
  if (dialog.open || closingDialog || dialogBackPending || pendingTabNavigation !== null) return;
  const detail = { type };
  let title, body;
  if (type === "policy") {
    title = t("settings.policyTitle");
    body = `<p>${escapeHtml(t("settings.policyDesc"))}</p><dl class="info-list">${infoItem(t("settings.policyOwner"), rootImplLabel())}${infoItem(t("status.denylistSource"), policySourceLabel())}${infoItem(t("status.policyCache"), t(state.status.root_policy_cache_ready ? "policy.ready" : "policy.pending"))}${infoItem(t("settings.configPath"), PATHS.CONFIG, true)}</dl>`;
  } else if (type === "zygisk") {
    const module = state.status.modules[index];
    if (!module) return;
    const id = typeof module === "string" ? module : module.id;
    detail.id = id;
    title = typeof module === "object" ? module.name || id : id;
    body = `<dl class="info-list">${infoItem("ID", id)}${infoItem(t("common.abi"), state.status.abi)}</dl>${stateBadge(state.status.suspended_modules.includes(id) ? "suspended" : "discovered")}${crashEvidence(id)}`;
  } else if (type === "native") {
    const group = nativeGroups()[index];
    if (!group) return;
    detail.id = group.id;
    title = group.id;
    body = `${stateBadge(combinedNativeState([...group.scopes, ...group.records]))}<h3>${escapeHtml(t("status.target"))}</h3>${group.scopes.map((scope) => `<dl class="info-list">${infoItem(scope.target_type, scope.target, true)}${infoItem(t("status.companion"), t(scope.companion ? "status.enabled" : "status.disabled"))}</dl>`).join("")}<h3>${escapeHtml(t("status.nativeByProcess"))}</h3>${group.records.length ? group.records.map((record) => `<div class="evidence-record">${nativeRecordDetails(record)}</div>`).join("") : `<p>${escapeHtml(t("status.noNativeInjections"))}</p>`}${crashEvidence(group.id)}`;
  } else if (type === "process") {
    const group = nativeProcesses()[index];
    if (!group) return;
    detail.pid = group.pid;
    detail.process = group.process;
    title = processName(group.process);
    body = `<dl class="info-list">${infoItem(t("status.process"), group.process, true)}${infoItem("PID", group.pid)}${infoItem(t("common.abi"), group.abi)}</dl><h3>${escapeHtml(t("nav.modules"))}</h3>${group.records.map((record) => `<div class="evidence-record">${nativeRecordDetails(record)}</div>`).join("")}`;
  } else return;
  document.getElementById("dialog-title").textContent = title;
  document.getElementById("dialog-body").innerHTML = body;
  const close = dialog.querySelector('[data-action="close-dialog"]');
  close.innerHTML = icon("x");
  close.setAttribute("aria-label", t("common.close"));
  close.setAttribute("title", t("common.close"));
  // Android WebUI hosts route system Back through WebView history.
  // Keep the dialog above its tab, including when opened on the entry page.
  if (updateHistory) history.pushState({ ...history.state, yukizygiskDetail: detail }, "", location.href);
  dialog.showModal();
  void animateSurface(dialog, { dialog: true });
}
function closeDetail() {
  const dialog = document.getElementById("detail-dialog");
  if (!dialog.open || closingDialog || dialogBackPending) return;
  if (history.state?.yukizygiskDetail) {
    // Wait for popstate before closing so repeated dismissals cannot go back twice.
    dialogBackPending = true;
    history.back();
  } else void hideDetail();
}
function hideDetail() {
  if (dialogClosePromise) return dialogClosePromise;
  const dialog = document.getElementById("detail-dialog");
  if (!dialog.open) return Promise.resolve();
  closingDialog = true;
  dialogClosePromise = (async () => {
    try {
      await animateSurface(dialog, { dialog: true, exiting: true });
      dialog.close();
    } finally { closingDialog = false; dialogClosePromise = undefined; }
  })();
  return dialogClosePromise;
}
function restoreDetailFromHistory() {
  if (document.getElementById("detail-dialog").open || closingDialog || dialogBackPending || pendingTabNavigation !== null) return;
  const detail = history.state?.yukizygiskDetail;
  if (!detail || (detail.type !== "policy" && !state.statusReady)) return;
  let index = -1;
  if (detail.type === "zygisk") index = state.status.modules.findIndex((module) => (typeof module === "string" ? module : module.id) === detail.id);
  else if (detail.type === "native") index = nativeGroups().findIndex((group) => group.id === detail.id);
  else if (detail.type === "process") index = nativeProcesses().findIndex((group) => group.pid === detail.pid && group.process === detail.process);
  if (detail.type === "policy" || index >= 0) openDetail(detail.type, index, { updateHistory: false });
  else {
    // A removed module/process has no detail level to restore. Consume that
    // entry instead of leaving a second copy of the same parent page.
    dialogBackPending = true;
    history.back();
  }
}
async function restoreNavigation() {
  const revision = ++navigationRevision;
  dialogBackPending = false;
  await hideDetail();
  if (revision !== navigationRevision) return;
  if (pendingTabNavigation !== null) {
    const tab = pendingTabNavigation;
    pendingTabNavigation = null;
    if (tab !== "status") history.pushState({ yukizygiskPage: tab }, "", tabUrl(tab));
    setTab(tab);
  } else setTab(new URLSearchParams(location.search).get("tab") || "status");
  restoreDetailFromHistory();
}
function updateModuleSelection(attribute, value) {
  for (const button of document.querySelectorAll(`[${attribute}]`)) button.setAttribute("aria-pressed", String(button.getAttribute(attribute) === value));
  const root = document.getElementById("view-modules");
  // Keep the pressed controls and their ripple mounted while replacing the monitor content.
  const template = document.createElement("template");
  template.innerHTML = renderModules();
  const section = root.querySelector(".section");
  section.replaceWith(template.content.querySelector(".section"));
  root.__markup = undefined;
  void animateSurface(root.querySelector(".module-list"));
}

document.addEventListener("click", (event) => {
  const target = event.target;
  const tab = target.closest("[data-tab]");
  if (tab) { selectTab(tab.dataset.tab); return; }
  const detail = target.closest("[data-detail]");
  if (detail) { openDetail(detail.dataset.detail, Number(detail.dataset.index)); return; }
  const kind = target.closest("[data-module-kind]");
  if (kind) {
    if (state.moduleKind !== kind.dataset.moduleKind) {
      state.moduleKind = kind.dataset.moduleKind;
      storePreference("module_kind", state.moduleKind);
      updateModuleSelection("data-module-kind", state.moduleKind);
    }
    return;
  }
  const view = target.closest("[data-native-view]");
  if (view) {
    if (state.nativeView !== view.dataset.nativeView) {
      state.nativeView = view.dataset.nativeView;
      storePreference("native_view", state.nativeView);
      const list = document.getElementById("view-modules").querySelector(".module-list");
      const template = document.createElement("template");
      template.innerHTML = renderModules();
      list.replaceChildren(...template.content.querySelector(".module-list").childNodes);
      for (const button of document.querySelectorAll("[data-native-view]")) button.setAttribute("aria-pressed", String(button.dataset.nativeView === state.nativeView));
      document.getElementById("view-modules").__markup = undefined;
      void animateSurface(list);
    }
    return;
  }
  const mode = target.closest("[data-denylist-mode]");
  if (mode && !mode.disabled) {
    const value = Number(mode.dataset.denylistMode);
    if (value !== state.config.denylist_mode) queueConfig("denylist_mode", value);
    return;
  }
  const action = target.closest("[data-action]")?.dataset.action;
  if (action === "refresh" || action === "retry-config") void refreshData({ manual: true });
  if (action === "close-dialog") void closeDetail();
  if (action === "dismiss-toast") document.getElementById("toast-stack").replaceChildren();
});
document.addEventListener("change", (event) => {
  const target = event.target;
  if (target.dataset.config) {
    if (target.dataset.config !== "denylist_mode") queueConfig(target.dataset.config, target.selected);
  } else if (target.id === "theme-select") {
    state.theme = target.value;
    storePreference("theme", state.theme);
    applyTheme();
  } else if (target.id === "language-select") {
    state.language = target.value;
    storePreference("language", state.language);
    document.documentElement.lang = state.language;
    mountApp();
    void restoreNavigation();
  }
});
document.addEventListener("keydown", (event) => {
  const button = event.target.closest("[data-denylist-mode]");
  if (!button || button.disabled || !["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) return;
  event.preventDefault();
  const current = Number(button.dataset.denylistMode);
  const next = event.key === "Home" ? 0 : event.key === "End" ? 2 : (current + (["ArrowLeft", "ArrowUp"].includes(event.key) ? 2 : 1)) % 3;
  document.querySelector(`[data-denylist-mode="${next}"]`).focus();
  queueConfig("denylist_mode", next);
});
reducedMotion.addEventListener("change", () => {
  for (const element of document.querySelectorAll(".view, .detail-dialog")) if (reducedMotion.matches) for (const animation of element.getAnimations({ subtree: true })) animation.cancel();
  for (const element of document.querySelectorAll("md-ripple")) element.disabled = reducedMotion.matches || element.closest('[aria-disabled="true"]') !== null;
});
document.getElementById("detail-dialog").addEventListener("cancel", (event) => {
  event.preventDefault();
  void closeDetail();
});
document.getElementById("detail-dialog").addEventListener("click", (event) => {
  const dialog = event.currentTarget;
  if (event.target !== dialog) return;
  const bounds = dialog.getBoundingClientRect();
  if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) void closeDetail();
});
window.addEventListener("popstate", () => { void restoreNavigation(); });
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    clearTimeout(pollTimer);
    if (pendingKeys.size) void flushConfig();
  } else if (["status", "modules"].includes(state.tab)) void refreshData({ includeConfig: false });
});
document.getElementById("detail-dialog").addEventListener("close", () => {
  if (deferredTelemetry) {
    deferredTelemetry = false;
    updateTelemetryViews();
  }
});

applyTheme();
document.documentElement.lang = state.language;
initializeNavigation();
mountApp();
restoreDetailFromHistory();
try {
  setFullScreen(true);
  void enableEdgeToEdge(true).catch(() => false);
} catch { /* Older hosts can omit window controls. */ }
// The host intercepts these URLs. Loading them separately keeps offline first paint immediate.
if (state.runtimeMode === "live") {
  for (const name of ["insets", "colors"]) {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = `https://mui.kernelsu.org/internal/${name}.css`;
    link.media = "print";
    link.onload = () => { link.media = "all"; };
    document.head.appendChild(link);
  }
}
void refreshData();
void api.getSystemInfo().then((system) => { state.system = system; updateTelemetryViews(); }).catch(() => {
  state.system = Object.fromEntries(Object.keys(state.system).map((key) => [key, t("common.unknown")]));
  updateTelemetryViews();
});
void api.getModuleMeta().then((meta) => { state.meta = meta; updateTelemetryViews(); }).catch(() => {});
