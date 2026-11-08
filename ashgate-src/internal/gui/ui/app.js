const DEMO = new URLSearchParams(location.search).get("demo") === "1";
// The window host injects this before the page loads; every API call must carry it.
const TOKEN = window.__ashgateToken || "";
function apiFetch(path, opts) {
  opts = opts || {};
  opts.headers = Object.assign({ "X-Ashgate-Token": TOKEN }, opts.headers || {});
  return fetch(path, opts);
}
// setHTML replaces el's markup only when it changed. Rebuilding unchanged
// markup on every poll swallowed clicks that landed mid-rebuild, cleared
// text selections and broke drag and drop.
function setHTML(el, html) {
  if (!el || el._html === html) return false;
  el.innerHTML = html;
  el._html = html;
  return true;
}
// Fluent icons live in icons.js (FLUENT). These few are drawn here.
const ICONS = {
  grip: '<circle cx="9" cy="6" r="1.3" fill="currentColor" stroke="none"/><circle cx="15" cy="6" r="1.3" fill="currentColor" stroke="none"/><circle cx="9" cy="12" r="1.3" fill="currentColor" stroke="none"/><circle cx="15" cy="12" r="1.3" fill="currentColor" stroke="none"/><circle cx="9" cy="18" r="1.3" fill="currentColor" stroke="none"/><circle cx="15" cy="18" r="1.3" fill="currentColor" stroke="none"/>',
  checkbox: '<rect x="4" y="4" width="16" height="16" rx="4" fill="currentColor" stroke="none"/><path d="m8 12 3 3 5-6" stroke="var(--acc-tx)"/>',
  square: '<rect x="4" y="4" width="16" height="16" rx="4"/>',
};
// [page, label, icon]. Settings sit at the bottom of the rail.
const NAV = [
  ["rules", "Приложения", "rules"],
  ["proxies", "Прокси", "server"],
  ["log", "Журнал", "activity"],
];
const NAV_FOOT = [["settings", "Настройки", "sliders"]];
const STATUS = {
  open: ["открыто", "ok"],
  closed: ["закрыто", "neu"],
  direct: ["напрямую", "info"],
  blocked: ["блокировано", "warn"],
  error: ["ошибка", "err"],
};

let state = null;
let page = "rules";
let modal = null;
let paused = false;
let frozen = null;
let logFilter = "";
let logProto = "all";
let sel = { proxy: 0, rule: -1, log: "" };
let built = "";
let lastBridge = "";
let errorsOnly = false;
let openErr = "";
// probing counts the checks in flight per proxy name.
let probing = {};
let probeAllBusy = false;
// powerBusy is set while a Start or Stop request runs.
let powerBusy = false;
let settingsTimer = null;

function icon(name, size) {
  size = size || 16;
  const f = (size >= 18 && FLUENT[name + "20"]) || FLUENT[name] || FLUENT[name + "20"];
  if (f) return `<svg width="${size}" height="${size}" viewBox="0 0 ${f[0]} ${f[0]}" fill="currentColor" aria-hidden="true"><path d="${f[1]}"/></svg>`;
  const fill = name === "grip" ? "currentColor" : "none";
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="${fill}" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">${ICONS[name] || ""}</svg>`;
}
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function bytes(n) {
  n = Math.abs(Number(n) || 0);
  const units = ["Б", "КБ", "МБ", "ГБ"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  const text = i === 0 ? String(Math.round(n)) : n.toFixed(1).replace(".", ",");
  return text + " " + units[i];
}
function viaText(v) {
  if (!v || v === "direct" || v === "block" || v === "relay") return "—";
  return v;
}
function badge(label, kind, dot, title) {
  const tip = title ? ` title="${esc(title)}"` : "";
  return `<span class="badge ${kind}${dot === false ? " plain" : ""}"${tip}>${dot === false ? "" : "<i></i>"}${esc(label)}</span>`;
}
function statusBadge(st) {
  const m = STATUS[st] || [st || "—", "neu"];
  return badge(m[0], m[1], true);
}

function demoState() {
  const on = true;
  const off = false;
  return {
    version: "0.7.3",
    build: { version: "0.7.3", commit: "912208e", time: "2026-10-26T18:40:00Z" },
    path: "C:\\ProgramData\\Ashgate\\config.json",
    running: true,
    active: 12,
    tcp: 10,
    udp: 2,
    bytesUp: Math.round(1.2 * 1024 * 1024),
    bytesDown: Math.round(17.2 * 1024 * 1024),
    admin: true,
    driver: true,
    error: "",
    theme: "dark",
    autostart: false,
    bridges: {
      aeza: { published: "127.0.0.1:10808", http: "127.0.0.1:10809", up: true },
    },
    checks: {
      aeza: { ok: true, udp: true, ms: 38, label: "38 мс", detail: "TCP и UDP" },
      local: { ok: true, udp: true, ms: 42, label: "42 мс", detail: "TCP и UDP" },
      "work-http": { ok: true, udp: false, ms: 412, label: "412 мс", detail: "только TCP" },
      backup: { ok: false, ms: 5000, label: "нет ответа", detail: "таймаут 5 с" },
    },
    config: {
      version: 1,
      relay: { tcp4: "127.0.0.1:34010", tcp6: "[::1]:34010" },
      dns: { mode: "proxy", servers: ["1.1.1.1:53", "8.8.8.8:53"], systemResolver: "tunnel", systemResolverProxy: "" },
      bypassPrivate: true,
      killSwitch: true,
      udpUnsupported: "block",
      log: { level: "info" },
      ui: { theme: "dark" },
      proxies: [
        { name: "local", type: "socks5", address: "127.0.0.1:1080" },
        { name: "work-http", type: "http", address: "10.0.0.5:3128", username: "user" },
        { name: "backup", type: "socks5", address: "proxy.example.com:1080", username: "alice" },
        { name: "tor", type: "socks5", address: "127.0.0.1:9050" },
        {
          name: "aeza", type: "vless", address: "203.0.113.10:443", socksPort: 10808,
          link: "vless://b7e2c1a0-4f3a-4c2b-9a11-111111111111@203.0.113.10:443?encryption=none&security=reality&type=xhttp&path=%2Fxhttp&host=www.microsoft.com&mode=auto&sni=www.microsoft.com&fp=chrome&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=ab12#aeza",
          vless: { uuid: "b7e2c1a0-4f3a-4c2b-9a11-111111111111", network: "xhttp", security: "reality", sni: "www.microsoft.com", fp: "chrome", pbk: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", sid: "ab12", path: "/xhttp", host: "www.microsoft.com", mode: "auto" },
        },
      ],
      rules: [
        { enabled: on, process: "*\\Discord\\app-*\\Discord.exe", action: "proxy", proxy: "aeza", group: "Связь и звонки" },
        { enabled: on, process: "C:\\Users\\user\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe", action: "proxy", proxy: "aeza", group: "Связь и звонки", children: false },
        { enabled: on, process: "Cursor.exe", action: "proxy", proxy: "aeza" },
        { enabled: on, process: "Spotify.exe", action: "proxy", proxy: "backup", killSwitch: true },
        { enabled: on, process: "curl.exe", action: "proxy", proxy: "local", tcpOnly: true },
        { enabled: on, process: "telemetry.exe", action: "block" },
        { enabled: off, process: "chrome.exe", action: "proxy", proxy: "work-http" },
        { enabled: off, process: "steam.exe", action: "direct" },
      ],
      groups: [{ name: "Связь и звонки", enabled: on, action: "proxy", proxy: "aeza", collapsed: false }],
    },
    alive: { "curl.exe": true, "spotify.exe": true, "cursor.exe": false, "telemetry.exe": false, "*\\discord\\app-*\\discord.exe": true, "c:\\users\\user\\appdata\\roaming\\telegram desktop\\telegram.exe": true },
    ruleStats: {
      "*\\discord\\app-*\\discord.exe": { flows: 18, up: 9200000, down: 842000000, upRate: 122880, downRate: 2516582 },
      "c:\\users\\user\\appdata\\roaming\\telegram desktop\\telegram.exe": { flows: 6, up: 31000000, down: 1150000000, upRate: 12288, downRate: 184320 },
      "cursor.exe": { flows: 0, up: 4100000, down: 210000000, upRate: 0, downRate: 0 },
      "spotify.exe": { flows: 0, up: 120000, down: 14200000, upRate: 0, downRate: 0, error: "SOCKS5: нет ответа от proxy.example.com:1080 (таймаут)" },
      "curl.exe": { flows: 0, up: 800, down: 4100, upRate: 0, downRate: 0 },
    },
    events: [
      { time: "12:04:31", process: "curl.exe", pid: 9012, proto: "TCP", dest: "api.ipify.org:443", via: "local", status: "open", bytesUp: 800, bytesDown: 4100 },
      { time: "12:04:30", process: "chrome.exe", pid: 4120, proto: "TCP", dest: "www.example.com:443", via: "work-http", status: "open", bytesUp: 12000, bytesDown: 284000 },
      { time: "12:04:29", process: "chrome.exe", pid: 4120, proto: "UDP", dest: "142.250.74.46:443", via: "work-http", status: "blocked", bytesUp: 1300, bytesDown: 0 },
      { time: "12:04:28", process: "telegram.exe", pid: 7788, proto: "TCP", dest: "149.154.167.51:443", via: "local", status: "open", bytesUp: 3200, bytesDown: 61000 },
      { time: "12:04:27", process: "telegram.exe", pid: 7788, proto: "UDP", dest: "1.1.1.1:53", via: "local", status: "closed", bytesUp: 64, bytesDown: 112 },
      { time: "12:04:25", process: "steam.exe", pid: 6120, proto: "TCP", dest: "store.example.net:443", via: "direct", status: "direct", bytesUp: 2400, bytesDown: 96000 },
      { time: "12:04:22", process: "firefox.exe", pid: 5532, proto: "TCP", dest: "example.org:443", via: "backup", status: "error", bytesUp: 0, bytesDown: 0, error: "SOCKS5: соединение отклонено прокси backup" },
      { time: "12:04:20", process: "curl.exe", pid: 9012, proto: "TCP", dest: "example.com:80", via: "local", status: "closed", bytesUp: 100, bytesDown: 1600 },
    ],
    generation: 8,
    killSwitch: { on: true, blocked: [], missing: [] },
  };
}

function cfg() { return state.config; }

function paintChrome() {
  const running = !!(state && state.running);
  // The window is dark only.
  document.body.dataset.theme = "dark";
  const item = ([id, label, ic]) => `<button class="nav-item${page === id ? " active" : ""}" data-nav="${id}" type="button" title="${esc(label)}" aria-label="${esc(label)}">${icon(ic, 20)}<span>${label}</span></button>`;
  setHTML(document.getElementById("nav"), NAV.map(item).join(""));
  setHTML(document.getElementById("nav-foot"), NAV_FOOT.map(item).join(""));
  const side = document.getElementById("side-card");
  if (!side) return;
  const sideName = running ? "Работает" : "Остановлен";
  const powerLabel = running ? "Стоп" : "Запустить";
  const traffic = state ? bytes((state.bytesUp || 0) + (state.bytesDown || 0)) : "0 Б";
  const ksBlocked = state && state.killSwitch && state.killSwitch.on && (state.killSwitch.blocked || []).length;
  const sideSub = running ? (state.active || 0) + " потоков · " + traffic : (ksBlocked ? "kill switch: приложения без сети" : "перехват выключен");
  side.className = "side-card" + (running ? " run" : "");
  // The button is rebuilt only when the state flips; the live details go
  // into its tooltip in place, so clicks on it are not lost.
  setHTML(side, `<button class="side-power" id="side-power" type="button" aria-label="${powerLabel}"${powerBusy ? " disabled" : ""}>${icon("power", 20)}</button>
    <div class="side-state"><i class="dot"></i><span>${powerLabel}</span></div>`);
  const btn = document.getElementById("side-power");
  const tip = sideName + " · " + sideSub;
  if (btn && btn.title !== tip) btn.title = tip;
}

function pageHTML() {
  if (page === "proxies") return proxiesHTML();
  if (page === "rules") return appsHTML();
  if (page === "log") return logHTML();
  if (page === "settings") return settingsHTML();
  return "";
}

function headMore() {
  return `<button class="iconbtn head-more" data-act="head-more" type="button" aria-label="Ещё" title="Ещё">${icon("more")}</button>`;
}
function proxiesHTML() {
  return `<div class="head"><div><h1>Прокси</h1><p class="sub">SOCKS5, HTTP и VLESS. Через них идёт трафик приложений.</p></div>
  <div class="head-actions"><button class="btn secondary" data-act="probe-all" type="button">${icon("refresh")}Проверить все</button><button class="btn secondary" data-act="paste-vless" type="button">${icon("paste")}Вставить vless://</button><button class="btn pri" data-act="proxy-add" type="button">${icon("plus")}Добавить</button>${headMore()}</div></div>
  <div id="proxy-table"></div>`;
}
function logHTML() {
  const onlyOn = errorsOnly ? " on" : "";
  return `<div class="head"><div><h1>Подключения</h1><p class="sub">Живой журнал перехваченных соединений. Также пишется в ashgate.log.</p></div>
  <div class="head-actions"><button class="btn secondary" id="pause-btn" data-act="pause" type="button">${icon("pause")}Пауза</button><button class="btn ghost secondary" data-act="clear" type="button">${icon("trash")}Очистить экран</button>${headMore()}</div></div>
  <div class="tools"><label class="field search" style="width:268px">${icon("search")}<input id="log-filter" placeholder="Процесс, адрес или прокси" value="${esc(logFilter)}"></label>
  <div class="seg" id="log-seg">${["Все", "TCP", "UDP"].map((n, i) => `<button type="button" data-act="proto" data-value="${["all", "TCP", "UDP"][i]}" class="${logProto === ["all", "TCP", "UDP"][i] ? "on" : ""}">${n}</button>`).join("")}</div>
  <span class="onlyerr">Только ошибки <button class="toggle${onlyOn}" type="button" data-act="errors-only" aria-pressed="${errorsOnly ? "true" : "false"}" aria-label="Только ошибки"><i></i></button></span>
  <div class="live" id="live"><i></i><span></span></div></div>
  <div class="pause-banner" id="pause-banner" hidden></div>
  <div id="log-table"></div>`;
}
function settingsHTML() {
  const c = cfg();
  const dnsOn = c.dns.mode !== "original";
  const sys = c.dns.systemResolver !== "direct";
  const udp = c.udpUnsupported === "direct" ? 1 : 0;
  const names = (c.proxies || []).map((p) => p.name);
  const selProxy = c.dns.systemResolverProxy || "";
  return `<div class="head"><div><h1>Настройки</h1><p class="sub">Применяются сразу · ${esc(state.path || "config.json")}</p></div>
  <div class="head-actions"><button class="btn ghost" data-act="open-folder" type="button">${icon("folder")}Открыть папку</button></div></div>
  ${group("DNS", [
    row("globe", "DNS приложений через прокси", "Порт 53 выбранных приложений уходит через прокси их правила", toggle("dns", dnsOn, "DNS приложений через прокси")),
    row("server", "DNS-серверы", "Куда отправлять эти запросы", `<input class="mono" id="dns-servers" aria-label="DNS-серверы" value="${esc((c.dns.servers || []).join(", "))}" ${dnsOn ? "" : "disabled"}>`),
    row("sliders", "DNS Windows через туннель", "Имена, которые программы спрашивают у Windows (svchost.exe), идут через прокси, кроме исключений. Пока туннель не работает, они не разрешаются", `${select("sys-proxy", names, selProxy, !sys, "Авто", "Прокси для DNS Windows")}${toggle("sys", sys, "DNS Windows через туннель")}`),
  ])}
  ${group("Защита от утечек", [
    row("shield", "Kill switch", "Приложения с правилом «прокси» и их дочерние процессы никогда не выходят в сеть напрямую. Пока перехват выключен или Ashgate закрыт, Брандмауэр Windows отключает их от сети", toggle("kill", !!c.killSwitch, "Kill switch"), true),
  ])}
  ${group("UDP и сеть", [
    row("swap", "UDP, который прокси не умеет", "Для HTTP-прокси: QUIC и игры. «Блокировать» не даёт обойти прокси", segCtrl("udp", ["Блокировать", "Напрямую"], ["block", "direct"], udp)),
    row("link", "Не проксировать частные сети", "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7 — напрямую", toggle("bypass", !!c.bypassPrivate, "Не проксировать частные сети")),
  ])}
  ${group("Исключения", [
    row("link", "Напрямую, без VLESS", "По одному домену в строке, поддомены тоже. Эти сайты открываются напрямую, даже если правило приложения ведёт через VLESS, и их имена разрешает DNS провайдера", `<div class="field" style="width:240px"><textarea class="mono" id="direct-domains" aria-label="Домены напрямую" rows="6" spellcheck="false">${esc((c.directDomains || []).join("\n"))}</textarea></div>`),
  ])}
  ${group("Запуск и журнал", [
    row("rocket", "Запускать с Windows", "При входе в систему открывается окно и включается перехват", toggle("auto", !!state.autostart, "Запускать с Windows")),
    row("doc", "Подробный журнал", "Уровень debug вместо info в ashgate.log", toggle("verbose", c.log && c.log.level === "debug", "Подробный журнал")),
  ])}
  ${group("О программе", [aboutRow(), updateRow()])}`;
}
// aboutRow shows which exe is running. After "git pull" only a rebuilt exe
// changes; compare the commit with the newest one on GitHub.
function aboutRow() {
  const b = state.build || { version: state.version };
  const text = buildText(b);
  const desc = b.commit
    ? "Коммит должен совпадать с последним в репозитории. Иначе обновите Ashgate: update.bat в клоне репозитория соберёт и поставит свежий exe"
    : "Exe собран без git, поэтому коммит неизвестен. Соберите его из клона репозитория, чтобы видеть коммит";
  return row("info", "Версия", desc, `<span class="mono">${esc(text)}</span><button class="iconbtn" type="button" data-act="copy-text" data-text="${esc(text)}" title="Копировать" aria-label="Копировать">${icon("copy", 14)}</button>`);
}
// Update check. The server reads version.json on GitHub and opens the
// download page itself, so the page never handles the link.
let updateCheck = { busy: false, res: null, err: "" };
function updateRow() {
  const u = updateCheck;
  let desc = "Сравнить с последней версией на GitHub";
  let warn = false;
  let ctl = `<button class="btn sm" type="button" data-act="update-check"${u.busy ? " disabled" : ""}>${icon("refresh")}${u.busy ? "Проверка…" : "Проверить"}</button>`;
  if (u.busy) desc = "Проверяю…";
  else if (u.err) { desc = "Не удалось проверить: " + u.err; warn = true; }
  else if (u.res && u.res.available) {
    desc = "Доступна версия " + u.res.latest + (u.res.notes ? ". " + u.res.notes : "");
    ctl = `<button class="btn sm pri" type="button" data-act="update-open">Скачать</button>` + ctl;
  } else if (u.res) desc = "У вас последняя версия, " + u.res.current;
  return row("refresh", "Обновления", desc, ctl, warn, "update-row");
}
function paintUpdate() {
  const el = document.getElementById("update-row");
  if (el) el.outerHTML = updateRow();
}
async function checkUpdate() {
  if (updateCheck.busy) return;
  updateCheck = { busy: true, res: null, err: "" };
  paintUpdate();
  try {
    const res = DEMO
      ? { current: state.version, latest: state.version, available: false }
      : await post("/api/update/check");
    updateCheck = { busy: false, res, err: "" };
  } catch (err) {
    updateCheck = { busy: false, res: null, err: err.message };
  }
  paintUpdate();
}

function buildText(b) {
  let t = b.version || "";
  if (b.commit) t += " · " + b.commit;
  if (b.time) {
    const d = new Date(b.time);
    if (!Number.isNaN(d.getTime())) t += " · " + d.toLocaleDateString("ru-RU");
  }
  if (b.modified) t += " · с локальными правками";
  return t;
}
function group(title, rows) {
  return `<div class="group-title">${esc(title)}</div><div class="sgroup">${rows.join("")}</div>`;
}
// Settings icons sit on coloured tiles, as in Windows Settings.
const SET_COLORS = { globe: "blue", server: "teal", sliders: "violet", shield: "green", swap: "pink", link: "teal", rocket: "orange", doc: "yellow", info: "blue" };
function row(ic, title, desc, ctl, warn, id) {
  return `<div class="set"${id ? ` id="${id}"` : ""}><span class="sico c-${SET_COLORS[ic] || "blue"}">${icon(ic, 20)}</span><div class="txt"><div class="t">${esc(title)}</div><div class="d${warn ? " warn" : ""}">${esc(desc)}</div></div><div class="ctl">${ctl}</div></div>`;
}
function toggle(key, on, label) {
  return `<button class="toggle${on ? " on" : ""}" type="button" data-act="toggle" data-key="${key}" aria-pressed="${on ? "true" : "false"}" aria-label="${esc(label)}"><i></i></button>`;
}
function segCtrl(key, labels, values, active) {
  return `<div class="seg">${labels.map((l, i) => `<button type="button" data-act="seg" data-key="${key}" data-value="${values[i]}" class="${i === active ? "on" : ""}">${l}</button>`).join("")}</div>`;
}
// select lists proxy names; auto, when given, is a first option with an
// empty value.
function select(id, names, value, disabled, auto, label) {
  let opts = names.map((n) => `<option value="${esc(n)}" ${n === value ? "selected" : ""}>${esc(n)}</option>`).join("");
  if (auto) opts = `<option value="" ${value ? "" : "selected"}>${esc(auto)}</option>` + opts;
  return `<select id="${id}"${label ? ` aria-label="${esc(label)}"` : ""} ${disabled ? "disabled" : ""}>${opts || `<option value="">нет прокси</option>`}</select>`;
}

function fillPage() {
  if (!state) return;
  if (page === "proxies") fillProxies();
  if (page === "rules") fillApps();
  if (page === "log") fillLog();
  if (page === "settings") fillSettings();
}
// fillSettings redraws Settings from the server's config, so a rejected
// save does not leave its values on screen. Never under the user's hands:
// not while an edit waits to be saved or is saving, nor while a field is
// being typed in.
function fillSettings() {
  const host = document.getElementById("page");
  if (!host || built !== "settings" || settingsPending || settingsSaving > 0) return;
  const a = document.activeElement;
  const inside = a && a !== document.body && host.contains(a);
  if (inside && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)) return;
  const html = settingsHTML();
  if (host._html === html) return;
  const key = inside ? focusKey(a) : "";
  host.innerHTML = html;
  host._html = html;
  const back = key && host.querySelector(key);
  if (back) back.focus({ preventScroll: true });
}
// focusKey is a selector that finds an element again after a redraw: its
// id, or its action and data attributes.
function focusKey(el) {
  if (!el || el === document.body) return "";
  if (el.id) return "#" + CSS.escape(el.id);
  if (!el.dataset || !el.dataset.act) return "";
  let s = `[data-act="${CSS.escape(el.dataset.act)}"]`;
  for (const k of ["key", "value", "i", "name", "path", "target", "group"]) {
    if (el.dataset[k] !== undefined) s += `[data-${k}="${CSS.escape(el.dataset[k])}"]`;
  }
  return s;
}

// ksNotice is the kill switch notice at the top of the Apps tab. It shows
// only when something needs attention: apps without network while capture
// is off, an exe that was not found, or a firewall error.
function ksNotice() {
  const ks = (state && state.killSwitch) || {};
  if (!ks.on) return "";
  const need = (!state.running && (ks.blocked || []).length) || (ks.missing || []).length || ks.error;
  return need ? killBanner(ks) : "";
}
// killBanner tells what the kill switch is doing right now.
function killBanner(ks) {
  if (!ks || !ks.on) return "";
  const blocked = ks.blocked || [];
  const missing = ks.missing || [];
  let title;
  let text;
  let cls = "ks-banner";
  if (state.running) {
    title = "Kill switch активен";
    text = "Приложения с прокси не выйдут в сеть напрямую. Если перехват остановится или Ashgate закроется, Брандмауэр Windows отключит их от сети.";
  } else if (blocked.length) {
    cls += " warn";
    title = `Kill switch: ${blocked.length} ${progWord(blocked.length)} без сети`;
    text = "Перехват выключен, поэтому Брандмауэр Windows блокирует: " + blocked.map((p) => appLabel(p)).join(", ") + ". Нажмите «Старт», чтобы они снова работали через прокси.";
  } else {
    title = "Kill switch включён";
    text = "Блокировать пока нечего: нет включённых правил «прокси» с найденным exe.";
  }
  const miss = missing.length ? `<p class="miss">Не найден exe: ${esc(missing.join(", "))}. Пока перехват выключен, эти программы не блокируются — запустите их или укажите полный путь в правиле.</p>` : "";
  const err = ks.error ? `<p class="miss">Брандмауэр: ${esc(ks.error)}</p>` : "";
  const btn = !state.running ? `<button class="btn pri sm" type="button" data-act="ks-start"${powerBusy ? " disabled" : ""}>${icon("power", 14)}Старт</button>` : "";
  return `<div class="${cls}">${icon("shield", 18)}<div class="txt"><strong>${esc(title)}</strong><p>${esc(text)}</p>${miss}${err}</div>${btn}</div>`;
}
function progWord(n) {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return "программа";
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return "программы";
  return "программ";
}
function fillProxies() {
  const host = document.getElementById("proxy-table");
  if (!host) return;
  const all = document.querySelector('[data-act="probe-all"]');
  if (all) all.disabled = probeAllBusy;
  const list = cfg().proxies || [];
  if (!list.length) {
    setHTML(host, `<div class="empty-card"><h3>Прокси ещё нет</h3><p>Добавьте SOCKS5, HTTP, ссылку vless:// или подписку 3x-ui.</p><button class="btn pri" type="button" data-act="proxy-add">${icon("plus")}Добавить прокси</button></div>`);
    return;
  }
  // One card per proxy. The selected card shows edit and delete; the
  // actions column keeps its width so the other columns stay aligned.
  const rows = list.map((p, i) => {
    const view = probeView(p);
    const why = view.detail ? `<div class="why">${esc(view.detail)}</div>` : "";
    const selected = sel.proxy === i;
    const acts = selected
      ? `<button class="iconbtn" data-act="proxy-edit" data-i="${i}" type="button" aria-label="Изменить" title="Изменить">${icon("edit")}</button><button class="iconbtn danger" data-act="proxy-del" data-i="${i}" type="button" aria-label="Удалить" title="Удалить">${icon("trash")}</button>`
      : "";
    return `<div class="prow${selected ? " sel" : ""}" data-act="sel-proxy" data-i="${i}">
      <span class="ptype k-${esc(p.type || "socks5")}" title="${esc(p.subscription ? "Подписка" : proxyTypeLabel(p.type))}">${icon(p.subscription ? "link" : typeIconName(p.type), 16)}</span>
      <div class="stack"><span class="main">${esc(p.name)}</span><span class="sub">${esc((p.subscription ? "Подписка" : proxyTypeLabel(p.type)) + " · " + proxySub(p))}</span>${p.subscription ? subNarrow(p) : ""}</div>
      <div class="paddr mono">${proxyAddrCell(p)}</div>
      <div class="checkcell">${badge(view.label, view.kind, true, view.detail || view.label)}${why}</div>
      <div class="row-actions">${acts}<button class="iconbtn" data-act="menu-proxy" data-i="${i}" type="button" aria-label="Ещё" title="Ещё">${icon("more")}</button></div>
    </div>`;
  });
  setHTML(host, `<div class="plist">${rows.join("")}</div>`);
}

function baseName(process) {
  const s = String(process).replace(/\//g, "\\");
  const i = s.lastIndexOf("\\");
  return i >= 0 ? s.slice(i + 1) : s;
}
function appLabel(process) {
  return baseName(process).replace(/\.exe$/i, "");
}
const iconMisses = new Set();
// Forget misses now and then: a program may be installed meanwhile.
setInterval(() => iconMisses.clear(), 5 * 60 * 1000);
function iconMiss(img) {
  iconMisses.add(img.dataset.key || "");
  img.remove();
}
// appHue gives every app its own tile colour, the same on every redraw.
function appHue(name) {
  let h = 0;
  for (const ch of String(name || "").toLowerCase()) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return [210, 265, 330, 150, 185, 45, 290, 100][h % 8];
}
function appIconHTML(process, style) {
  const letter = esc((appLabel(process) || "?").slice(0, 1).toUpperCase());
  const path = String(process || "");
  const st = ` style="--hue:${appHue(appLabel(process))};${style || ""}"`;
  // Names and masks are resolved to an exe by the server; 404 keeps the letter.
  if (DEMO || !path.trim()) return `<span class="appicon"${st}>${letter}</span>`;
  // Names without an icon are remembered, so a redraw does not ask again.
  if (iconMisses.has(path.toLowerCase())) return `<span class="appicon"${st}>${letter}</span>`;
  const src = "/api/icon?path=" + encodeURIComponent(path) + "&t=" + encodeURIComponent(TOKEN);
  // draggable=false: a dragged icon would carry its URL, token included.
  return `<span class="appicon"${st}><img alt="" draggable="false" src="${esc(src)}" data-key="${esc(path.toLowerCase())}" onload="this.parentNode.classList.add('hasimg')" onerror="iconMiss(this)">${letter}</span>`;
}

function eventKey(e) {
  return [e.time, e.pid, e.proto, e.dest, e.status, e.error || ""].join("|");
}
function missedCount() {
  if (!paused || !frozen) return 0;
  const seen = new Set(frozen.map(eventKey));
  return (state.events || []).filter((e) => !seen.has(eventKey(e))).length;
}
function logEvents() {
  const src = paused && frozen ? frozen : (state.events || []);
  const q = logFilter.trim().toLowerCase();
  return src.filter((e) => {
    if (errorsOnly && e.status !== "error") return false;
    if (logProto !== "all" && e.proto !== logProto) return false;
    if (!q) return true;
    const blob = ((e.process || "") + " " + (e.dest || "") + " " + (e.via || "") + " " + (e.parent || "")).toLowerCase();
    return blob.includes(q);
  });
}
function fillLog() {
  const host = document.getElementById("log-table");
  if (!host) return;
  const live = document.getElementById("live");
  const pause = document.getElementById("pause-btn");
  if (live) {
    live.className = "live" + (paused ? " pause" : "");
    live.querySelector("span").textContent = paused ? "пауза" : "в реальном времени · 250 мс";
  }
  if (pause) setHTML(pause, paused ? `${icon("play")}Продолжить` : `${icon("pause")}Пауза`);
  const banner = document.getElementById("pause-banner");
  if (banner) {
    if (paused) {
      const n = missedCount();
      banner.hidden = false;
      setHTML(banner, `<span>Пауза · ${n} новых соединений не показаны</span><button type="button" data-act="pause">Показать</button>`);
    } else banner.hidden = true;
  }
  const rows = logEvents();
  if (!rows.length) {
    setHTML(host, `<div class="table"><div class="empty">${(state.events || []).length ? "Ничего не найдено." : "Пока нет перехваченных соединений. Они появятся после «Старт»."}</div></div>`);
    return;
  }
  const head = ["Время", "Процесс", "Протокол", "Назначение", "Через", "Статус", "Трафик"];
  const body = rows.map((e) => {
    const key = eventKey(e);
    const open = e.status === "error" && openErr === key;
    // Rows are selected by event, not by position: new events push rows down.
    const main = `<tr class="${sel.log === key ? "sel" : ""}" data-act="sel-log" data-key="${esc(key)}">
    <td class="mono">${esc(e.time)}</td>
    <td><div class="stack"><span class="main">${esc(appLabel(e.process))}</span><span class="sub mono">PID ${e.pid || 0}${e.parent ? " · от " + esc(appLabel(e.parent)) : ""}</span></div></td>
    <td><span class="tag ${e.proto === "UDP" ? "udp" : "tcp"}">${esc(e.proto || "")}</span></td>
    <td class="mono" style="color:var(--tx)">${esc(e.dest)}</td>
    <td>${esc(viaText(e.via))}</td>
    <td>${statusBadge(e.status)}</td>
    <td class="bytes mono"><div>↑ ${esc(bytes(e.bytesUp))}</div><div>↓ ${esc(bytes(e.bytesDown))}</div></td>
  </tr>`;
    if (!open) return main;
    const err = e.error || "ошибка";
    return main + `<tr class="errline"><td colspan="7"><div class="errpanel"><span class="msg">${esc(err)}</span><button class="btn sm" type="button" data-act="copy-text" data-text="${esc(err)}">Копировать</button><button class="btn sm" type="button" data-act="goto-rule" data-proc="${esc(e.process || "")}">К правилу</button></div></td></tr>`;
  }).join("");
  setHTML(host, `<table class="table"><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${body}</tbody></table>`);
}

function render() {
  if (!state) return;
  if (page === "tray") {
    document.getElementById("app").hidden = true;
    const tray = document.getElementById("tray");
    tray.hidden = false;
    if (tray.dataset.built !== "1") { tray.innerHTML = trayHTML(); tray.dataset.built = "1"; }
    const root = document.getElementById("modal");
    root.innerHTML = "";
    root.drawnFor = null;
    return;
  }
  document.getElementById("app").hidden = false;
  document.getElementById("tray").hidden = true;
  paintChrome();
  const host = document.getElementById("page");
  if (built !== page) {
    const html = pageHTML();
    host.innerHTML = html;
    host._html = html;
    host.dataset.page = page;
    // The autostart task is read again when Settings opens, not on a timer.
    if (page === "settings") askAuto = true;
    built = page;
  }
  // The page behind an open dialog stays current. The dialog itself is
  // drawn when it opens or closes, never by a poll: that used to drop what
  // was typed. Only its live SOCKS status is updated in place.
  fillPage();
  if (document.getElementById("modal").drawnFor !== modal) renderModal();
  else paintSocksPreview();
  if (state.error) showToast(state.error);
}

function renderModal() {
  const root = document.getElementById("modal");
  if (!modal) { root.innerHTML = ""; root.drawnFor = null; return; }
  // Typed text is in the model already (see the input handlers), so a
  // redraw never reads the fields back and values set by code win. A redraw
  // of the same dialog keeps the focused control, caret and scroll and does
  // not replay the opening animation.
  const again = root.drawnFor === modal;
  const el = again && root.contains(document.activeElement) ? document.activeElement : null;
  const key = focusKey(el);
  let range = null;
  try { range = el && typeof el.selectionStart === "number" ? [el.selectionStart, el.selectionEnd] : null; } catch (e) { range = null; }
  const oldBody = again ? root.querySelector(".dialog .body") : null;
  const scroll = oldBody ? oldBody.scrollTop : 0;
  if (modal.kind === "proxy") root.innerHTML = proxyDialog();
  else if (AP_MODALS[modal.kind]) root.innerHTML = AP_MODALS[modal.kind]();
  else if (modal.kind === "confirm" || modal.kind === "alert") root.innerHTML = confirmDialog();
  root.drawnFor = modal;
  if (!again) {
    const first = root.querySelector("[autofocus]");
    if (first) first.focus();
    return;
  }
  const dlg = root.querySelector(".dialog");
  if (dlg) dlg.classList.add("steady");
  const body = root.querySelector(".dialog .body");
  if (body) body.scrollTop = scroll;
  const back = key && root.querySelector(key);
  if (back) {
    back.focus({ preventScroll: true });
    if (range) { try { back.setSelectionRange(range[0], range[1]); } catch (e) { /* not a text field */ } }
  }
}
function confirmDialog() {
  const alert = modal.kind === "alert";
  const okCls = modal.danger ? "btn danger" : "btn pri";
  const buttons = alert
    ? `<button class="btn pri" type="submit" autofocus>Понятно</button>`
    : `<button class="${okCls}" type="submit">${esc(modal.ok || "Удалить")}</button><button class="btn" type="button" data-act="cancel">Отмена</button>`;
  return `<div class="scrim"><form class="dialog narrow" id="dlg"><h2>${esc(modal.title || "")}</h2>
    <div class="body"><p class="confirm-text selectable">${esc(modal.text || "")}</p></div>
    <div class="footer">${buttons}</div></form></div>`;
}

function proxyTypeLabel(t) {
  if (t === "http") return "HTTP";
  if (t === "vless") return "VLESS";
  return "SOCKS5";
}
function proxyDialog() {
  const p = modal.draft;
  const type = p.subscription ? "sub" : p.type || "socks5";
  // A saved subscription stays one (its button does nothing); the type of
  // other proxies can change.
  const types = p.subscription ? [["sub", "Подписка"]] : [["socks5", "SOCKS5"], ["http", "HTTP"], ["vless", "VLESS"], ["sub", "Подписка"]];
  const vless = type === "vless";
  const sub = type === "sub";
  // autocomplete="off": WebView2 must not keep typed links, UUIDs, keys,
  // logins or subscription URLs in its form history on disk.
  return `<div class="scrim"><form class="dialog${vless ? "" : " narrow"}" id="dlg" autocomplete="off">
    <h2>Прокси</h2><div class="dsub">${modal.index < 0 ? "Новый прокси" : "Изменение · " + esc(p.name || "")}</div>
    <div class="body">
      <label class="lbl">Имя</label><div class="field${modal.nameError ? " bad" : ""}"><input id="p-name" value="${esc(p.name || "")}" placeholder="Задаётся само, если оставить пустым" autofocus></div>
      ${modal.nameError ? `<div class="field-err">${esc(modal.nameError)}</div>` : ""}
      <div style="height:14px"></div><label class="lbl">Тип</label>
      <div class="seg">${types.map(([v, n]) => `<button type="button" data-act="ptype" data-value="${v}" class="${type === v ? "on" : ""}">${n}</button>`).join("")}</div>
      ${sub ? subFields(p) : vless ? vlessFields(p) : socksFields(p)}
      ${sub ? "" : `<div class="checkline"><button class="btn sm" type="button" data-act="probe-draft">${icon("refresh")}Проверить</button><span id="probe-out">${modal.checking ? badge("проверка…", "neu", true) : (modal.report ? probeBadge(modal.report, type) : "")}</span></div>`}
      ${modal.realityError ? `<div class="field-err">${esc(modal.realityError)}</div>` : ""}
    </div>
    <div class="footer"><button class="btn pri" type="submit"${modal.busy ? " disabled" : ""}>${modal.busy ? "Загружаю подписку…" : modal.index < 0 ? "Добавить" : "Сохранить"}</button><button class="btn" type="button" data-act="cancel">Отмена</button></div>
  </form></div>`;
}
// subFields is the subscription part of the proxy dialog. A saved one shows
// only its host: the full URL carries a token and stays on the server.
function subFields(p) {
  if (p.subscription) {
    const s = p.subscription;
    return `<div style="height:14px"></div><label class="lbl">Подписка</label>
      <div class="help">${esc(s.host || "")} · ${esc(serverWord(s.count || 0))} · ${esc(subUpdated(s))}</div>
      <div class="help">Адрес хранится зашифрованным. Чтобы сменить его, удалите подписку и добавьте заново.</div>`;
  }
  return `<div style="height:14px"></div><label class="lbl">Ссылка подписки</label>
      <div class="field${modal.subError ? " bad" : ""}"><input class="mono" id="p-suburl" value="${esc(p.subUrl || "")}" placeholder="https://…/sub/…"></div>
      ${modal.subError ? `<div class="field-err">${esc(modal.subError)}</div>` : ""}
      <div class="help">Подписка 3x-ui. Все серверы из неё — одна группа: XHTTP основной, RAW запасной, переключение само. Обновляется раз в сутки; адрес хранится зашифрованным.</div>`;
}
function serverWord(n) {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return n + " сервер";
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return n + " сервера";
  return n + " серверов";
}
function subUpdated(s) {
  // Go writes a zero time as 0001-01-01: never updated.
  const d = new Date(s.updatedAt || 0);
  if (!s.updatedAt || Number.isNaN(d.getTime()) || d.getFullYear() < 2000) return "ещё не обновлялась";
  return "обновлена " + d.toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
}
function refreshSub(name) {
  if (DEMO || !name) return;
  if (state.subs && state.subs[name]) state.subs[name].fetching = true;
  fillProxies();
  post("/api/subscription/refresh", { name }).then(() => { showToast("Подписка обновлена"); return refresh(); })
    .catch((err) => { showToast(err.message); return refresh(); });
}
function socksFields(p) {
  return `<div style="height:14px"></div><label class="lbl">Адрес</label><div class="field${modal.addrError ? " bad" : ""}"><input class="mono" id="p-addr" value="${esc(p.address || "")}" placeholder="127.0.0.1:1080"></div>
      ${modal.addrError ? `<div class="field-err">${esc(modal.addrError)}</div>` : `<div class="help">хост:порт, например 127.0.0.1:1080</div>`}
      <div class="grid" style="margin-top:14px">
        <div><label class="lbl">Логин</label><div class="field"><input id="p-user" value="${esc(p.username || "")}" placeholder="необязательно"></div></div>
        <div style="position:relative"><label class="lbl">Пароль</label><div class="field"><input id="p-pass" type="${modal.showPass ? "text" : "password"}" value="${esc(p.password || "")}"></div>
        <button class="eye" type="button" data-act="eye" aria-label="Показать пароль">${icon("eye")}</button></div>
      </div>`;
}
function vlessFields(p) {
  const v = p.vless || {};
  return `<div style="height:14px"></div><label class="lbl">Вставить ссылку</label>
      <div class="field${modal.parseError ? " bad" : ""}"><textarea class="mono" id="p-link" placeholder="vless://…">${esc(p.link || "")}</textarea></div>
      <div class="help">Ссылка vless:// из 3x-ui или v2rayN. Имя берётся из фрагмента после #, если поле «Имя» пустое.</div>
      <div class="checkline" style="margin-top:8px"><button class="btn sm" type="button" data-act="parse-link">Разобрать</button></div>
      ${modal.parseError ? `<div class="field-err">${esc(modal.parseError)}</div>` : ""}
      ${vlessLocal(p)}
      <div class="vless-grid">
        ${vinput("p-addr", "Адрес", p.address, true)}
        ${vinput("v-uuid", "UUID", v.uuid, true)}
        ${vselect("v-net", "Транспорт", v.network || "tcp", ["tcp", "xhttp", "ws", "grpc", "httpupgrade"])}
        ${vselect("v-sec", "Безопасность", v.security || "reality", ["reality", "tls", "none"])}
        ${vinput("v-sni", "SNI", v.sni)}
        ${vinput("v-fp", "Fingerprint", v.fp)}
        ${vinput("v-pbk", "Публичный ключ", v.pbk, true)}
        ${vinput("v-sid", "Short ID", v.sid)}
        ${vinput("v-flow", "Flow", v.flow)}
        ${vinput("v-path", "Path", v.path)}
        ${vinput("v-host", "Host", v.host)}
        ${vinput("v-svc", "serviceName", v.serviceName)}
        ${vinput("v-mode", "Режим", v.mode)}
      </div>`;
}
function vlessLocal(p) {
  const port = modal.socksText !== undefined ? modal.socksText : p.socksPort ? String(p.socksPort) : "";
  return `<div class="socks-box">
      <label class="lbl">Локальный SOCKS5-порт</label>
      <div class="field${modal.portError ? " bad" : ""}"><input class="mono" id="p-socks" inputmode="numeric" placeholder="10808" value="${esc(port)}"></div>
      ${modal.portError ? `<div class="field-err">${esc(modal.portError)}</div>` : ""}
      <div class="help">Пусто — только для правил Ashgate: случайный порт и случайный логин при каждом запуске. Число, например 10808 — SOCKS5 на 127.0.0.1 для Dolphin и других программ, всегда с логином: если поля пусты, Ashgate придумает его при сохранении. Следующий порт — HTTP с тем же логином. Только 127.0.0.1, в локальную сеть не открывается; UDP через SOCKS5 выключен.</div>
      <div class="grid" style="margin-top:10px">
        <div><label class="lbl">Логин SOCKS5</label><div class="field"><input id="p-luser" value="${esc(p.localUser || "")}" placeholder="необязательно"></div></div>
        <div><label class="lbl">Пароль</label><div class="field"><input id="p-lpass" type="password" value="${esc(p.localPass || "")}" placeholder="необязательно"></div></div>
      </div>
      ${socksPreviewHTML(p)}
    </div>`;
}
function socksPreviewHTML(p) {
  return `<div id="socks-preview" class="socks-pub">${socksPreviewInner(p)}</div>`;
}
// paintSocksPreview updates the open proxy dialog's SOCKS status in place.
function paintSocksPreview() {
  if (!modal || modal.kind !== "proxy") return;
  setHTML(document.getElementById("socks-preview"), socksPreviewInner(modal.draft));
}
// socksPreviewInner shows the published port and its login. The password
// is masked like its field; «Копировать» still copies it.
function socksPreviewInner(p) {
  const port = Number(p.socksPort) || 0;
  if (!port || port < 1 || port > 65535) return "";
  const socks = "127.0.0.1:" + port;
  const http = port < 65535 ? "127.0.0.1:" + (port + 1) : "";
  const live = (state && state.bridges && state.bridges[p.name]) || {};
  let mark = "wait";
  let text = "откроется после сохранения";
  if (live.up && live.published === socks) { mark = "ok"; text = "слушает"; }
  else if (live.error) { mark = "bad"; text = live.error; }
  const user = p.localUser || live.user || "";
  const pass = p.localUser ? p.localPass || "" : live.pass || "";
  const masked = pass ? "••••••••" : "";
  const loginRow = user ? `<div class="row"><span class="addr">${esc(user)} / ${masked || "—"}</span><button class="btn sm" type="button" data-act="copy-text" data-text="${esc(user + ":" + pass + "@" + socks)}" data-shown="${esc(user + ":" + masked + "@" + socks)}">Копировать</button><span class="sub">логин / пароль</span></div>` : "";
  const httpRow = http ? `<div class="row"><span class="addr">${esc(http)}</span><button class="btn sm" type="button" data-act="copy-text" data-text="${esc(http)}">Копировать</button><span class="sub">HTTP</span></div>` : "";
  return `<div class="row"><span class="addr">${esc(socks)}</span><button class="btn sm" type="button" data-act="copy-text" data-text="${esc(socks)}">Копировать</button><span class="sockline"><i class="${mark}"></i><span class="sub">${esc(text)}</span></span></div>
      ${httpRow}
      ${loginRow}`;
}
function proxyAddrText(p) {
  if (p.subscription) {
    const v = (state && state.subs && state.subs[p.name]) || {};
    return v.active || "нет серверов";
  }
  if (p.type === "vless" && p.socksPort) return "127.0.0.1:" + p.socksPort;
  return p.address || "";
}
// subAddrCell shows a subscription: the active server and why it was
// chosen, the last update or its error, and the «Обновить» button.
function subAddrCell(p) {
  const s = p.subscription || {};
  const v = (state && state.subs && state.subs[p.name]) || {};
  const err = v.error || s.error || "";
  const status = v.fetching ? "обновляется…" : err ? "Ошибка обновления: " + err : subUpdated(s);
  const why = v.reason ? `<div class="sub" title="${esc(v.reason)}">${esc(v.reason)}</div>` : "";
  return `<div class="sockline" title="${esc(status)}"><i class="${err ? "bad" : v.active ? "ok" : "wait"}"></i><span>${esc(v.active || "нет серверов")}</span>
      <button class="btn sm" type="button" data-act="sub-refresh" data-name="${esc(p.name)}"${v.fetching ? " disabled" : ""}>${icon("refresh", 14)}Обновить</button></div>
    ${why}<div class="sub${err ? " warn" : ""}">${esc(status)}</div>`;
}
// subNarrow repeats a subscription's active server or update error under
// its name when the window is too narrow for the address column.
function subNarrow(p) {
  const s = p.subscription || {};
  const v = (state && state.subs && state.subs[p.name]) || {};
  const err = v.error || s.error || "";
  const text = v.fetching ? "обновляется…" : err ? "Ошибка обновления: " + err : v.active || "нет серверов";
  return `<span class="sub only-narrow${err ? " warn" : ""}">${esc(text)}</span>`;
}
function proxyAddrCell(p) {
  if (p.subscription) return subAddrCell(p);
  if (p.type === "vless" && p.socksPort) {
    const socks = "127.0.0.1:" + p.socksPort;
    const live = (state && state.bridges && state.bridges[p.name]) || {};
    let mark = "wait";
    let text = "не запущен";
    if (live.up && live.published === socks) { mark = "ok"; text = "слушает"; }
    else if (live.error) { mark = "bad"; text = live.error; }
    return `<div class="sockline" title="${esc(text)}"><i class="${mark}"></i><span>${esc(socks)}</span><button class="iconbtn" type="button" data-act="copy-text" data-text="${esc(socks)}" title="Копировать" aria-label="Копировать">${icon("copy", 14)}</button><span class="sub">${esc(text)}</span></div>`;
  }
  if (p.type === "vless") return `${esc(p.address || "")}<div class="sub">Локальный порт не задан — только для правил</div>`;
  return esc(p.address || "");
}
function typeIconName(t) {
  if (t === "http") return "http";
  if (t === "vless") return "vless";
  return "socks";
}
function ruleWord(n) {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return "правило";
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return "правила";
  return "правил";
}
function proxySub(p) {
  const n = (cfg().rules || []).filter((r) => r.proxy === p.name).length;
  const parts = [];
  if (p.subscription) parts.push(serverWord(p.subscription.count || 0));
  else if (p.type === "vless" && p.vless) {
    if (p.vless.network) parts.push(String(p.vless.network).toUpperCase());
    if (p.vless.security) parts.push(String(p.vless.security).toUpperCase());
  } else if (p.username) parts.push(p.username);
  else parts.push("без логина");
  parts.push(n ? n + " " + ruleWord(n) : "не используется");
  if (p.type === "http") parts.push("без UDP");
  else if (p.type !== "vless") parts.push("UDP есть");
  return parts.join(" · ");
}
function probeView(p) {
  if (probing[p.name]) return { kind: "neu", label: "проверка…", detail: "" };
  const check = state.checks && state.checks[p.name];
  if (!check) return { kind: "neu", label: "не проверен", detail: "" };
  if (!check.ok) return { kind: "err", label: "нет ответа", detail: check.detail || "" };
  if ((check.ms || 0) >= 300) return { kind: "warn", label: "медленно", detail: check.label || "" };
  return { kind: "ok", label: check.label || "ок", detail: "" };
}
// copyText copies text; shown, when given, is what the toast says instead
// (a login with its password masked).
async function copyText(text, shown) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  showToast("Скопировано: " + (shown || text));
}
function vinput(id, label, value, span) {
  return `<div class="${span ? "span2" : ""}"><label class="lbl">${label}</label><div class="field"><input class="mono" id="${id}" value="${esc(value || "")}"></div></div>`;
}
function vselect(id, label, value, options) {
  const opts = options.slice();
  if (value && opts.indexOf(value) < 0) opts.unshift(value);
  return `<div><label class="lbl">${label}</label><div class="field"><select id="${id}">${opts.map((o) => `<option value="${esc(o)}"${o === value ? " selected" : ""}>${esc(o)}</option>`).join("")}</select></div></div>`;
}
function probeBadge(rep, type) {
  if (!rep) return "";
  if (!rep.ok) return badge("нет ответа", "err", true, rep.detail || "");
  if ((rep.ms || 0) >= 300) return badge("медленно", "warn", true, rep.label || "");
  let text = rep.label || "ок";
  if (type === "http") text += " · только TCP";
  else text += rep.udp ? " · UDP есть" : "";
  return badge(text, "ok", true);
}
function pickMatch(q, name, path) {
  if (!q) return 1;
  const n = String(name || "").toLowerCase();
  const exe = baseName(path || "").toLowerCase();
  if (n.startsWith(q) || exe.startsWith(q)) return 3;
  if (n.includes(q) || exe.includes(q)) return 2;
  return String(path || "").toLowerCase().includes(q) ? 1 : 0;
}
function trayHTML() {
  const menu = (running, top) => `<div class="tray-card" style="top:${top}px;${running ? "right:80px" : "left:340px"}">
    <div class="tray-hd"><img src="logo.svg" alt=""><div><b>Ashgate</b><span><i style="background:${running ? "var(--ok)" : "var(--tx3)"}"></i>${running ? "Работает · потоков: 12" : "Остановлен"}</span></div></div>
    <div class="tray-sep"></div>
    <div class="tray-item">${icon("window")}<span>Открыть</span></div>
    <div class="tray-item on ${running ? "" : "stop"}">${icon("power")}<span>${running ? "Стоп" : "Старт"}</span></div>
    <div class="tray-sep"></div>
    <div class="tray-item">${icon("exit")}<span>Выход</span></div>
  </div>`;
  return `<div class="tray-wrap"><h1>Меню в трее</h1><p class="lead">Правый клик по значку: «Открыть», «Стоп» или «Старт» по состоянию, «Выход». Закрытие окна прячет его в трей.</p>
    <div style="margin-top:36px;font-size:12px;font-weight:500;color:var(--tx3)">Значок в трее</div>
    <div class="glyphs"><div><div class="glyph">${icon("shield")}<em style="background:#3DD68C"></em></div><span>работает</span></div>
    <div><div class="glyph" style="color:#A3A3AE">${icon("shield")}</div><span>остановлен</span></div>
    <div><div class="glyph" style="color:#FF6363">${icon("shield")}<em style="background:#FF6363"></em></div><span>ошибка</span></div></div>
    ${menu(true, 250)}${menu(false, 250)}
    <div class="taskbar"><div class="apps"><i></i><i></i><i></i><i></i></div><span class="clock">12:04<br>22.10.2026</span></div>
  </div>`;
}

async function post(path, body) {
  const r = await apiFetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || "ошибка");
  return data;
}
// getJSON reads a GET endpoint; an error answer throws with its text.
async function getJSON(path) {
  const r = await apiFetch(path);
  const data = await r.json().catch(() => null);
  if (!r.ok) throw new Error((data && data.error) || "ошибка");
  return data;
}
let reqSeq = 0;
let shownSeq = 0;
// cfgSaving counts config saves queued or in flight; cfgSeq is the last
// request asked before the newest save landed. Answers to those may
// predate the save, so they keep the local config.
let cfgSaving = 0;
let cfgSeq = 0;
let failedPolls = 0;
// shownErr is the server error last shown (or dismissed) as an alert.
let shownErr = "";
// askAuto makes the next state request read the autostart task again.
let askAuto = false;
async function refresh() {
  if (DEMO) { render(); return; }
  const seq = ++reqSeq;
  const auto = askAuto;
  askAuto = false;
  let next;
  try {
    // With the last generation the server skips the event list when no
    // connection was logged since.
    const gen = state && state.events ? state.generation || 0 : 0;
    const signal = AbortSignal.timeout ? AbortSignal.timeout(5000) : undefined;
    const r = await apiFetch("/api/state?gen=" + gen + (auto ? "&auto=1" : ""), { signal });
    if (!r.ok) throw new Error("HTTP " + r.status);
    next = await r.json();
  } catch (e) {
    // A dead or hung backend: after a few misses say so, instead of
    // showing the last frame as if it were live.
    if (auto) askAuto = true;
    failedPolls++;
    setOffline(failedPolls >= 3);
    return;
  }
  failedPolls = 0;
  setOffline(false);
  // Requests can overlap (poll plus a save); never show an older answer
  // over a newer one.
  if (seq < shownSeq) return;
  shownSeq = seq;
  if (next.eventsSame) next.events = (state && state.events) || [];
  const err = next.error || "";
  next.error = "";
  const keep = state && (cfgSaving > 0 || seq <= cfgSeq) ? state.config : null;
  state = next;
  if (keep) state.config = keep;
  if (!paused) frozen = null;
  render();
  if (next.notice) showToast(next.notice);
  noteError(err);
  noteBridge();
}
function setOffline(on) {
  const el = document.getElementById("offline");
  if (el && el.hidden === on) el.hidden = !on;
}
// noteError shows a start or capture error (Start from the tray or at
// logon, a session that failed) until it is dismissed or capture starts.
function noteError(err) {
  if (!err) {
    shownErr = "";
    if (modal && modal.errAlert) { modal = null; renderModal(); }
    return;
  }
  if (err === shownErr || modal || state.hidden) return;
  shownErr = err;
  showStartError(err, "Ошибка");
}
function bridgeNote() {
  const bridges = (state && state.bridges) || {};
  const msgs = [];
  Object.keys(bridges).forEach((name) => {
    const err = bridges[name] && bridges[name].error;
    if (err) msgs.push(name + ": " + err);
  });
  return msgs.join("\n");
}
// quietBridge is set while a save that already warned refreshes, so the
// same bridge error does not pop up again as an alert.
let quietBridge = false;
function noteBridge() {
  const note = bridgeNote();
  if (!note) {
    lastBridge = "";
    return;
  }
  if (note === lastBridge || modal) return;
  lastBridge = note;
  if (quietBridge) return;
  showAlert(/занят/.test(note) ? "Порт занят" : "Локальный мост VLESS", note);
}
// Saves run one at a time, each sending the config as it is when its turn
// comes, so a later save carries the earlier edits too.
let saveChain = Promise.resolve();
let lastWarning = "";
function saveConfig(extra) {
  extra = extra || {};
  cfgSaving++;
  const run = () => saveNow(extra);
  const p = saveChain.then(run, run);
  saveChain = p.catch(() => {});
  return p;
}
async function saveNow(extra) {
  let res;
  try {
    if (DEMO) {
      showToast("Демонстрация: сохранение выключено");
      return {};
    }
    const body = { config: JSON.parse(JSON.stringify(cfg())) };
    if ("autostart" in extra) body.autostart = extra.autostart;
    res = await post("/api/config", body);
  } finally {
    cfgSaving--;
    cfgSeq = reqSeq;
  }
  // Saved, but a bridge or the engine did not take it all (a busy port):
  // a warning, not a failure, and not repeated on every later save.
  const warn = (res && res.warning) || "";
  if (warn && warn !== lastWarning) { showToast("Сохранено. " + warn); res.shown = true; }
  else if (!extra.quiet) showToast("Сохранено");
  lastWarning = warn;
  quietBridge = !!warn;
  try { await refresh(); } finally { quietBridge = false; }
  return res;
}
function showToast(text) {
  const t = document.getElementById("toast");
  t.hidden = false;
  t.textContent = text;
  clearTimeout(showToast._t);
  // Long messages (an error with a path in it) stay longer.
  showToast._t = setTimeout(() => { t.hidden = true; }, Math.min(8000, 3200 + String(text || "").length * 30));
}
function closeMenu() { document.getElementById("menu").hidden = true; }
// openMenu opens a menu under its button, also when opened from the
// keyboard (a click without a mouse position used to put it at 0,0).
function openMenu(anchor, items, keyboard) {
  const m = document.getElementById("menu");
  m.innerHTML = items.map((it) => `<button type="button" class="${it.danger ? "danger" : ""}" data-menu="${it.id}">${esc(it.label)}</button>`).join("");
  m.hidden = false;
  const r = anchor.getBoundingClientRect();
  const w = m.offsetWidth;
  const h = m.offsetHeight;
  const left = Math.max(8, Math.min(r.right - w, window.innerWidth - w - 8));
  let top = r.bottom + 4;
  if (top + h > window.innerHeight - 8) top = Math.max(8, r.top - h - 4);
  m.style.left = left + "px";
  m.style.top = top + "px";
  m.onclick = (e) => {
    const b = e.target.closest("[data-menu]");
    if (!b) return;
    closeMenu();
    items.find((it) => it.id === b.dataset.menu).run();
  };
  if (keyboard) {
    const first = m.querySelector("button");
    if (first) first.focus();
  }
}

function openProxy(index) {
  const src = index >= 0 ? cfg().proxies[index] : { name: "", type: "socks5", address: "", username: "", password: "" };
  const draft = JSON.parse(JSON.stringify(src));
  modal = { kind: "proxy", index, draft, showPass: false, report: null, parsedLink: draft.link || "", parseError: "", socksText: undefined };
  renderModal();
}
// VLESS_INPUTS maps the VLESS fields of the proxy dialog to draft.vless.
const VLESS_INPUTS = {
  "v-uuid": "uuid", "v-net": "network", "v-sec": "security", "v-sni": "sni", "v-fp": "fp", "v-pbk": "pbk",
  "v-sid": "sid", "v-flow": "flow", "v-path": "path", "v-host": "host", "v-svc": "serviceName", "v-mode": "mode",
};
const PROXY_INPUTS = {
  "p-name": "name", "p-addr": "address", "p-link": "link", "p-suburl": "subUrl", "p-user": "username",
  "p-pass": "password", "p-luser": "localUser", "p-lpass": "localPass",
};
// proxyInput keeps the draft in step with every keystroke, as typed, so a
// redraw after a check or a parse never brings back older text. Values are
// trimmed when they are used (readProxyDraft).
function proxyInput(el) {
  if (!modal || modal.kind !== "proxy" || !el.id) return;
  const d = modal.draft;
  if (PROXY_INPUTS[el.id]) d[PROXY_INPUTS[el.id]] = el.value;
  else if (VLESS_INPUTS[el.id]) { d.vless = d.vless || {}; d.vless[VLESS_INPUTS[el.id]] = el.value; }
  else if (el.id === "p-socks") { modal.socksText = el.value; d.socksPort = portValue(el.value); }
  else return;
  paintSocksPreview();
}
function portValue(raw) {
  raw = String(raw || "").trim();
  if (!raw) return 0;
  return /^\d+$/.test(raw) ? Number(raw) : -1;
}
function readProxyDraft() {
  if (!modal || !document.getElementById("p-name")) return;
  modal.draft.name = document.getElementById("p-name").value.trim();
  const addr = document.getElementById("p-addr");
  if (addr) modal.draft.address = addr.value.trim();
  const link = document.getElementById("p-link");
  if (link) modal.draft.link = link.value.trim();
  const subUrl = document.getElementById("p-suburl");
  if (subUrl) modal.draft.subUrl = subUrl.value.trim();
  const user = document.getElementById("p-user");
  if (user) modal.draft.username = user.value;
  const pass = document.getElementById("p-pass");
  if (pass) modal.draft.password = pass.value;
  const socks = document.getElementById("p-socks");
  if (socks) {
    modal.socksText = socks.value;
    modal.draft.socksPort = portValue(socks.value);
  }
  const luser = document.getElementById("p-luser");
  if (luser) modal.draft.localUser = luser.value.trim();
  const lpass = document.getElementById("p-lpass");
  if (lpass) modal.draft.localPass = lpass.value;
  if (modal.draft.type === "vless" && !modal.draft.subscription) readVLESSFields();
}
function readVLESSFields() {
  const v = modal.draft.vless || {};
  const take = (id, key) => {
    const n = document.getElementById(id);
    if (n) v[key] = n.value.trim();
  };
  take("v-uuid", "uuid");
  take("v-net", "network");
  take("v-sec", "security");
  take("v-sni", "sni");
  take("v-fp", "fp");
  take("v-pbk", "pbk");
  take("v-sid", "sid");
  take("v-flow", "flow");
  take("v-path", "path");
  take("v-host", "host");
  take("v-svc", "serviceName");
  take("v-mode", "mode");
  modal.draft.vless = v;
}
function applyParsed(m, parsed) {
  const draft = m.draft;
  draft.address = parsed.address || draft.address;
  draft.vless = parsed.vless || {};
  if (!String(draft.name || "").trim() && parsed.name) draft.name = uniqueProxyName(parsed.name, m.index);
}
// ensureVLESS parses the link of dialog m when it changed since the last
// parse. m is the dialog that asked; it may be closed by the time it ends.
async function ensureVLESS(m) {
  const draft = m.draft;
  const link = (draft.link || "").trim();
  const stale = link && link !== m.parsedLink;
  if (!stale && draft.vless && draft.vless.uuid) return;
  if (!link) throw new Error("Вставьте ссылку VLESS");
  const parsed = await parseVLESS(link);
  applyParsed(m, parsed);
  m.parsedLink = link;
  m.parseError = "";
}
// proxyPayload is the draft as the server's proxy: only its fields, and
// only those of its type. The server refuses unknown fields; a subscription
// URL left from the «Подписка» type used to fail every save.
const PROXY_KEYS = ["name", "type", "address", "username", "password", "link", "vless", "socksPort", "localUser", "localPass", "subscription"];
function proxyPayload(p) {
  const out = {};
  for (const k of PROXY_KEYS) if (p[k] !== undefined) out[k] = JSON.parse(JSON.stringify(p[k]));
  if (out.type === "vless") {
    delete out.username;
    delete out.password;
  } else if (!out.subscription) {
    for (const k of ["link", "vless", "socksPort", "localUser", "localPass"]) delete out[k];
  }
  return out;
}
async function parseVLESS(link) {
  if (DEMO) return parseVLESSJS(link);
  return post("/api/vless/parse", { link });
}
function parseVLESSJS(raw) {
  raw = (raw || "").trim();
  let u;
  try { u = new URL(raw); } catch (e) { throw new Error("Не удалось разобрать ссылку VLESS"); }
  if (u.protocol !== "vless:") throw new Error("Не удалось разобрать ссылку VLESS");
  const uuid = normalizeUUIDJS(u.username || "");
  const host = u.hostname;
  if (!host) throw new Error("Не удалось разобрать ссылку VLESS: в ссылке нет адреса сервера");
  const port = u.port || "443";
  const q = u.searchParams;
  const network = canonNetJS(q.get("type") || "");
  let security = (q.get("security") || "").toLowerCase();
  const pbk = (q.get("pbk") || q.get("publicKey") || "").trim();
  if (!security && pbk) security = "reality";
  if (!security) security = "none";
  if (!["tcp", "ws", "grpc", "xhttp", "httpupgrade"].includes(network)) {
    throw new Error("Не удалось разобрать ссылку VLESS: транспорт " + (network || "не указан") + " не поддерживается");
  }
  const vless = {
    uuid, encryption: (q.get("encryption") || "none").toLowerCase(), flow: (q.get("flow") || "").trim(),
    network, security, sni: (q.get("sni") || q.get("serverName") || "").trim(),
    fp: (q.get("fp") || "").trim(), pbk, sid: (q.get("sid") || q.get("shortId") || "").trim(),
    spx: (q.get("spx") || q.get("spiderX") || "").trim(), path: (q.get("path") || "").trim(),
    host: (q.get("host") || "").trim(), serviceName: (q.get("serviceName") || q.get("service") || "").trim(),
    mode: (q.get("mode") || "").trim(), authority: (q.get("authority") || "").trim(),
    alpn: (q.get("alpn") || "").trim(), headerType: (q.get("headerType") || "").trim(),
  };
  if (/^randomized/i.test(vless.fp)) vless.fp = "";
  if (!vless.fp && (security === "reality" || security === "tls")) vless.fp = "firefox";
  if (security === "reality" && !vless.spx) vless.spx = "/";
  if (q.get("allowInsecure") === "1" || q.get("insecure") === "1") vless.allowInsecure = true;
  const extra = q.get("extra");
  if (extra) {
    try { vless.extra = JSON.parse(extra); } catch (e) { throw new Error("Не удалось разобрать ссылку VLESS: поле extra не является JSON"); }
  }
  if (vless.encryption !== "none") throw new Error("Не удалось разобрать ссылку VLESS: шифрование должно быть none");
  if (security === "reality" && !pbk) throw new Error("Не удалось разобрать ссылку VLESS: для REALITY нужен публичный ключ (pbk)");
  if (security === "reality" && !vless.sni) throw new Error("Не удалось разобрать ссылку VLESS: для REALITY укажите SNI");
  if (network === "grpc" && !vless.serviceName && vless.path) {
    vless.serviceName = vless.path.replace(/^\/+|\/+$/g, "");
    vless.path = "";
  }
  if (network === "grpc" && !vless.serviceName) throw new Error("Не удалось разобрать ссылку VLESS: для gRPC укажите serviceName");
  let name = "";
  try { name = suggestNameJS(decodeURIComponent(u.hash.replace(/^#/, ""))); } catch (e) { name = suggestNameJS(u.hash.replace(/^#/, "")); }
  const address = host.includes(":") ? "[" + host + "]:" + port : host + ":" + port;
  return { name, address, vless };
}
function canonNetJS(s) {
  s = (s || "").toLowerCase();
  if (!s || s === "tcp" || s === "raw") return "tcp";
  if (s === "ws" || s === "websocket") return "ws";
  if (s === "grpc" || s === "gun") return "grpc";
  if (s === "xhttp" || s === "splithttp") return "xhttp";
  return s;
}
function normalizeUUIDJS(s) {
  const hex = String(s || "").replace(/-/g, "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error("Не удалось разобрать ссылку VLESS: неверный UUID");
  return hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
}
// suggestNameJS mirrors vless.SuggestName (demo mode only).
function suggestNameJS(fragment) {
  let s = "";
  for (const ch of String(fragment || "").trim()) {
    if (/[\p{L}\p{Nd}_.-]/u.test(ch)) s += ch;
    else if (ch === " " || ch === "+") s += " ";
    else if (ch === "/") s += "-";
  }
  s = s.split(/\s+/).filter(Boolean).join(" ").replace(/--+/g, "-");
  return [...s].slice(0, 64).join("").replace(/^[-_. ]+|[-_. ]+$/g, "");
}
// validProxyName mirrors config.validName: letters and digits of any
// script, space, '.', '_' and '-', up to 64 characters, starting with a
// letter or digit, no trailing space.
const NAME_RULE = "Имя прокси: буквы, цифры, пробел, точка, _ или -, до 64 символов; начинается с буквы или цифры.";
function validProxyName(name) {
  return [...name].length <= 64 && name === name.trim() && /^[\p{L}\p{Nd}][\p{L}\p{Nd} _.-]*$/u.test(name);
}
// uniqueProxyName returns base, or base with " 2", " 3"… when another
// proxy (not the one at skip) already has that name.
function uniqueProxyName(base, skip) {
  const taken = new Set((cfg().proxies || []).filter((_, i) => i !== skip).map((x) => x.name));
  if (!taken.has(base)) return base;
  for (let n = 2; ; n++) {
    const tail = " " + n;
    const name = [...base].slice(0, 64 - tail.length).join("").trim() + tail;
    if (!taken.has(name)) return name;
  }
}
// defaultProxyName is used when the name field and the link's #fragment
// give nothing: "VLESS 203.0.113.10", or just the type for an IPv6 host.
function defaultProxyName(p) {
  const label = proxyTypeLabel(p.type);
  const host = String(p.address || "").replace(/:\d+$/, "");
  return validProxyName(label + " " + host) ? label + " " + host : label;
}
async function commitProxy() {
  const m = modal;
  readProxyDraft();
  m.nameError = "";
  m.addrError = "";
  m.subError = "";
  m.portError = "";
  const p = m.draft;
  if (p.type === "sub" && !p.subscription) return commitSub(m);
  delete p.subUrl;
  if (p.subscription) {
    // Only the name of a saved subscription changes here.
  } else if (p.type === "vless") {
    try { await ensureVLESS(m); } catch (e) {
      if (modal === m) { m.parseError = linkFail(e.message); renderModal(); }
      return;
    }
    if (modal !== m) return; // cancelled while the link was parsed
    if (p.socksPort < 0 || p.socksPort > 65535) { showToast("Локальный SOCKS5-порт: число от 1 до 65535 или пусто"); return; }
    delete p.username;
    delete p.password;
    if (!p.socksPort) delete p.socksPort;
    // A published port always has a login: make one up when the fields
    // are empty, so it stays the same after a restart.
    if (p.socksPort && !p.localUser) { p.localUser = "ashgate-" + randomHex(3); p.localPass = randomHex(12); }
    if (!p.localUser) delete p.localUser;
    if (!p.localPass) delete p.localPass;
    if (DEMO) {
      state.bridges = state.bridges || {};
      if (p.socksPort) state.bridges[p.name] = { published: "127.0.0.1:" + p.socksPort, http: p.socksPort < 65535 ? "127.0.0.1:" + (p.socksPort + 1) : "", up: true };
      else delete state.bridges[p.name];
    }
  } else {
    delete p.link;
    delete p.vless;
    delete p.socksPort;
    delete p.localUser;
    delete p.localPass;
  }
  if (!p.address && !p.subscription) {
    if (p.type === "vless") showToast("Вставьте ссылку VLESS");
    else { m.addrError = "Укажите адрес: хост:порт, например 127.0.0.1:1080"; renderModal(); }
    return;
  }
  if (!p.name) p.name = uniqueProxyName(defaultProxyName(p), m.index);
  if (!validProxyName(p.name)) { m.nameError = NAME_RULE; renderModal(); return; }
  if (uniqueProxyName(p.name, m.index) !== p.name) { m.nameError = "Прокси с таким именем уже есть."; renderModal(); return; }
  // Work on the live config, but keep a copy: a rejected save must not
  // leave the new proxy in the list (a retry would add it twice).
  const before = JSON.parse(JSON.stringify(cfg()));
  const list = cfg().proxies;
  const oldName = m.index >= 0 ? list[m.index].name : "";
  if (m.index < 0) list.push(proxyPayload(p));
  else list[m.index] = proxyPayload(p);
  if (oldName && oldName !== p.name) renameProxyRefs(oldName, p.name);
  modal = null;
  built = "";
  render();
  // A save that applied with a warning (a busy port) is still saved: the
  // dialog stays closed and saveConfig shows the warning.
  saveConfig().then(() => { sel.proxy = m.index < 0 ? list.length - 1 : m.index; }).catch((e) => {
    const msg = e.message || "";
    if (state) state.config = before;
    built = "";
    render();
    if (modal) { showToast(msg); return; }
    modal = m;
    if (/^Имя прокси/i.test(msg)) m.nameError = msg;
    else if (/^Адрес прокси/i.test(msg) && m.draft.type !== "vless") m.addrError = msg;
    else if (/порт/i.test(msg)) m.portError = /занят|совпадает/i.test(msg) ? "Порт занят. " + msg : msg;
    else if (/разобрать ссылку/i.test(msg)) m.parseError = linkFail(msg);
    else showToast(msg);
    renderModal();
  });
}
// commitSub adds a subscription: the server downloads it first (up to
// 15 s) and adds nothing when that fails. Its outcome shows even when the
// dialog was cancelled meanwhile.
async function commitSub(m) {
  const p = m.draft;
  if (!p.subUrl) { m.subError = "Вставьте ссылку подписки"; renderModal(); return; }
  if (!/^https?:\/\//i.test(p.subUrl)) { m.subError = "Ссылка должна начинаться с https:// или http://"; renderModal(); return; }
  if (!p.name) p.name = uniqueProxyName("Подписка", -1);
  if (!validProxyName(p.name)) { m.nameError = NAME_RULE; renderModal(); return; }
  if (uniqueProxyName(p.name, -1) !== p.name) { m.nameError = "Прокси с таким именем уже есть."; renderModal(); return; }
  if (DEMO) { showToast("Демонстрация: подписки не загружаются"); return; }
  m.busy = true;
  renderModal();
  try {
    const res = await post("/api/subscription", { name: p.name, url: p.subUrl });
    if (modal === m) modal = null;
    built = "";
    await refresh();
    sel.proxy = (cfg().proxies || []).findIndex((x) => x.name === p.name);
    showToast(res && res.warning ? "Подписка добавлена. " + res.warning : "Подписка добавлена");
  } catch (e) {
    const msg = e.message || "";
    if (modal !== m) { showToast(msg); return; }
    m.busy = false;
    if (/^Имя прокси/i.test(msg)) m.nameError = msg;
    else m.subError = msg;
    renderModal();
  }
}
function randomHex(bytes) {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
function linkFail(msg) {
  const rest = String(msg || "").replace(/^Не удалось разобрать ссылку VLESS:?\s*/i, "").trim();
  if (!rest || rest === String(msg || "").trim()) return "Ссылка не разобрана";
  return "Ссылка не разобрана. " + rest;
}
// renameProxyRefs points rules, groups and the system resolver at a
// renamed proxy; otherwise the save fails with "unknown proxy".
function renameProxyRefs(from, to) {
  const c = cfg();
  for (const r of c.rules || []) if (r.proxy === from) r.proxy = to;
  for (const g of c.groups || []) if (g.proxy === from) g.proxy = to;
  if (c.dns && c.dns.systemResolverProxy === from) c.dns.systemResolverProxy = to;
}
function proxyInUse(name) {
  return (cfg().rules || []).some((r) => r.proxy === name) || (cfg().groups || []).some((g) => g.proxy === name) ||
    (cfg().dns.systemResolver !== "direct" && cfg().dns.systemResolverProxy === name);
}
// dnsServer adds the default port to a bare IP: "1.1.1.1" -> "1.1.1.1:53".
function dnsServer(s) {
  s = String(s || "").trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return s + ":53";
  if (/^[0-9a-f]*:[0-9a-f:]*:[0-9a-f]*$/i.test(s) && !s.startsWith("[")) return "[" + s + "]:53";
  return s;
}
// cleanDomains turns pasted text into bare domains: "https://www.vk.com/feed"
// and "*.vk.com" become "www.vk.com" and "vk.com"; duplicates go.
function cleanDomains(text) {
  const out = [];
  for (let d of String(text || "").split(/[\s,;]+/)) {
    d = d.trim().toLowerCase().replace(/^[a-z]+:\/\//, "").replace(/[\/?#].*$/, "").replace(/:\d+$/, "");
    d = d.replace(/^\*?\.+/, "").replace(/\.+$/, "");
    // Cyrillic names (госуслуги.рф) stay as typed; the server checks and
    // converts them.
    if (d && !out.includes(d)) out.push(d);
  }
  return out;
}
// readSettings takes the Settings controls as they are on the page.
function readSettings() {
  const on = (k) => document.querySelector(`[data-key="${k}"]`).classList.contains("on");
  const s = {};
  s.dnsMode = on("dns") ? "proxy" : "original";
  const dnsInput = document.getElementById("dns-servers");
  s.servers = dnsInput.value.split(/[,\s]+/).map(dnsServer).filter(Boolean);
  if (s.servers.length) dnsInput.value = s.servers.join(", ");
  s.systemResolver = on("sys") ? "tunnel" : "direct";
  const sp = document.getElementById("sys-proxy");
  s.systemResolverProxy = sp ? sp.value : "";
  const udp = document.querySelector('[data-key="udp"].on');
  s.udpUnsupported = udp ? udp.dataset.value : "block";
  s.bypassPrivate = on("bypass");
  const dd = document.getElementById("direct-domains");
  if (dd) {
    s.directDomains = cleanDomains(dd.value);
    dd.value = s.directDomains.join("\n");
  }
  s.killSwitch = on("kill");
  s.logLevel = on("verbose") ? "debug" : "info";
  s.auto = on("auto");
  return s;
}
function applySettings(c, s) {
  c.dns = c.dns || {};
  c.dns.mode = s.dnsMode;
  c.dns.servers = s.servers;
  c.dns.systemResolver = s.systemResolver;
  c.dns.systemResolverProxy = s.systemResolverProxy;
  c.udpUnsupported = s.udpUnsupported;
  c.bypassPrivate = s.bypassPrivate;
  if (s.directDomains) c.directDomains = s.directDomains;
  c.killSwitch = s.killSwitch;
  c.log = c.log || {};
  c.log.level = s.logLevel;
}

function onClick(e) {
  const nav = e.target.closest("[data-nav]");
  if (nav) {
    // Settings edits are saved whatever page comes next.
    if (settingsPending) flushSettings();
    page = nav.dataset.nav; built = ""; modal = null; closeMenu(); render(); return;
  }
  const act = e.target.closest("[data-act]");
  if (!act) return;
  const id = act.dataset.act;
  const i = Number(act.dataset.i);
  if (id === "copy-text") { copyText(act.dataset.text || "", act.dataset.shown); return; }
  if (id.startsWith("ap-")) { appsClick(id, act); return; }
  if (id === "goto") { page = act.dataset.page; built = ""; render(); return; }
  if (id === "sel-proxy") { sel.proxy = i; fillProxies(); return; }
  if (id === "sel-log") {
    const key = act.dataset.key || "";
    const ev = logEvents().find((x) => eventKey(x) === key);
    sel.log = key;
    if (ev && ev.status === "error") openErr = openErr === key ? "" : key;
    fillLog();
    return;
  }
  if (id === "goto-rule") {
    const proc = (act.dataset.proc || "").toLowerCase();
    page = "rules";
    built = "";
    apQuery = appLabel(proc);
    render();
    return;
  }
  if (id === "paste-vless") { pasteVLESS(); return; }
  if (id === "ks-start") { if (!state.running) startStop(); return; }
  if (id === "errors-only") {
    errorsOnly = !errorsOnly;
    built = "";
    render();
    return;
  }
  if (id === "update-check") { checkUpdate(); return; }
  if (id === "update-open") {
    if (DEMO) return;
    post("/api/update/open").catch((err) => showToast(err.message));
    return;
  }
  if (id === "open-folder") {
    if (DEMO) { showToast(state.path || ""); return; }
    post("/api/reveal").catch((err) => showToast(err.message));
    return;
  }
  if (id === "proxy-add") return openProxy(-1);
  if (id === "sub-refresh") return refreshSub(act.dataset.name || "");
  if (id === "proxy-edit") return openProxy(i);
  if (id === "proxy-del") return deleteProxy(i);
  if (id === "menu-proxy") {
    const name = cfg().proxies[i].name;
    const items = [
      { id: "edit", label: "Изменить", run: () => openProxy(i) },
      { id: "probe", label: "Проверить", run: () => probeNamed(name) },
      { id: "del", label: "Удалить", danger: true, run: () => deleteProxy(i) },
    ];
    if (cfg().proxies[i].subscription) items.splice(1, 0, { id: "sub-refresh", label: "Обновить подписку", run: () => refreshSub(name) });
    openMenu(act, items, e.detail === 0);
    return;
  }
  if (id === "probe-all") {
    if (probeAllBusy) return;
    probeAllBusy = true;
    const names = (cfg().proxies || []).map((p) => p.name);
    names.forEach(probeStart);
    fillProxies();
    const done = () => { probeAllBusy = false; names.forEach(probeEnd); fillProxies(); };
    if (DEMO) { setTimeout(done, 600); return; }
    post("/api/probe-all").then((checks) => {
      if (state && checks) state.checks = Object.assign({}, state.checks, checks);
      done();
    }).catch((err) => { done(); showToast(err.message); });
    return;
  }
  if (id === "head-more") {
    const actions = [...document.querySelectorAll(".head-actions .btn.secondary")].map((b) => ({
      id: b.dataset.act,
      label: b.textContent.trim(),
      run: () => b.click(),
    }));
    if (actions.length) openMenu(act, actions, e.detail === 0);
    return;
  }
  if (id === "pause") {
    paused = !paused;
    frozen = paused ? (state.events || []).slice() : null;
    fillLog();
    return;
  }
  if (id === "clear") {
    askConfirm("Очистить экран?", "Строки исчезнут с экрана. Файл ashgate.log останется.", "Очистить", true, () => {
      frozen = [];
      if (!DEMO) post("/api/log/clear").then(refresh).catch((err) => showToast(err.message));
      else { state.events = []; fillLog(); }
    });
    return;
  }
  if (id === "proto") {
    logProto = act.dataset.value;
    document.querySelectorAll("#log-seg button").forEach((b) => b.classList.toggle("on", b === act));
    fillLog();
    return;
  }
  if (id === "toggle") {
    act.classList.toggle("on");
    act.setAttribute("aria-pressed", act.classList.contains("on") ? "true" : "false");
    if (act.dataset.key === "dns") {
      const input = document.getElementById("dns-servers");
      if (input) input.disabled = !act.classList.contains("on");
    }
    if (act.dataset.key === "sys") {
      const s = document.getElementById("sys-proxy");
      if (s) s.disabled = !act.classList.contains("on");
    }
    if (page === "settings") queueSettings(act.dataset.key === "auto");
    return;
  }
  if (id === "seg") {
    act.parentElement.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b === act));
    if (page === "settings") queueSettings();
    return;
  }
  if (id === "cancel") { modal = null; renderModal(); return; }
  if (id === "eye") { modal.showPass = !modal.showPass; readProxyDraft(); renderModal(); return; }
  if (id === "ptype") {
    // A saved subscription stays one: its only type button does nothing.
    if (modal.draft.subscription) return;
    readProxyDraft();
    modal.draft.type = act.dataset.value;
    modal.report = null;
    modal.parseError = "";
    renderModal();
    return;
  }
  // Results of a parse or a check land only in the dialog that asked:
  // it may be closed, or another one open, by then.
  if (id === "parse-link") {
    readProxyDraft();
    const m = modal;
    parseVLESS(m.draft.link).then((parsed) => {
      if (modal !== m) return;
      applyParsed(m, parsed);
      m.parsedLink = (m.draft.link || "").trim();
      m.parseError = "";
      renderModal();
    }).catch((err) => {
      if (modal !== m) return;
      m.parseError = linkFail(err.message);
      renderModal();
    });
    return;
  }
  if (id === "probe-draft") {
    readProxyDraft();
    const m = modal;
    if (DEMO) { m.report = { ok: true, udp: m.draft.type !== "http", label: "42 мс" }; renderModal(); return; }
    if (m.checking) return;
    const run = () => {
      if (modal !== m) return;
      m.checking = true;
      m.report = null;
      renderModal();
      post("/api/probe", { proxy: proxyPayload(m.draft) }).then((rep) => {
        if (modal !== m) return;
        m.checking = false;
        m.report = rep;
        m.realityError = realityFail(m.draft, rep);
        renderModal();
      }).catch((err) => {
        if (modal !== m) return;
        m.checking = false;
        renderModal();
        showToast(err.message);
      });
    };
    if (m.draft.type === "vless") {
      ensureVLESS(m).then(run).catch((err) => { if (modal === m) showToast(err.message); });
    } else run();
    return;
  }
}
function probeStart(name) { probing[name] = (probing[name] || 0) + 1; }
function probeEnd(name) { if (--probing[name] <= 0) delete probing[name]; }
function probeNamed(name) {
  probeStart(name);
  if (page === "proxies") fillProxies();
  if (DEMO) { setTimeout(() => { probeEnd(name); fillProxies(); }, 600); return; }
  post("/api/probe", { name }).then((rep) => {
    probeEnd(name);
    if (state) { state.checks = state.checks || {}; state.checks[name] = rep; }
    fillProxies();
  }).catch((err) => { probeEnd(name); fillProxies(); showToast(err.message); });
}
// Settings are read from the page when they change and saved 400 ms later,
// whatever page is open by then: leaving by a tab click (its mousedown
// ends a text edit) used to lose them.
let settingsPending = null;
let settingsSaving = 0;
function queueSettings(autoTouched) {
  if (!document.querySelector('[data-key="dns"]')) return;
  const s = readSettings();
  s.autoTouched = !!autoTouched || !!(settingsPending && settingsPending.autoTouched);
  settingsPending = s;
  clearTimeout(settingsTimer);
  settingsTimer = setTimeout(flushSettings, 400);
}
function flushSettings() {
  clearTimeout(settingsTimer);
  settingsTimer = null;
  const s = settingsPending;
  settingsPending = null;
  if (!s || !state) return;
  applySettings(cfg(), s);
  const extra = { quiet: true };
  if (s.autoTouched) extra.autostart = s.auto;
  settingsSaving++;
  // A rejected save: the toast says why and the page shows the saved
  // values again (fillSettings), not the rejected ones.
  saveConfig(extra).catch((err) => { showToast(err.message); return refresh(); })
    .finally(() => { settingsSaving--; if (page === "settings") fillPage(); });
}
async function pasteVLESS(silent) {
  let text = "";
  try { text = await navigator.clipboard.readText(); } catch (e) {
    if (!silent) showToast("Не удалось прочитать буфер обмена");
    return;
  }
  text = (text || "").trim();
  if (!text.toLowerCase().startsWith("vless://")) {
    if (!silent) showToast("В буфере нет ссылки vless://");
    return;
  }
  page = "proxies";
  built = "";
  render();
  openProxy(-1);
  const m = modal;
  m.draft.type = "vless";
  m.draft.link = text;
  renderModal();
  parseVLESS(text).then((parsed) => {
    if (modal !== m) return;
    applyParsed(m, parsed);
    m.parsedLink = text;
    m.parseError = "";
    renderModal();
  }).catch((err) => {
    if (modal !== m) return;
    m.parseError = linkFail(err.message);
    renderModal();
  });
}
// showStartError shows why capture did not start. The server's text is
// already the plain Russian explanation (windivert.FormatError and the
// runtime add the code and the conflicting programs). The alert closes by
// itself when capture starts.
function showStartError(msg, title) {
  showAlert(title || "Перехват не запустился", String(msg || "").trim() || "Не удалось запустить перехват.");
  modal.errAlert = true;
}
function startStop() {
  if (powerBusy) return;
  const path = state.running ? "/api/stop" : "/api/start";
  if (DEMO) {
    state.running = !state.running;
    state.driver = state.running;
    render();
    return;
  }
  const starting = !state.running;
  powerBusy = true;
  render();
  post(path).then(refresh).catch((err) => {
    if (starting) { shownErr = err.message; showStartError(err.message); }
    else showToast(err.message);
  }).finally(() => { powerBusy = false; render(); });
}
function askConfirm(title, text, ok, danger, run) {
  modal = { kind: "confirm", title, text, ok, danger, run };
  renderModal();
}
function showAlert(title, text) {
  modal = { kind: "alert", title, text };
  renderModal();
}
function realityFail(draft, rep) {
  if (!rep || rep.ok) return "";
  const sec = draft && draft.vless && draft.vless.security;
  if (sec !== "reality" && !/reality/i.test(rep.detail || "")) return "";
  return "Проверка REALITY не прошла" + (rep.detail ? ". " + rep.detail : "");
}
function deleteProxy(i) {
  const name = cfg().proxies[i].name;
  if (proxyInUse(name)) {
    showAlert("Прокси используется", "«" + name + "» указан в приложении, группе или системном резолвере. Сначала смените их, потом удаляйте прокси.");
    return;
  }
  askConfirm("Удалить прокси?", "«" + name + "» исчезнет из списка. Это нельзя отменить.", "Удалить", true, () => {
    cfg().proxies.splice(i, 1);
    if (sel.proxy >= cfg().proxies.length) sel.proxy = cfg().proxies.length - 1;
    saveConfig().catch((err) => showToast(err.message));
  });
}
function onSubmit(e) {
  const form = e.target.closest("#dlg");
  if (!form) return;
  e.preventDefault();
  if (modal && modal.kind === "proxy" && !modal.busy) commitProxy();
  else if (modal && AP_MODALS[modal.kind]) appsSubmit();
  else if (modal && modal.kind === "confirm") {
    const run = modal.run;
    modal = null;
    renderModal();
    if (run) run();
  } else if (modal && modal.kind === "alert") {
    modal = null;
    renderModal();
  }
}
function win(op) {
  const fn = window["ashgate" + op];
  if (typeof fn === "function") fn();
  else if (!DEMO) post("/api/window", { op: op.toLowerCase() }).catch(() => {});
}

function bootChrome() {
  document.getElementById("win-min").innerHTML = icon("min", 12);
  document.getElementById("win-max").innerHTML = icon("max", 12);
  document.getElementById("win-close").innerHTML = icon("close", 12);
  // The window has no native top border; these strips resize from the top.
  document.querySelectorAll("#titlebar [data-edge]").forEach((el) => {
    el.addEventListener("mousedown", (e) => {
      if (e.button !== 0) return;
      e.stopPropagation();
      if (typeof window.ashgateResize === "function") window.ashgateResize(el.dataset.edge);
    });
  });
  document.getElementById("titlebar").addEventListener("mousedown", (e) => {
    if (e.button !== 0 || e.target.closest("button") || e.target.closest("[data-edge]")) return;
    win("Drag");
  });
  document.getElementById("titlebar").addEventListener("dblclick", (e) => {
    if (e.target.closest("button") || e.target.closest("[data-edge]")) return;
    win("Max");
  });
  document.getElementById("win-min").onclick = () => win("Min");
  document.getElementById("win-max").onclick = () => win("Max");
  document.getElementById("win-close").onclick = () => win("Close");
  document.body.addEventListener("click", (e) => {
    if (e.target.closest("#side-power")) {
      startStop();
      return;
    }
    onClick(e);
  });
  document.body.addEventListener("submit", onSubmit);
  document.body.addEventListener("input", (e) => {
    if (appsInput(e)) return;
    if (e.target.closest("#modal")) proxyInput(e.target);
    if (e.target.id === "log-filter") { logFilter = e.target.value; fillLog(); }
  });
  // Text and select settings save when the user finishes editing, not on
  // every keystroke: a half-typed DNS address used to pop an error.
  document.body.addEventListener("change", (e) => {
    if (e.target.closest("#modal")) { apInput(e.target); proxyInput(e.target); return; }
    if (page === "settings" && e.target.closest(".page") && (e.target.id === "dns-servers" || e.target.id === "sys-proxy" || e.target.id === "direct-domains")) queueSettings();
  });
  // A file or link dropped on the window would open in it, as a page from
  // elsewhere. Rule cards take their own drags (apBindDrag).
  const external = (e) => !apDrag && e.dataTransfer && Array.from(e.dataTransfer.types || []).some((t) => t === "Files" || t === "text/uri-list" || t === "text/html");
  document.addEventListener("dragover", (e) => {
    if (!external(e)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "none";
  });
  document.addEventListener("drop", (e) => { if (external(e)) e.preventDefault(); });
  document.body.addEventListener("mouseover", (e) => {
    const el = e.target.closest("td, .nm, .sub, .addr, .main");
    if (el && !el.title && !el.querySelector("button") && el.scrollWidth > el.clientWidth) {
      const text = el.textContent.replace(/\s+/g, " ").trim();
      if (text) el.title = text;
    }
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      modal = null;
      closeMenu();
      renderModal();
      if (apOpen) { apOpen = ""; if (page === "rules") fillApps(); }
    }
  });
  document.addEventListener("click", (e) => {
    if (!e.target.closest("#menu") && !e.target.closest("[data-act='menu-proxy']") && !e.target.closest("[data-act='menu-rule']") && !e.target.closest("[data-act='head-more']")) closeMenu();
  });
}

function applyRoute() {
  const h = (location.hash || "#rules").replace("#", "");
  if (h === "tray") page = "tray";
  else if (h === "empty") {
    page = "proxies";
    if (state) {
      state.running = false;
      state.config.proxies = [];
      state.config.rules = [];
      state.events = [];
      state.checks = {};
      state.bridges = {};
      state.bytesUp = 0;
      state.bytesDown = 0;
      state.active = 0;
    }
  } else if (h === "start-error") page = "rules";
  else if (h === "proxy-dialog" || h === "vless-dialog") { page = "proxies"; }
  else if (h === "rule-dialog") { page = "rules"; }
  else if (["proxies", "rules", "log", "settings"].includes(h)) page = h;
  built = "";
}

async function main() {
  bootChrome();
  if (DEMO) {
    state = demoState();
    applyRoute();
    render();
    if (location.hash === "#proxy-dialog") openProxy(0);
    if (location.hash === "#vless-dialog") openProxy(cfg().proxies.findIndex((p) => p.type === "vless"));
    if (location.hash === "#rule-dialog") apOpenAdd();
    if (location.hash === "#start-error") showStartError("доступ запрещён; запустите Ashgate от имени администратора (код 5)");
    window.addEventListener("hashchange", () => {
      modal = null; applyRoute(); render();
      if (location.hash === "#proxy-dialog") openProxy(0);
      if (location.hash === "#vless-dialog") openProxy(cfg().proxies.findIndex((p) => p.type === "vless"));
      if (location.hash === "#rule-dialog") apOpenAdd();
    });
    return;
  }
  await refresh();
  // Without proxies there is nothing to route yet: start on the Proxies tab.
  if (state && !(cfg().proxies || []).length) { page = "proxies"; built = ""; render(); pasteVLESS(true); }
  poll();
  // The host calls ashgateShown when the window is back on screen.
  window.ashgateShown = wakePoll;
  document.addEventListener("visibilitychange", () => { if (!document.hidden) wakePoll(); });
  window.addEventListener("focus", wakePoll);
}
// poll waits for each answer before asking again, so slow replies cannot
// pile up; it goes on while a dialog is open. The live log needs 250 ms,
// the other pages show figures that change once a second. In the tray or
// minimized (the host reports it: WebView2 does not set document.hidden)
// it stops: the tray icon gets its state from Go, and the host wakes the
// page when it is shown again.
let polling = false;
async function poll() {
  polling = true;
  await refresh();
  if (document.hidden || (state && state.hidden && failedPolls === 0)) { polling = false; return; }
  let wait = 1000;
  if (failedPolls) wait = 2000;
  else if (page === "log" && !paused) wait = 250;
  setTimeout(poll, wait);
}
function wakePoll() {
  if (!polling && !DEMO) poll();
}
main();
