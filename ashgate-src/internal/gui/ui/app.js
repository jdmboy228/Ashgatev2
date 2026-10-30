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
function setText(el, text) {
  if (el && el.textContent !== text) el.textContent = text;
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
const ACTION = {
  proxy: ["прокси", "neu"],
  direct: ["напрямую", "neu"],
  block: ["блокировать", "warn"],
};

let state = null;
let page = "rules";
let modal = null;
let paused = false;
let frozen = null;
let logFilter = "";
let logProto = "all";
let sel = { proxy: 0, rule: -1, log: "" };
let dragging = false;
let built = "";
let lastErr = "";
let lastBridge = "";
let tipEl = null;
let rulesDirty = false;
let rulesSnapshot = "";
let errorsOnly = false;
let openErr = "";
let probing = {};
let clipboardTried = false;
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
function enabledCount(rules) {
  return (rules || []).filter((r) => r.enabled !== false).length;
}
function usedProxies(cfg) {
  const s = new Set();
  (cfg.rules || []).forEach((r) => { if (r.enabled !== false && r.action === "proxy" && r.proxy) s.add(r.proxy); });
  return s.size;
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
function actionBadge(a) {
  const m = ACTION[a] || [a, "neu"];
  return badge(m[0], m[1], false);
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
      aeza: { socks: "127.0.0.1:10808", http: "127.0.0.1:10809", up: true },
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
      dns: { mode: "proxy", servers: ["1.1.1.1:53", "8.8.8.8:53"], includeSystemResolver: false, systemResolverProxy: "local" },
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
    ruleStats: {
      "*\\discord\\app-*\\discord.exe": { flows: 18, up: 9200000, down: 842000000, upRate: 122880, downRate: 2516582 },
      "c:\\users\\user\\appdata\\roaming\\telegram desktop\\telegram.exe": { flows: 6, up: 31000000, down: 1150000000, upRate: 12288, downRate: 184320 },
      "cursor.exe": { flows: 8, up: 4100000, down: 210000000, upRate: 34816, downRate: 430080 },
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
  setHTML(side, `<button class="side-power" id="side-power" type="button" aria-label="${powerLabel}">${icon("power", 20)}</button>
    <div class="side-state"><i class="dot"></i><span>${powerLabel}</span></div>`);
  const btn = document.getElementById("side-power");
  const tip = sideName + " · " + sideSub;
  if (btn && btn.title !== tip) btn.title = tip;
  renderDirty();
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
  <span class="onlyerr">Только ошибки <button class="toggle${onlyOn}" type="button" data-act="errors-only" aria-pressed="${errorsOnly ? "true" : "false"}"><i></i></button></span>
  <div class="live" id="live"><i></i><span></span></div></div>
  <div class="pause-banner" id="pause-banner" hidden></div>
  <div id="log-table"></div>`;
}
function settingsHTML() {
  const c = cfg();
  const dnsOn = c.dns.mode !== "original";
  const sys = !!c.dns.includeSystemResolver;
  const udp = c.udpUnsupported === "direct" ? 1 : 0;
  const names = (c.proxies || []).map((p) => p.name);
  const selProxy = c.dns.systemResolverProxy || names[0] || "";
  return `<div class="head"><div><h1>Настройки</h1><p class="sub">Применяются сразу · ${esc(state.path || "config.json")}</p></div>
  <div class="head-actions"><button class="btn ghost" data-act="open-folder" type="button">${icon("folder")}Открыть папку</button></div></div>
  ${group("DNS", [
    row("globe", "DNS приложений через прокси", "Порт 53 выбранных приложений уходит через прокси их правила", toggle("dns", dnsOn)),
    row("server", "DNS-серверы", "Куда отправлять эти запросы", `<input class="mono" id="dns-servers" value="${esc((c.dns.servers || []).join(", "))}" ${dnsOn ? "" : "disabled"}>`),
    row("sliders", "Системный резолвер (svchost.exe)", "Влияет на DNS всех программ, не только выбранных", `${select("sys-proxy", names, selProxy, !sys)}${toggle("sys", sys)}`, true),
  ])}
  ${group("Защита от утечек", [
    row("shield", "Kill switch", "Приложения с правилом «прокси» и их дочерние процессы никогда не выходят в сеть напрямую. Пока перехват выключен или Ashgate закрыт, Брандмауэр Windows отключает их от сети", toggle("kill", !!c.killSwitch), true),
  ])}
  ${group("UDP и сеть", [
    row("swap", "UDP, который прокси не умеет", "Для HTTP-прокси: QUIC и игры. «Блокировать» не даёт обойти прокси", segCtrl("udp", ["Блокировать", "Напрямую"], ["block", "direct"], udp)),
    row("link", "Не проксировать частные сети", "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7 — напрямую", toggle("bypass", !!c.bypassPrivate)),
  ])}
  ${group("Запуск и журнал", [
    row("rocket", "Запускать с Windows", "При входе в систему открывается окно и включается перехват", toggle("auto", !!state.autostart)),
    row("doc", "Подробный журнал", "Уровень debug вместо info в ashgate.log", toggle("verbose", c.log && c.log.level === "debug")),
  ])}
  ${group("О программе", [aboutRow()])}`;
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
function row(ic, title, desc, ctl, warn) {
  return `<div class="set">${icon(ic, 20)}<div class="txt"><div class="t">${esc(title)}</div><div class="d${warn ? " warn" : ""}">${esc(desc)}</div></div><div class="ctl">${ctl}</div></div>`;
}
function toggle(key, on) {
  return `<button class="toggle${on ? " on" : ""}" type="button" data-act="toggle" data-key="${key}" aria-pressed="${on ? "true" : "false"}"><i></i></button>`;
}
function segCtrl(key, labels, values, active) {
  return `<div class="seg">${labels.map((l, i) => `<button type="button" data-act="seg" data-key="${key}" data-value="${values[i]}" class="${i === active ? "on" : ""}">${l}</button>`).join("")}</div>`;
}
function select(id, names, value, disabled) {
  const opts = names.map((n) => `<option ${n === value ? "selected" : ""}>${esc(n)}</option>`).join("");
  return `<select id="${id}" ${disabled ? "disabled" : ""}>${opts || `<option value="">нет прокси</option>`}</select>`;
}

function fillPage() {
  if (!state) return;
  if (page === "proxies") fillProxies();
  if (page === "rules") fillApps();
  if (page === "log") fillLog();
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
  const btn = !state.running ? `<button class="btn pri sm" type="button" data-act="ks-start">${icon("power", 14)}Старт</button>` : "";
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
  const list = cfg().proxies || [];
  if (!list.length) {
    setHTML(host, `<div class="empty-card"><h3>Прокси ещё нет</h3><p>Добавьте SOCKS5, HTTP или вставьте ссылку vless://.</p><button class="btn pri" type="button" data-act="proxy-add">${icon("plus")}Добавить прокси</button></div>`);
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
      <span class="ptype k-${esc(p.type || "socks5")}" title="${esc(proxyTypeLabel(p.type))}">${icon(typeIconName(p.type), 16)}</span>
      <div class="stack"><span class="main">${esc(p.name)}</span><span class="sub">${esc(proxyTypeLabel(p.type) + " · " + proxySub(p))}</span></div>
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
function appIconHTML(process, style) {
  const letter = esc((appLabel(process) || "?").slice(0, 1).toUpperCase());
  const path = String(process || "");
  const st = style ? ` style="${style}"` : "";
  // Names and masks are resolved to an exe by the server; 404 keeps the letter.
  if (DEMO || !path.trim()) return `<span class="appicon"${st}>${letter}</span>`;
  // Names without an icon are remembered, so a redraw does not ask again.
  if (iconMisses.has(path.toLowerCase())) return `<span class="appicon"${st}>${letter}</span>`;
  const src = "/api/icon?path=" + encodeURIComponent(path) + "&t=" + encodeURIComponent(TOKEN);
  return `<span class="appicon"${st}><img alt="" src="${esc(src)}" data-key="${esc(path.toLowerCase())}" onload="this.parentNode.classList.add('hasimg')" onerror="iconMiss(this)">${letter}</span>`;
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
    <td><span class="tag${e.proto === "UDP" ? " udp" : ""}">${esc(e.proto || "")}</span></td>
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
function table(head, rows, empty) {
  if (!rows.length) return `<div class="table"><div class="empty">${esc(empty || "")}</div></div>`;
  return `<table class="table"><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

function render() {
  if (!state) return;
  if (page === "tray") {
    document.getElementById("app").hidden = true;
    const tray = document.getElementById("tray");
    tray.hidden = false;
    if (tray.dataset.built !== "1") { tray.innerHTML = trayHTML(); tray.dataset.built = "1"; }
    document.getElementById("modal").innerHTML = "";
    return;
  }
  document.getElementById("app").hidden = false;
  document.getElementById("tray").hidden = true;
  paintChrome();
  const host = document.getElementById("page");
  if (built !== page) {
    host.innerHTML = pageHTML();
    host.dataset.page = page;
    built = page;
  }
  if (!modal && !dragging) fillPage();
  renderModal();
  if (state.error) showToast(state.error);
}

function renderModal() {
  const root = document.getElementById("modal");
  if (!modal) { root.innerHTML = ""; return; }
  if (modal.kind === "proxy") root.innerHTML = proxyDialog();
  else if (AP_MODALS[modal.kind]) root.innerHTML = AP_MODALS[modal.kind]();
  else if (modal.kind === "confirm" || modal.kind === "alert") root.innerHTML = confirmDialog();
}
function confirmDialog() {
  const alert = modal.kind === "alert";
  const okCls = modal.danger ? "btn danger" : "btn pri";
  const buttons = alert
    ? `<button class="btn pri" type="submit">Понятно</button>`
    : `<button class="${okCls}" type="submit">${esc(modal.ok || "Удалить")}</button><button class="btn" type="button" data-act="cancel">Отмена</button>`;
  return `<div class="scrim"><form class="dialog narrow" id="dlg"><h2>${esc(modal.title || "")}</h2>
    <div class="body"><p class="confirm-text">${esc(modal.text || "")}</p></div>
    <div class="footer">${buttons}</div></form></div>`;
}

function proxyTypeLabel(t) {
  if (t === "http") return "HTTP";
  if (t === "vless") return "VLESS";
  return "SOCKS5";
}
function proxyDialog() {
  const p = modal.draft;
  const type = p.type || "socks5";
  const types = [["socks5", "SOCKS5"], ["http", "HTTP"], ["vless", "VLESS"]];
  const vless = type === "vless";
  return `<div class="scrim"><form class="dialog${vless ? "" : " narrow"}" id="dlg">
    <h2>Прокси</h2><div class="dsub">${modal.index < 0 ? "Новый прокси" : "Изменение · " + esc(p.name || "")}</div>
    <div class="body">
      <label class="lbl">Имя</label><div class="field"><input id="p-name" value="${esc(p.name || "")}" autofocus></div>
      <div style="height:14px"></div><label class="lbl">Тип</label>
      <div class="seg">${types.map(([v, n]) => `<button type="button" data-act="ptype" data-value="${v}" class="${type === v ? "on" : ""}">${n}</button>`).join("")}</div>
      ${vless ? vlessFields(p) : socksFields(p)}
      <div class="checkline"><button class="btn sm" type="button" data-act="probe-draft">${icon("refresh")}Проверить</button><span id="probe-out">${modal.checking ? badge("проверка…", "neu", true) : (modal.report ? probeBadge(modal.report, type) : "")}</span></div>
      ${modal.realityError ? `<div class="field-err">${esc(modal.realityError)}</div>` : ""}
    </div>
    <div class="footer"><button class="btn pri" type="submit">${modal.index < 0 ? "Добавить" : "Сохранить"}</button><button class="btn" type="button" data-act="cancel">Отмена</button></div>
  </form></div>`;
}
function socksFields(p) {
  return `<div style="height:14px"></div><label class="lbl">Адрес</label><div class="field"><input class="mono" id="p-addr" value="${esc(p.address || "")}" placeholder="127.0.0.1:1080"></div>
      <div class="help">хост:порт, например 127.0.0.1:1080</div>
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
  const port = p.socksPort ? String(p.socksPort) : "";
  return `<div class="socks-box">
      <label class="lbl">Локальный SOCKS5-порт</label>
      <div class="field${modal.portError ? " bad" : ""}"><input class="mono" id="p-socks" inputmode="numeric" placeholder="10808" value="${esc(port)}"></div>
      ${modal.portError ? `<div class="field-err">${esc(modal.portError)}</div>` : ""}
      <div class="help">Пусто — случайный порт только для правил Ashgate. Число, например 10808 — обычный SOCKS5 на 127.0.0.1 для Dolphin и других программ. Слушает, пока открыто окно или работает служба, без «Старт». Следующий порт — HTTP. Только 127.0.0.1, в локальную сеть не открывается.</div>
      <div class="grid" style="margin-top:10px">
        <div><label class="lbl">Логин SOCKS5</label><div class="field"><input id="p-luser" value="${esc(p.localUser || "")}" placeholder="необязательно"></div></div>
        <div><label class="lbl">Пароль</label><div class="field"><input id="p-lpass" type="password" value="${esc(p.localPass || "")}" placeholder="необязательно"></div></div>
      </div>
      ${socksPreviewHTML(p)}
    </div>`;
}
function socksPreviewHTML(p) {
  const port = Number(p.socksPort) || 0;
  if (!port || port < 1 || port > 65535) return `<div id="socks-preview"></div>`;
  const socks = "127.0.0.1:" + port;
  const http = port < 65535 ? "127.0.0.1:" + (port + 1) : "";
  const live = (state && state.bridges && state.bridges[p.name]) || {};
  let mark = "wait";
  let text = "откроется после сохранения";
  if (live.up && live.socks === socks) { mark = "ok"; text = "слушает"; }
  else if (live.error) { mark = "bad"; text = live.error; }
  const httpRow = http ? `<div class="row"><span class="addr">${esc(http)}</span><button class="btn sm" type="button" data-act="copy-text" data-text="${esc(http)}">Копировать</button><span class="sub">HTTP</span></div>` : "";
  return `<div id="socks-preview" class="socks-pub">
      <div class="row"><span class="addr">${esc(socks)}</span><button class="btn sm" type="button" data-act="copy-text" data-text="${esc(socks)}">Копировать</button><span class="sockline"><i class="${mark}"></i><span class="sub">${esc(text)}</span></span></div>
      ${httpRow}
    </div>`;
}
function proxyAddrText(p) {
  if (p.type === "vless" && p.socksPort) return "127.0.0.1:" + p.socksPort;
  return p.address || "";
}
function proxyAddrCell(p) {
  if (p.type === "vless" && p.socksPort) {
    const socks = "127.0.0.1:" + p.socksPort;
    const live = (state && state.bridges && state.bridges[p.name]) || {};
    let mark = "wait";
    let text = "не запущен";
    if (live.up && live.socks === socks) { mark = "ok"; text = "слушает"; }
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
  if (p.type === "vless" && p.vless) {
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
async function copyText(text) {
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
  showToast("Скопировано: " + text);
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
function rulesJSON() {
  return JSON.stringify(cfg().rules || []);
}
function rememberRules() {
  rulesSnapshot = rulesJSON();
  rulesDirty = false;
  renderDirty();
}
function unsavedLabel(n) {
  const m10 = n % 10;
  const m100 = n % 100;
  let word = "несохранённых изменений";
  if (m10 === 1 && m100 !== 11) word = "несохранённое изменение";
  else if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) word = "несохранённых изменения";
  return n + " " + word;
}
function dirtyHint() {
  let prev = [];
  try { prev = JSON.parse(rulesSnapshot || "[]"); } catch (e) { prev = []; }
  const cur = cfg().rules || [];
  const bits = [];
  if (prev.map((r) => r.process).join("|") !== cur.map((r) => r.process).join("|")) bits.push("порядок изменён");
  cur.forEach((r) => {
    const was = prev.find((p) => p.process === r.process);
    if (was && (was.enabled === false) !== (r.enabled === false)) bits.push((r.enabled === false ? "выключено " : "включено ") + appLabel(r.process));
  });
  const had = new Set(prev.map((r) => r.process));
  cur.forEach((r) => { if (!had.has(r.process)) bits.push("добавлено " + appLabel(r.process)); });
  prev.forEach((r) => { if (!cur.some((c) => c.process === r.process)) bits.push("убрано " + appLabel(r.process)); });
  return bits.slice(0, 3).join(", ") || "Есть несохранённые правки";
}
function renderDirty() {
  const bar = document.getElementById("dirtybar");
  if (!bar) return;
  if (page !== "rules" || !rulesDirty) { bar.hidden = true; return; }
  let n = 1;
  try {
    const prev = JSON.parse(rulesSnapshot || "[]");
    n = Math.max(1, Math.abs((cfg().rules || []).length - prev.length) || 1);
    const changed = (cfg().rules || []).filter((r, i) => JSON.stringify(r) !== JSON.stringify(prev[i])).length;
    if (changed) n = changed;
  } catch (e) { /* keep 1 */ }
  bar.hidden = false;
  setHTML(bar, `<div><div class="t">${esc(unsavedLabel(n))}</div><div class="d">${esc(dirtyHint())} · Ctrl+S</div></div><div class="actions"><button class="btn" type="button" data-act="rules-revert">Отменить</button><button class="btn pri" type="button" data-act="rules-save">Сохранить</button></div>`);
}
let reqSeq = 0;
let shownSeq = 0;
async function refresh() {
  if (DEMO) { render(); return; }
  const seq = ++reqSeq;
  try {
    // With the last generation the server skips the event list when no
    // connection was logged since.
    const gen = state && state.events ? state.generation || 0 : 0;
    const r = await apiFetch("/api/state?gen=" + gen);
    if (!r.ok) return;
    const next = await r.json();
    // Requests can overlap (poll plus a save); never show an older answer
    // over a newer one.
    if (seq < shownSeq) return;
    shownSeq = seq;
    if (next.eventsSame) next.events = (state && state.events) || [];
    const err = next.error;
    next.error = "";
    // While an Apps-tab save is in flight, keep the local rules and groups:
    // this answer may predate it.
    const keep = (rulesDirty || apSaving > 0) && state ? cfg().rules : null;
    const keepGroups = apSaving > 0 && state ? cfg().groups : undefined;
    state = next;
    if (keep) state.config.rules = keep;
    if (keepGroups !== undefined) state.config.groups = keepGroups;
    else rememberRules();
    if (!paused) frozen = null;
    render();
    if (next.notice && err && err !== lastErr) showToast(next.notice + "\n" + err);
    else if (next.notice) showToast(next.notice);
    else if (err && err !== lastErr) showToast(err);
    lastErr = err || "";
    noteBridge();
  } catch (e) { /* keep the last frame */ }
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
function noteBridge() {
  const note = bridgeNote();
  if (!note) {
    lastBridge = "";
    return;
  }
  if (note === lastBridge || modal) return;
  lastBridge = note;
  showAlert(/занят/.test(note) ? "Порт занят" : "Локальный мост VLESS", note);
}
async function saveConfig(extra) {
  extra = extra || {};
  const bodyCfg = JSON.parse(JSON.stringify(cfg()));
  if (rulesDirty && !extra.rules && rulesSnapshot) {
    try { bodyCfg.rules = JSON.parse(rulesSnapshot); } catch (e) { /* send current */ }
  }
  const body = { config: bodyCfg };
  if ("autostart" in extra) body.autostart = extra.autostart;
  if (DEMO) {
    if (extra.rules) rememberRules();
    showToast("Демонстрация: сохранение выключено");
    return;
  }
  const dirtyRules = rulesDirty && !extra.rules ? cfg().rules : null;
  await post("/api/config", body);
  if (!extra.quiet) showToast("Сохранено");
  await refresh();
  if (dirtyRules && state) {
    state.config.rules = dirtyRules;
    rulesDirty = true;
    render();
  } else if (extra.rules) rememberRules();
}
function showToast(text) {
  if (text && /порт/i.test(text) && /занят/i.test(text)) {
    showAlert("Порт занят", text);
    return;
  }
  const t = document.getElementById("toast");
  t.hidden = false;
  t.textContent = text;
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => { t.hidden = true; }, 3200);
}
function closeMenu() { document.getElementById("menu").hidden = true; }
function openMenu(x, y, items) {
  const m = document.getElementById("menu");
  m.innerHTML = items.map((it) => `<button type="button" class="${it.danger ? "danger" : ""}" data-menu="${it.id}">${esc(it.label)}</button>`).join("");
  m.hidden = false;
  m.style.left = Math.min(x, window.innerWidth - 200) + "px";
  m.style.top = Math.min(y, window.innerHeight - 40 * items.length) + "px";
  m.onclick = (e) => {
    const b = e.target.closest("[data-menu]");
    if (!b) return;
    closeMenu();
    items.find((it) => it.id === b.dataset.menu).run();
  };
}
function showTip(text, x, y) {
  hideTip();
  tipEl = document.createElement("div");
  tipEl.className = "tip";
  tipEl.innerHTML = `<b>Ошибка</b><span>${esc(text)}</span>`;
  document.body.appendChild(tipEl);
  tipEl.style.left = Math.min(x, window.innerWidth - 340) + "px";
  tipEl.style.top = (y + 12) + "px";
}
function hideTip() { if (tipEl) { tipEl.remove(); tipEl = null; } }

function openProxy(index) {
  const src = index >= 0 ? cfg().proxies[index] : { name: "", type: "socks5", address: "", username: "", password: "" };
  const draft = JSON.parse(JSON.stringify(src));
  modal = { kind: "proxy", index, draft, showPass: false, report: null, parsedLink: draft.link || "", parseError: "" };
  renderModal();
}
function readProxyDraft() {
  if (!modal || !document.getElementById("p-name")) return;
  modal.draft.name = document.getElementById("p-name").value.trim();
  const addr = document.getElementById("p-addr");
  if (addr) modal.draft.address = addr.value.trim();
  const link = document.getElementById("p-link");
  if (link) modal.draft.link = link.value.trim();
  const user = document.getElementById("p-user");
  if (user) modal.draft.username = user.value;
  const pass = document.getElementById("p-pass");
  if (pass) modal.draft.password = pass.value;
  const socks = document.getElementById("p-socks");
  if (socks) {
    const raw = socks.value.trim();
    if (!raw) modal.draft.socksPort = 0;
    else if (/^\d+$/.test(raw)) modal.draft.socksPort = Number(raw);
    else modal.draft.socksPort = -1;
  }
  const luser = document.getElementById("p-luser");
  if (luser) modal.draft.localUser = luser.value.trim();
  const lpass = document.getElementById("p-lpass");
  if (lpass) modal.draft.localPass = lpass.value;
  if (modal.draft.type === "vless") readVLESSFields();
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
function applyParsed(draft, parsed) {
  draft.address = parsed.address || draft.address;
  draft.vless = parsed.vless || {};
  if (!draft.name && parsed.name) draft.name = parsed.name;
}
async function ensureVLESS(draft) {
  const link = (draft.link || "").trim();
  const stale = link && link !== modal.parsedLink;
  if (!stale && draft.vless && draft.vless.uuid) return;
  if (!link) throw new Error("Вставьте ссылку VLESS");
  const parsed = await parseVLESS(link);
  applyParsed(draft, parsed);
  modal.parsedLink = link;
  modal.parseError = "";
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
  if (!vless.fp && (security === "reality" || security === "tls")) vless.fp = "chrome";
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
function suggestNameJS(fragment) {
  let s = "";
  for (const ch of String(fragment || "").trim()) {
    if (/[A-Za-z0-9]/.test(ch)) s += ch;
    else if (ch === "_" || ch === "." || ch === "-") s += ch;
    else if (ch === " " || ch === "+" || ch === "/") s += "-";
  }
  s = s.replace(/^[-_.]+|[-_.]+$/g, "").replace(/--+/g, "-");
  if (s.length > 64) s = s.slice(0, 64).replace(/[-_.]+$/g, "");
  return s;
}
async function commitProxy() {
  readProxyDraft();
  const p = modal.draft;
  if (p.type === "vless") {
    try { await ensureVLESS(p); } catch (e) { modal.parseError = linkFail(e.message); renderModal(); return; }
    if (p.socksPort < 0 || p.socksPort > 65535) { showToast("Локальный SOCKS5-порт: число от 1 до 65535 или пусто"); return; }
    delete p.username;
    delete p.password;
    if (!p.socksPort) delete p.socksPort;
    if (!p.localUser) delete p.localUser;
    if (!p.localPass) delete p.localPass;
    if (DEMO) {
      state.bridges = state.bridges || {};
      if (p.socksPort) state.bridges[p.name] = { socks: "127.0.0.1:" + p.socksPort, http: p.socksPort < 65535 ? "127.0.0.1:" + (p.socksPort + 1) : "", up: true };
      else delete state.bridges[p.name];
    }
  } else {
    delete p.link;
    delete p.vless;
    delete p.socksPort;
    delete p.localUser;
    delete p.localPass;
  }
  if (!p.name || !p.address) { showToast("Укажите имя и адрес"); return; }
  const list = cfg().proxies;
  if (modal.index < 0) list.push(p);
  else list[modal.index] = p;
  const done = modal;
  modal = null;
  built = "";
  render();
  saveConfig().then(() => { sel.proxy = done.index < 0 ? list.length - 1 : done.index; }).catch((e) => {
    const msg = e.message || "";
    modal = done;
    if (/порт/i.test(msg)) modal.portError = /занят|совпадает/i.test(msg) ? "Порт занят. " + msg : msg;
    else if (/разобрать ссылку/i.test(msg)) modal.parseError = linkFail(msg);
    else showToast(msg);
    renderModal();
  });
}
function linkFail(msg) {
  const rest = String(msg || "").replace(/^Не удалось разобрать ссылку VLESS:?\s*/i, "").trim();
  if (!rest || rest === String(msg || "").trim()) return "Ссылка не разобрана";
  return "Ссылка не разобрана. " + rest;
}
function proxyInUse(name) {
  return (cfg().rules || []).some((r) => r.proxy === name) || (cfg().groups || []).some((g) => g.proxy === name) ||
    (cfg().dns.includeSystemResolver && cfg().dns.systemResolverProxy === name);
}
// dnsServer adds the default port to a bare IP: "1.1.1.1" -> "1.1.1.1:53".
function dnsServer(s) {
  s = String(s || "").trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return s + ":53";
  if (/^[0-9a-f]*:[0-9a-f:]*:[0-9a-f]*$/i.test(s) && !s.startsWith("[")) return "[" + s + "]:53";
  return s;
}
function readSettings() {
  const c = cfg();
  c.dns = c.dns || {};
  c.dns.mode = document.querySelector('[data-key="dns"]').classList.contains("on") ? "proxy" : "original";
  const dnsInput = document.getElementById("dns-servers");
  c.dns.servers = dnsInput.value.split(/[,\s]+/).map(dnsServer).filter(Boolean);
  if (c.dns.servers.length) dnsInput.value = c.dns.servers.join(", ");
  c.dns.includeSystemResolver = document.querySelector('[data-key="sys"]').classList.contains("on");
  const sp = document.getElementById("sys-proxy");
  c.dns.systemResolverProxy = sp ? sp.value : "";
  const udp = document.querySelector('[data-key="udp"].on');
  c.udpUnsupported = udp ? udp.dataset.value : "block";
  c.bypassPrivate = document.querySelector('[data-key="bypass"]').classList.contains("on");
  c.killSwitch = document.querySelector('[data-key="kill"]').classList.contains("on");
  c.log = c.log || {};
  c.log.level = document.querySelector('[data-key="verbose"]').classList.contains("on") ? "debug" : "info";
  const auto = document.querySelector('[data-key="auto"]').classList.contains("on");
  return auto;
}

function onClick(e) {
  const nav = e.target.closest("[data-nav]");
  if (nav) { page = nav.dataset.nav; built = ""; modal = null; closeMenu(); render(); return; }
  const act = e.target.closest("[data-act]");
  if (!act) return;
  const id = act.dataset.act;
  const i = Number(act.dataset.i);
  if (id === "copy-text") { copyText(act.dataset.text || ""); return; }
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
  if (id === "rules-save") { saveConfig({ rules: true }).catch((err) => showToast(err.message)); return; }
  if (id === "rules-revert") {
    try { cfg().rules = JSON.parse(rulesSnapshot || "[]"); } catch (err) { /* keep */ }
    rulesDirty = false;
    built = "";
    render();
    return;
  }
  if (id === "errors-only") {
    errorsOnly = !errorsOnly;
    built = "";
    render();
    return;
  }
  if (id === "open-folder") {
    if (DEMO) { showToast(state.path || ""); return; }
    post("/api/reveal").catch((err) => showToast(err.message));
    return;
  }
  if (id === "proxy-add") return openProxy(-1);
  if (id === "proxy-edit") return openProxy(i);
  if (id === "proxy-del") return deleteProxy(i);
  if (id === "menu-proxy") {
    const name = cfg().proxies[i].name;
    openMenu(e.clientX, e.clientY, [
      { id: "edit", label: "Изменить", run: () => openProxy(i) },
      { id: "probe", label: "Проверить", run: () => probeNamed(name) },
      { id: "del", label: "Удалить", danger: true, run: () => deleteProxy(i) },
    ]);
    return;
  }
  if (id === "probe-all") {
    (cfg().proxies || []).forEach((p) => { probing[p.name] = true; });
    fillProxies();
    if (DEMO) {
      setTimeout(() => { probing = {}; fillProxies(); }, 600);
      return;
    }
    post("/api/probe-all").then((checks) => {
      probing = {};
      if (state && checks) state.checks = checks;
      fillProxies();
    }).catch((err) => { probing = {}; fillProxies(); showToast(err.message); });
    return;
  }
  if (id === "head-more") {
    const actions = [...document.querySelectorAll(".head-actions .btn.secondary")].map((b) => ({
      id: b.dataset.act,
      label: b.textContent.trim(),
      run: () => b.click(),
    }));
    if (actions.length) openMenu(e.clientX, e.clientY, actions);
    return;
  }
  if (id === "save" || id === "save-settings" || id === "rules-save-legacy") {
    saveConfig({ rules: page === "rules" }).catch((err) => showToast(err.message));
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
    readProxyDraft();
    modal.draft.type = act.dataset.value;
    modal.report = null;
    modal.parseError = "";
    renderModal();
    return;
  }
  if (id === "parse-link") {
    readProxyDraft();
    parseVLESS(modal.draft.link).then((parsed) => {
      applyParsed(modal.draft, parsed);
      modal.parsedLink = (modal.draft.link || "").trim();
      modal.parseError = "";
      renderModal();
    }).catch((err) => { modal.parseError = linkFail(err.message); renderModal(); });
    return;
  }
  if (id === "probe-draft") {
    readProxyDraft();
    if (DEMO) { modal.report = { ok: true, udp: modal.draft.type !== "http", label: "42 мс" }; renderModal(); return; }
    const run = () => {
      modal.checking = true;
      modal.report = null;
      renderModal();
      post("/api/probe", { proxy: modal.draft }).then((rep) => {
        if (!modal) return;
        modal.checking = false;
        modal.report = rep;
        modal.realityError = realityFail(modal.draft, rep);
        renderModal();
      }).catch((err) => {
        if (modal) { modal.checking = false; renderModal(); }
        showToast(err.message);
      });
    };
    if (modal.draft.type === "vless") {
      ensureVLESS(modal.draft).then(run).catch((err) => showToast(err.message));
    } else run();
    return;
  }
}
function probeNamed(name) {
  probing[name] = true;
  if (page === "proxies") fillProxies();
  if (DEMO) { setTimeout(() => { delete probing[name]; fillProxies(); }, 600); return; }
  post("/api/probe", { name }).then((rep) => {
    delete probing[name];
    if (state) { state.checks = state.checks || {}; state.checks[name] = rep; }
    fillProxies();
  }).catch((err) => { delete probing[name]; fillProxies(); showToast(err.message); });
}
let settingsAuto = false;
function queueSettings(autoTouched) {
  if (autoTouched) settingsAuto = true;
  clearTimeout(settingsTimer);
  settingsTimer = setTimeout(() => {
    if (page !== "settings") return;
    if (!document.querySelector('[data-key="dns"]')) return;
    const sendAuto = settingsAuto;
    settingsAuto = false;
    const auto = readSettings();
    const extra = { quiet: true };
    if (sendAuto) extra.autostart = auto;
    saveConfig(extra).catch((err) => showToast(err.message));
  }, 400);
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
  modal.draft.type = "vless";
  modal.draft.link = text;
  renderModal();
  parseVLESS(text).then((parsed) => {
    if (!modal) return;
    applyParsed(modal.draft, parsed);
    modal.parsedLink = text;
    modal.parseError = "";
    renderModal();
  }).catch((err) => {
    if (!modal) return;
    modal.parseError = linkFail(err.message);
    renderModal();
  });
}
function showStartError(msg) {
  const text = String(msg || "").trim();
  if (/[А-Яа-яЁё]/.test(text)) {
    showAlert("Перехват не запустился", text);
    return;
  }
  if (/access is denied/i.test(text)) {
    showAlert("Перехват не запустился", "Нет прав администратора или перехват уже занят другой копией Ashgate/другой программой (Proxifier, zapret/winws, GoodbyeDPI). Закройте их и запустите Ashgate от имени администратора.");
    return;
  }
  const m = /код\s+(\d+)/.exec(text);
  const code = m ? Number(m[1]) : 0;
  const help = {
    5: "Нет прав администратора или перехват уже занят другой копией Ashgate/другой программой (Proxifier, zapret/winws, GoodbyeDPI). Закройте их и запустите Ashgate от имени администратора. (код 5)",
    2: "Рядом с программой нет WinDivert.dll или WinDivert64.sys (код 2). Положите их в ту же папку, что и ashgate.exe.",
    577: "Windows отклонила подпись драйвера (код 577). Попробуйте другой вариант WinDivert — A, B или C.",
    1275: "Драйвер заблокирован политикой Windows или антивирусом (код 1275). Разрешите WinDivert64.sys или отключите блокировку уязвимых драйверов.",
    654: "Уже загружен несовместимый драйвер WinDivert (код 654). Перезагрузите компьютер и запустите Ashgate снова.",
    1753: "Служба базовой фильтрации Windows выключена (код 1753). Включите Base Filtering Engine и повторите запуск.",
  };
  showAlert("Перехват не запустился", help[code] || (msg || "Не удалось запустить перехват."));
}
function startStop() {
  const path = state.running ? "/api/stop" : "/api/start";
  if (DEMO) {
    state.running = !state.running;
    state.driver = state.running;
    render();
    return;
  }
  const starting = !state.running;
  post(path).then(refresh).catch((err) => {
    if (starting) showStartError(err.message);
    else showToast(err.message);
  });
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
  if (modal && modal.kind === "proxy") commitProxy();
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
    if (e.target.id === "p-socks" && modal && modal.draft && modal.draft.type === "vless") {
      readProxyDraft();
      const box = document.getElementById("socks-preview");
      if (box) box.outerHTML = socksPreviewHTML(modal.draft);
    }
    if (e.target.id === "log-filter") { logFilter = e.target.value; fillLog(); }
  });
  // Text and select settings save when the user finishes editing, not on
  // every keystroke: a half-typed DNS address used to pop an error.
  document.body.addEventListener("change", (e) => {
    if (page === "settings" && e.target.closest(".page") && (e.target.id === "dns-servers" || e.target.id === "sys-proxy")) queueSettings();
  });
  document.body.addEventListener("mouseover", (e) => {
    const n = e.target.closest("[data-err]");
    if (n) showTip(n.dataset.err, e.clientX, e.clientY);
    const el = e.target.closest("td, .nm, .sub, .addr, .main");
    if (el && !el.title && !el.querySelector("button") && el.scrollWidth > el.clientWidth) {
      const text = el.textContent.replace(/\s+/g, " ").trim();
      if (text) el.title = text;
    }
  });
  document.body.addEventListener("mouseout", (e) => {
    if (e.target.closest("[data-err]")) hideTip();
  });
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === "s" || e.key === "S")) {
      if (rulesDirty) {
        e.preventDefault();
        saveConfig({ rules: true }).catch((err) => showToast(err.message));
      }
    }
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
    rememberRules();
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
  clipboardTried = true;
  poll();
  document.addEventListener("visibilitychange", () => { if (!document.hidden && !modal) refresh(); });
}
// poll waits for each answer before asking again, so slow replies cannot
// pile up, and slows down while the window is hidden in the tray.
// poll waits for each answer before asking again. The live log needs
// 250 ms; the other pages show figures that change once a second; in the
// tray (the host reports it: WebView2 does not set document.hidden) or
// minimized the page only needs to notice state changes.
async function poll() {
  if (!modal) await refresh();
  let wait = 1000;
  if (document.hidden || (state && state.hidden)) wait = 3000;
  else if (page === "log" && !paused) wait = 250;
  setTimeout(poll, wait);
}
main();
