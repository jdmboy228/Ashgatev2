// Apps tab ("Приложения"): rules and rule groups, live per-app traffic,
// add / from-windows / edit / group dialogs. Loaded before app.js; it uses
// app.js globals (state, modal, cfg, esc, icon, …) only when called.
// Every change is saved at once, like the design it follows.

const AP_GROUP_PRESETS = ["Связь и звонки", "Мессенджеры", "Рабочие инструменты", "Браузеры", "Игры"];
let apQuery = "";
let apSelected = new Set(); // rule indices chosen for grouping
let apOpen = ""; // open popover: "route:r3", "menu:r3", "route:g:Name", "menu:g:Name"
let apDrag = null; // unit key being dragged
let apSaveChain = Promise.resolve();
// apTele holds each row's live telemetry markup. Rows carry an empty cell
// that is filled in place, so traffic updating every second does not
// rebuild the list (that used to swallow clicks).
let apTele = {};
let apSaving = 0;

function apGroups() {
  const c = cfg();
  if (!Array.isArray(c.groups)) c.groups = [];
  return c.groups;
}
function apGroup(name) {
  return apGroups().find((g) => g.name === name);
}
function apKey(process) {
  return String(process || "").trim().replace(/^"+|"+$/g, "").toLowerCase();
}
function apLabel(process) {
  const base = baseName(String(process || "").replace(/^"+|"+$/g, ""));
  return base.replace(/\.exe$/i, "").replace(/\*/g, "…") || String(process || "");
}
function apGlobalKS() {
  return !!cfg().killSwitch;
}
function apRuleKS(r) {
  return r.killSwitch === undefined || r.killSwitch === null ? apGlobalKS() : !!r.killSwitch;
}
function apOn(v) {
  return v !== false;
}
// Effective route and switch of a rule: its group's when it has one.
function apEffective(r) {
  const g = r.group ? apGroup(r.group) : null;
  return {
    enabled: apOn(r.enabled) && (!g || apOn(g.enabled)),
    action: g ? g.action : r.action,
    proxy: g ? g.proxy || "" : r.proxy || "",
  };
}

// Units are what the list shows and moves: a standalone rule or a whole
// group, in config order. A group sits where its first rule is.
function apUnits() {
  const rules = cfg().rules || [];
  const units = [];
  const seen = new Set();
  rules.forEach((r, i) => {
    if (r.group && apGroup(r.group)) {
      if (seen.has(r.group)) return;
      seen.add(r.group);
      units.push({ key: "g:" + r.group, group: apGroup(r.group), members: rules.map((x, j) => (x.group === r.group ? j : -1)).filter((j) => j >= 0) });
    } else units.push({ key: "r:" + i, index: i });
  });
  return units;
}
// apFlatten rewrites cfg().rules from units, keeping group members together.
function apFlatten(units) {
  const rules = cfg().rules;
  const out = [];
  units.forEach((u) => {
    if (u.group) u.members.forEach((j) => out.push(rules[j]));
    else out.push(rules[u.index]);
  });
  cfg().rules = out;
}

// apPruneGroups drops groups that no rule belongs to any more. An empty
// group is invisible but would still hold its name.
function apPruneGroups() {
  const used = new Set((cfg().rules || []).map((r) => r.group).filter(Boolean));
  cfg().groups = apGroups().filter((g) => used.has(g.name));
}

function apSave(message) {
  apPruneGroups();
  if (DEMO) { if (message) showToast(message); render(); return Promise.resolve(); }
  apSaving++;
  render();
  apSaveChain = apSaveChain.then(() => saveConfig({ rules: true, quiet: true }))
    .then(() => { if (message) showToast(message); })
    .catch((err) => { showToast(err.message); return refresh(); })
    .finally(() => { apSaving--; });
  return apSaveChain;
}

// ---------- routes ----------

function apRoutes() {
  const list = (cfg().proxies || []).map((p) => ({ action: "proxy", proxy: p.name, p }));
  list.push({ action: "direct", proxy: "" }, { action: "block", proxy: "" });
  return list;
}
function apRouteIcon(action, p) {
  if (action === "direct") return icon("globe", 16);
  if (action === "block") return icon("ban", 16);
  const t = p && p.type;
  if (t === "vless") return icon("vless", 16);
  return icon(t === "http" ? "http" : "socks", 16);
}
function apRouteKind(action, p) {
  if (action === "direct") return "direct";
  if (action === "block") return "block";
  return (p && p.type) || "socks5";
}
function apRouteText(action, proxy) {
  if (action === "direct") return { kind: "Напрямую", name: "" };
  if (action === "block") return { kind: "Блокировать", name: "" };
  const p = (cfg().proxies || []).find((x) => x.name === proxy);
  return { kind: p ? proxyTypeLabel(p.type) : "Прокси", name: proxy || "не выбран" };
}
// apRouteBadge is the route dropdown: type icon, proxy name (or «Напрямую»,
// «Блокировать»), chevron. Type and endpoint are in the tooltip.
function apRouteBadge(target, action, proxy, bad) {
  const p = (cfg().proxies || []).find((x) => x.name === proxy);
  const t = apRouteText(action, proxy);
  const ep = action === "proxy" ? (p ? proxyAddrText(p) : "не выбран") : "";
  const open = apOpen === "route:" + target;
  const label = action === "proxy" ? (proxy || "не выбран") : t.kind;
  const tip = action === "proxy" ? `${proxy} · ${t.kind} · ${ep}` : t.kind;
  return `<div class="ap-pop-wrap"><button class="ap-route k-${apRouteKind(action, p)}${bad ? " bad" : ""}" type="button" data-act="ap-route" data-target="${esc(target)}" title="${esc(tip)}">${apRouteIcon(action, p)}<b>${esc(label)}</b>${icon("chev", 12)}</button>${open ? apRoutePopover(target, action, proxy) : ""}</div>`;
}
function apRoutePopover(target, action, proxy) {
  const items = apRoutes().map((r) => {
    const on = r.action === action && (r.action !== "proxy" || r.proxy === proxy);
    let side = "";
    if (r.p) {
      const v = probeView(r.p);
      side = v.kind === "err" ? `<span class="st err">Offline</span>` : v.kind === "neu" ? "" : `<span class="st ok">${esc(v.label)}</span>`;
    }
    const t = apRouteText(r.action, r.proxy);
    const name = r.p ? r.proxy : t.kind;
    const sub = r.p ? `${proxyTypeLabel(r.p.type)} · ${proxyAddrText(r.p)}` : r.action === "direct" ? "без прокси" : "трафик отбрасывается";
    return `<button type="button" class="${on ? "on" : ""}" data-act="ap-route-set" data-target="${esc(target)}" data-action="${r.action}" data-proxy="${esc(r.proxy)}"><span class="ri k-${apRouteKind(r.action, r.p)}">${apRouteIcon(r.action, r.p)}</span><span class="txt"><span class="nm">${esc(name)}</span><span class="sub">${esc(sub)}</span></span><span class="end">${side}${on ? icon("check", 14) : ""}</span></button>`;
  }).join("");
  const title = target.startsWith("g:") ? "Назначить прокси группе" : "Назначить прокси";
  return `<div class="ap-pop route"><div class="cap">${title}</div>${items}${(cfg().proxies || []).length ? "" : `<button type="button" data-act="goto" data-page="proxies"><span class="ri">${icon("plus", 14)}</span><span class="txt"><span class="nm">Добавить прокси</span></span></button>`}</div>`;
}

// ---------- telemetry ----------

function apStat(r) {
  return (state.ruleStats || {})[apKey(r.process)] || null;
}
function apRate(n) {
  // "132,0 КБ" -> "132 КБ": the rate column stays narrow.
  return bytes(n || 0).replace(/,0 /, " ") + "/с";
}
// apStatus describes a rule's state for its dot, badge and telemetry.
function apStatus(r) {
  const eff = apEffective(r);
  const st = apStat(r);
  const ks = apRuleKS(r);
  if (!eff.enabled) return { dot: "off", line: "Отключено · —", sub: "Трафик идёт напрямую, мимо правила" };
  if (eff.action === "direct") return { dot: "info", line: "Напрямую", sub: "Без прокси, по правилу" };
  if (eff.action === "block") return { dot: "warn", line: "Блокируется", sub: "Трафик приложения отбрасывается" };
  if (!state.running) {
    return ks
      ? { dot: "warn", line: "Перехват выключен", sub: "Kill switch: приложение без сети" }
      : { dot: "off", line: "Перехват выключен", sub: "Сейчас идёт напрямую" };
  }
  if (st && st.error && !st.flows) {
    return {
      dot: "err", bad: true, badge: ks ? "Трафик заблокирован" : "Ошибка прокси",
      line: "0 потоков · " + st.error, sub: ks ? "Kill switch: напрямую не выпущено" : "Соединения не устанавливаются",
      error: st.error,
    };
  }
  if (st && st.flows) {
    return { dot: "ok", flows: st.flows, down: st.downRate, up: st.upRate, sub: bytes((st.up || 0) + (st.down || 0)) };
  }
  return { dot: "ok idle", line: "Нет соединений", sub: st && (st.up || st.down) ? bytes(st.up + st.down) + " за сессию" : "Ждёт подключений приложения" };
}
function apTelemetry(s) {
  if (s.flows) {
    return `<div class="l1"><span class="dn">↓ ${esc(apRate(s.down))}</span><span class="dim">·</span><span class="up">↑ ${esc(apRate(s.up))}</span></div><div class="l2">${s.flows} ${flowWord(s.flows)} · ${esc(s.sub)}</div>`;
  }
  return `<div class="l1${s.bad ? " bad" : ""}" title="${esc(s.error || s.line)}">${esc(s.line)}</div><div class="l2">${esc(s.sub)}</div>`;
}
function flowWord(n) {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return "поток";
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return "потока";
  return "потоков";
}

// ---------- page ----------

function appsHTML() {
  return `<div class="head"><div><h1>Приложения</h1><p class="sub">Правила проверяются сверху вниз. Остальные программы работают напрямую.</p></div>
  <div class="head-actions"><label class="field search ap-search">${icon("search")}<input id="ap-q" placeholder="Поиск" value="${esc(apQuery)}" autocomplete="off"></label>
  <button class="btn secondary" data-act="ap-windows" type="button">${icon("window")}Из окон</button>
  <button class="btn pri" data-act="ap-add" type="button">${icon("plus")}Добавить</button>${headMore()}</div></div>
  <div id="ap-body"></div>`;
}

function apMatches(r) {
  const q = apQuery.trim().toLowerCase();
  if (!q) return true;
  return String(r.process || "").toLowerCase().includes(q) || apLabel(r.process).toLowerCase().includes(q);
}

function fillApps() {
  const host = document.getElementById("ap-body");
  if (!host || apDrag) return;
  const rules = cfg().rules || [];
  if (!rules.length) {
    setHTML(host, `<div class="ap-empty"><h3>Приложений ещё нет</h3><p>Добавьте программу по названию — путь к exe найдётся сам — или выберите её среди открытых окон.</p><div class="row"><button class="btn pri" type="button" data-act="ap-add">${icon("plus")}Добавить приложение</button><button class="btn" type="button" data-act="ap-windows">${icon("window")}Из окон</button></div></div>`);
    return;
  }
  apTele = {};
  const units = apUnits();
  const visible = units.filter((u) => u.group
    ? u.group.name.toLowerCase().includes(apQuery.trim().toLowerCase()) || u.members.some((j) => apMatches(rules[j]))
    : apMatches(rules[u.index]));
  const isOn = (u) => (u.group ? apOn(u.group.enabled) : apOn(rules[u.index].enabled));
  const active = visible.filter(isOn);
  const inactive = visible.filter((u) => !isOn(u));
  const activeCount = active.reduce((n, u) => n + (u.group ? u.members.filter((j) => apOn(rules[j].enabled)).length : 1), 0);
  const inactiveCount = rules.filter((r) => apMatches(r)).length - activeCount;
  const groupsOn = active.filter((u) => u.group).length;
  const sel = apSelected.size ? apSelectionBar(activeCount) : "";
  const body = `${ksNotice()}${apKillBanner()}${sel}
    <div class="ap-sec"><div class="ap-sec-h"><span class="t">Активные правила</span><span class="c">${activeCount}</span>${groupsOn ? `<span class="g">(${groupsOn} ${groupWord(groupsOn)})</span>` : ""}</div>
    ${active.length ? `<div class="ap-list">${active.map((u) => apUnitHTML(u)).join("")}</div>` : `<div class="ap-none">${apQuery ? "Ничего не найдено." : "Нет активных правил. Включите правило ниже или добавьте приложение."}</div>`}</div>
    <div class="ap-sec off"><div class="ap-sec-h"><span class="t">Отключённые и неактивные</span><span class="c">${Math.max(0, inactiveCount)}</span><span class="note">Трафик направляется напрямую в обход прокси</span></div>
    ${inactive.length ? `<div class="ap-list">${inactive.map((u) => apUnitHTML(u)).join("")}</div>` : `<div class="ap-none">Все правила включены.</div>`}</div>
    <p class="hint">${icon("info", 14)} Перетащите карточку, чтобы изменить порядок. Для системных служб Windows (svchost.exe, DNS) используйте «Настройки → Системный резолвер».</p>`;
  if (setHTML(host, body)) apBindDrag(host);
  host.querySelectorAll("[data-tele]").forEach((el) => setHTML(el, apTele[el.dataset.tele] || ""));
  apPlacePopover(host);
}

// apPlacePopover lifts the card that owns the open popover and opens the
// popover upwards when it would run past the bottom of the page.
function apPlacePopover(host) {
  if (!host.querySelector) return;
  const pop = host.querySelector(".ap-pop");
  if (!pop) return;
  const card = pop.closest(".ap-card");
  if (card) card.classList.add("popped");
  const scroller = document.getElementById("page");
  if (!scroller || !pop.getBoundingClientRect) return;
  const box = scroller.getBoundingClientRect();
  const r = pop.getBoundingClientRect();
  const room = r.top - box.top;
  if (r.bottom > box.bottom - 8 && room > r.height + 48) pop.classList.add("up");
}
function groupWord(n) {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return "группа";
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return "группы";
  return "групп";
}

function apKillBanner() {
  if (!state.running) return "";
  const rules = cfg().rules || [];
  const hit = rules.filter((r) => {
    const s = apStatus(r);
    return s.bad;
  });
  if (!hit.length) return "";
  const names = hit.map((r) => apLabel(r.process)).join(", ");
  const err = (apStat(hit[0]) || {}).error || "";
  const ks = hit.some((r) => apRuleKS(r));
  return `<div class="ap-alert">${icon("alert", 16)}<div class="txt"><b>Прокси не отвечает</b><span>${esc(names)}: ${ks ? "трафик заблокирован kill switch, напрямую не выпущен." : "соединения не устанавливаются."}</span><span class="err">${esc(err)}</span></div><button class="btn sm" type="button" data-act="goto" data-page="proxies">К прокси</button></div>`;
}

function apSelectionBar(activeCount) {
  return `<div class="ap-selbar">${icon("folder", 16)}<div class="txt"><div><b>Выбрано правил: ${apSelected.size}</b> · <button type="button" class="link" data-act="ap-sel-all">Выбрать все активные (${activeCount})</button> · <button type="button" class="link dim" data-act="ap-sel-none">Снять выбор</button></div><p>Сгруппируйте их: общий тумблер и один маршрут для всех.</p></div>
  <button class="btn" type="button" data-act="ap-sel-none">Отмена</button><button class="btn pri" type="button" data-act="ap-group-new">${icon("folder", 14)}Сгруппировать (${apSelected.size})</button></div>`;
}

function apUnitHTML(u) {
  return u.group ? apGroupHTML(u) : apRuleHTML(u.index, false);
}

function apPath(process) {
  return String(process || "").trim().replace(/^"+|"+$/g, "");
}
function apSwitch(act, data, on, title) {
  return `<button class="ap-switch${on ? " on" : ""}" type="button" role="switch" aria-checked="${on}" data-act="${act}" ${data} title="${esc(title)}"><i></i></button>`;
}

function apRuleHTML(i, inGroup) {
  const r = cfg().rules[i];
  const s = apStatus(r);
  const eff = apEffective(r);
  const selected = apSelected.has(i);
  const childBadge = r.children !== false ? `<span class="chip" title="Дочерние процессы идут по этому же правилу">${icon("branch", 12)}+дочерние</span>` : "";
  // Grouped rules take the group's selection, route and switch.
  const check = inGroup ? "" : `<button class="ap-check${selected ? " on" : ""}" type="button" data-act="ap-select" data-i="${i}" title="${selected ? "Снять выбор" : "Выбрать правило для группировки"}" aria-pressed="${selected}">${selected ? icon("check", 12) : ""}</button>`;
  const route = inGroup ? "" : apRouteBadge("r" + i, r.action, r.proxy || "", s.bad);
  apTele["r" + i] = apTelemetry(s);
  return `<div class="ap-card${eff.enabled ? "" : " dim"}${inGroup ? " member" : ""}${selected ? " picked" : ""}" draggable="${inGroup ? "false" : "true"}" data-unit="r:${i}">
    <div class="ap-left">${inGroup ? "" : `<span class="ap-slot">${check}</span>`}<span class="ap-ic">${appIconHTML(apPath(r.process))}<i class="ap-dot ${s.dot}" title="${esc(s.error || (s.flows ? "Трафик идёт через прокси" : s.line))}"></i></span>
      <div class="ap-name"><div class="nm"><span>${esc(apLabel(r.process))}</span>${childBadge}${s.badge ? `<em class="bad">${esc(s.badge)}</em>` : ""}</div>
      <div class="sub"><span class="path">${esc(apPath(r.process))}</span></div></div></div>
    <div class="ap-tele" data-tele="r${i}"></div>
    <div class="ap-routecell">${route}</div>
    <div class="ap-right">${apSwitch("ap-toggle", `data-i="${i}"`, apOn(r.enabled), apOn(r.enabled) ? "Выключить правило" : "Включить правило")}
    <div class="ap-pop-wrap"><button class="ap-more" type="button" data-act="ap-menu" data-target="r${i}" aria-label="Параметры правила" title="Дополнительные параметры правила">${icon("more")}</button>${apOpen === "menu:r" + i ? apRuleMenu(i, inGroup) : ""}</div></div>
  </div>`;
}

function apRuleMenu(i, inGroup) {
  const r = cfg().rules[i];
  const ksDefault = r.killSwitch === undefined || r.killSwitch === null;
  const box = (on) => `<span class="box${on ? " on" : ""}">${icon(on ? "checkbox" : "square", 16)}</span>`;
  const g = inGroup ? apGroup(r.group) : null;
  return `<div class="ap-pop menu"><div class="cap">Параметры правила</div>
    ${g ? `<button type="button" data-act="ap-ungroup-one" data-i="${i}">${icon("folder", 14)}<span class="txt"><span class="nm">Исключить из группы «${esc(g.name)}»</span></span></button><div class="sep"></div>` : ""}
    <button type="button" data-act="ap-children" data-i="${i}"><span class="txt"><span class="nm">Проксировать дочерние процессы</span><span class="sub">Помощники, обновления, игры из лаунчера</span></span>${box(r.children !== false)}</button>
    <button type="button" data-act="ap-ks" data-i="${i}"><span class="txt"><span class="nm">Kill switch</span><span class="sub">${ksDefault ? "Как в настройках" : "Своя настройка"} · без прокси — без сети</span></span>${box(apRuleKS(r))}</button>
    <div class="ap-proto"><span>Протокол маршрутизации</span><div class="seg"><button type="button" class="${r.tcpOnly ? "" : "on"}" data-act="ap-proto" data-i="${i}" data-value="all">TCP + UDP</button><button type="button" class="${r.tcpOnly ? "on" : ""}" data-act="ap-proto" data-i="${i}" data-value="tcp">Только TCP</button></div></div>
    <div class="sep"></div>
    <button type="button" data-act="ap-up" data-i="${i}">${icon("up", 14)}<span class="txt"><span class="nm">Выше</span></span></button>
    <button type="button" data-act="ap-down" data-i="${i}">${icon("down", 14)}<span class="txt"><span class="nm">Ниже</span></span></button>
    <button type="button" data-act="ap-edit" data-i="${i}">${icon("edit", 14)}<span class="txt"><span class="nm">Изменить путь / маску…</span></span></button>
    <button type="button" data-act="copy-text" data-text="${esc(r.process)}">${icon("copy", 14)}<span class="txt"><span class="nm">Скопировать путь</span></span></button>
    <button type="button" class="danger" data-act="ap-del" data-i="${i}">${icon("trash", 14)}<span class="txt"><span class="nm">Удалить правило</span></span></button></div>`;
}

function apGroupHTML(u) {
  const g = u.group;
  const rules = cfg().rules;
  const on = apOn(g.enabled);
  const members = u.members.map((j) => rules[j]);
  let flows = 0;
  let up = 0;
  let down = 0;
  let total = 0;
  let bad = false;
  members.forEach((r) => {
    const st = apStat(r);
    if (st) { flows += st.flows || 0; up += st.upRate || 0; down += st.downRate || 0; total += (st.up || 0) + (st.down || 0); }
    if (apStatus(r).bad) bad = true;
  });
  let tele;
  if (!on) tele = `<div class="l1">Группа отключена · —</div><div class="l2">Приложения группы работают напрямую</div>`;
  else if (g.action !== "proxy") tele = `<div class="l1">${g.action === "direct" ? "Напрямую" : "Блокируется"}</div><div class="l2">${members.length} ${appWord(members.length)}</div>`;
  else if (!state.running) tele = `<div class="l1">Перехват выключен</div><div class="l2">${members.length} ${appWord(members.length)}</div>`;
  else if (flows) tele = `<div class="l1"><span class="dn">↓ ${esc(apRate(down))}</span><span class="dim">·</span><span class="up">↑ ${esc(apRate(up))}</span></div><div class="l2">${flows} ${flowWord(flows)} · ${bytes(total)}</div>`;
  else tele = `<div class="l1">Нет соединений</div><div class="l2">${members.length} ${appWord(members.length)} суммарно</div>`;
  const icons = members.slice(0, 4).map((r) => `<span class="mini" title="${esc(apLabel(r.process))}">${appIconHTML(apPath(r.process), "width:16px;height:16px;font-size:8px")}</span>`).join("");
  const target = "g:" + g.name;
  apTele[target] = tele;
  const open = !g.collapsed;
  const dot = !on ? "off" : bad ? "err" : g.action === "proxy" ? "ok" : g.action === "direct" ? "info" : "warn";
  return `<div class="ap-group${on ? "" : " dim"}" draggable="true" data-unit="g:${esc(g.name)}">
    <div class="ap-card group">
      <div class="ap-left"><span class="ap-slot"><button class="ap-chev${open ? " open" : ""}" type="button" data-act="ap-collapse" data-group="${esc(g.name)}" title="${open ? "Свернуть группу" : "Развернуть группу"}">${icon("chevr", 16)}</button></span><span class="ap-folder">${icon("folder", 16)}<i class="ap-dot ${dot}"></i></span>
        <div class="ap-name"><div class="nm"><span>${esc(g.name)}</span></div><div class="sub g"><span class="stack">${icons}</span><span class="names">${esc(members.map((r) => apLabel(r.process)).join(", "))}</span></div></div></div>
      <div class="ap-tele" data-tele="${esc(target)}"></div>
      <div class="ap-routecell">${apRouteBadge(target, g.action, g.proxy || "", bad)}</div>
      <div class="ap-right">${apSwitch("ap-gtoggle", `data-group="${esc(g.name)}"`, on, on ? "Отключить всю группу правил" : "Включить всю группу правил")}
      <div class="ap-pop-wrap"><button class="ap-more" type="button" data-act="ap-menu" data-target="${esc(target)}" aria-label="Параметры группы" title="Параметры группы">${icon("more")}</button>${apOpen === "menu:" + target ? apGroupMenu(g) : ""}</div></div>
    </div>
    ${open ? `<div class="ap-members">${u.members.map((j) => apRuleHTML(j, true)).join("")}</div>` : ""}
  </div>`;
}
function appWord(n) {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return "приложение";
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return "приложения";
  return "приложений";
}
function apGroupMenu(g) {
  return `<div class="ap-pop menu"><div class="cap">Группа «${esc(g.name)}»</div>
    <button type="button" data-act="ap-grename" data-group="${esc(g.name)}">${icon("edit", 14)}<span class="txt"><span class="nm">Переименовать…</span></span></button>
    <button type="button" data-act="ap-gup" data-group="${esc(g.name)}">${icon("up", 14)}<span class="txt"><span class="nm">Выше</span></span></button>
    <button type="button" data-act="ap-gdown" data-group="${esc(g.name)}">${icon("down", 14)}<span class="txt"><span class="nm">Ниже</span></span></button>
    <button type="button" data-act="ap-gsplit" data-group="${esc(g.name)}">${icon("folder", 14)}<span class="txt"><span class="nm">Разгруппировать</span><span class="sub">Приложения станут отдельными правилами</span></span></button>
    <button type="button" class="danger" data-act="ap-gdel" data-group="${esc(g.name)}">${icon("trash", 14)}<span class="txt"><span class="nm">Удалить группу и её правила</span></span></button></div>`;
}

// ---------- reorder ----------

function apMoveUnit(key, delta) {
  const units = apUnits();
  const at = units.findIndex((u) => u.key === key);
  const to = at + delta;
  if (at < 0 || to < 0 || to >= units.length) return false;
  const [u] = units.splice(at, 1);
  units.splice(to, 0, u);
  apFlatten(units);
  return true;
}
function apMoveRule(i, delta) {
  const r = cfg().rules[i];
  if (!r.group) return apMoveUnit("r:" + i, delta);
  // Inside a group: move among its members only.
  const rules = cfg().rules;
  const members = rules.map((x, j) => (x.group === r.group ? j : -1)).filter((j) => j >= 0);
  const pos = members.indexOf(i);
  const other = members[pos + delta];
  if (other === undefined) return false;
  [rules[i], rules[other]] = [rules[other], rules[i]];
  return true;
}
function apBindDrag(host) {
  host.querySelectorAll("[data-unit][draggable='true']").forEach((el) => {
    el.addEventListener("dragstart", (e) => {
      if (e.target !== el) return;
      apDrag = el.dataset.unit;
      el.classList.add("dragging");
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", apDrag);
    });
    el.addEventListener("dragover", (e) => {
      if (!apDrag || apDrag === el.dataset.unit) return;
      e.preventDefault();
      host.querySelectorAll(".drop-line").forEach((n) => n.classList.remove("drop-line"));
      el.classList.add("drop-line");
    });
    el.addEventListener("drop", (e) => {
      e.preventDefault();
      const from = apDrag;
      const to = el.dataset.unit;
      apDrag = null;
      if (!from || from === to) return;
      const units = apUnits();
      const a = units.findIndex((u) => u.key === from);
      const b = units.findIndex((u) => u.key === to);
      if (a < 0 || b < 0) return;
      const [u] = units.splice(a, 1);
      units.splice(b, 0, u);
      apFlatten(units);
      apSelected.clear();
      apSave("Порядок правил изменён");
    });
    el.addEventListener("dragend", () => {
      apDrag = null;
      host.querySelectorAll(".drop-line, .dragging").forEach((n) => n.classList.remove("drop-line", "dragging"));
      fillApps();
    });
  });
}

// ---------- clicks ----------

function appsClick(id, act) {
  const i = Number(act.dataset.i);
  const rules = cfg().rules || [];
  const target = act.dataset.target || "";
  const gname = act.dataset.group || "";
  const keepOpen = id === "ap-route" || id === "ap-menu";
  if (!keepOpen && id !== "ap-children" && id !== "ap-ks" && id !== "ap-proto") apOpen = "";
  switch (id) {
    case "ap-add": return apOpenAdd();
    case "ap-windows": return apOpenWindows();
    case "ap-route":
    case "ap-menu": {
      const key = (id === "ap-route" ? "route:" : "menu:") + target;
      apOpen = apOpen === key ? "" : key;
      return fillApps();
    }
    case "ap-route-set": {
      const action = act.dataset.action;
      const proxy = action === "proxy" ? act.dataset.proxy : "";
      if (target.startsWith("g:")) {
        const g = apGroup(target.slice(2));
        if (!g) return;
        g.action = action;
        g.proxy = proxy;
        // Members keep the route too, so ungrouping changes nothing.
        rules.forEach((r) => { if (r.group === g.name) { r.action = action; r.proxy = proxy; if (!proxy) delete r.proxy; } });
        if (!proxy) delete g.proxy;
        return apSave(`Маршрут группы «${g.name}»: ${apRouteText(action, proxy).kind} ${proxy}`.trim());
      }
      const r = rules[Number(target.slice(1))];
      if (!r) return;
      r.action = action;
      if (proxy) r.proxy = proxy; else delete r.proxy;
      return apSave(`${apLabel(r.process)}: ${apRouteText(action, proxy).kind} ${proxy}`.trim());
    }
    case "ap-toggle": {
      const r = rules[i];
      r.enabled = !apOn(r.enabled);
      return apSave(`${apLabel(r.process)}: ${r.enabled ? "включено" : "выключено"}`);
    }
    case "ap-gtoggle": {
      const g = apGroup(gname);
      g.enabled = !apOn(g.enabled);
      return apSave(`Группа «${g.name}» ${g.enabled ? "включена" : "отключена"}`);
    }
    case "ap-collapse": {
      const g = apGroup(gname);
      g.collapsed = !g.collapsed;
      return apSave();
    }
    case "ap-children": {
      const r = rules[i];
      if (r.children === false) delete r.children; else r.children = false;
      return apSave();
    }
    case "ap-ks": {
      const r = rules[i];
      r.killSwitch = !apRuleKS(r);
      return apSave(`${apLabel(r.process)}: kill switch ${r.killSwitch ? "включён" : "выключен"}`);
    }
    case "ap-proto": {
      const r = rules[i];
      if (act.dataset.value === "tcp") r.tcpOnly = true; else delete r.tcpOnly;
      return apSave();
    }
    case "ap-up":
    case "ap-down":
      if (apMoveRule(i, id === "ap-up" ? -1 : 1)) { apSelected.clear(); return apSave(); }
      return fillApps();
    case "ap-gup":
    case "ap-gdown":
      if (apMoveUnit("g:" + gname, id === "ap-gup" ? -1 : 1)) return apSave();
      return fillApps();
    case "ap-edit": return apOpenEdit(i);
    case "ap-del": {
      const r = rules[i];
      rules.splice(i, 1);
      apSelected.clear();
      return apSave(`Правило «${apLabel(r.process)}» удалено`);
    }
    case "ap-ungroup-one": {
      // Move the rule just after its group so the group stays contiguous.
      const r = rules[i];
      const name = r.group;
      const last = rules.map((x, j) => (x.group === name ? j : -1)).filter((j) => j >= 0).pop();
      delete r.group;
      rules.splice(i, 1);
      rules.splice(last, 0, r);
      if (!rules.some((x) => x.group === name)) cfg().groups = apGroups().filter((g) => g.name !== name);
      return apSave(`«${apLabel(r.process)}» вынесено из группы`);
    }
    case "ap-gsplit": {
      const n = rules.filter((r) => r.group === gname).length;
      rules.forEach((r) => { if (r.group === gname) delete r.group; });
      cfg().groups = apGroups().filter((g) => g.name !== gname);
      return apSave(`Группа «${gname}» разделена: ${n} ${appWord(n)} снова отдельно`);
    }
    case "ap-gdel":
      return askConfirm("Удалить группу?", `Группа «${gname}» и все её правила исчезнут из списка.`, "Удалить", true, () => {
        cfg().rules = rules.filter((r) => r.group !== gname);
        cfg().groups = apGroups().filter((g) => g.name !== gname);
        apSelected.clear();
        apSave(`Группа «${gname}» удалена`);
      });
    case "ap-grename": return apOpenGroupName(gname);
    case "ap-select":
      if (apSelected.has(i)) apSelected.delete(i); else apSelected.add(i);
      return fillApps();
    case "ap-sel-all":
      rules.forEach((r, j) => { if (!r.group && apOn(r.enabled) && apMatches(r)) apSelected.add(j); });
      return fillApps();
    case "ap-sel-none":
      apSelected.clear();
      return fillApps();
    case "ap-group-new": return apOpenGroupNew();
    default: return appsModalClick(id, act);
  }
}

// Close popovers on any click outside them.
document.addEventListener("click", (e) => {
  if (!apOpen) return;
  if (e.target.closest(".ap-pop") || e.target.closest("[data-act='ap-route']") || e.target.closest("[data-act='ap-menu']")) return;
  apOpen = "";
  if (page === "rules") fillApps();
});

// ---------- dialogs ----------

function apDefaultRoute() {
  const first = (cfg().proxies || [])[0];
  return first ? { action: "proxy", proxy: first.name } : { action: "direct", proxy: "" };
}
function apRouteSelect(id, action, proxy) {
  const opts = apRoutes().map((r) => {
    const v = r.action + ":" + r.proxy;
    const label = r.p ? `${r.proxy} · ${proxyTypeLabel(r.p.type)} · ${proxyAddrText(r.p)}` : apRouteText(r.action, "").kind;
    const on = r.action === action && (r.action !== "proxy" || r.proxy === proxy);
    return `<option value="${esc(v)}"${on ? " selected" : ""}>${esc(label)}</option>`;
  }).join("");
  return `<div class="field"><select id="${id}">${opts}</select></div>`;
}
function apReadRoute(id) {
  const v = (document.getElementById(id) || {}).value || "direct:";
  const at = v.indexOf(":");
  return { action: v.slice(0, at), proxy: v.slice(at + 1) };
}
function apLoadApps(m) {
  if (DEMO) {
    m.apps = [
      { name: "Obsidian.exe", pid: 14208, window: true, title: "Obsidian — Заметки", path: "C:\\Users\\user\\AppData\\Local\\Obsidian\\Obsidian.exe" },
      { name: "Code.exe", pid: 8812, window: true, title: "Ashgate — Visual Studio Code", path: "C:\\Users\\user\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe" },
      { name: "chrome.exe", pid: 9104, window: true, title: "Google Chrome — 14 вкладок", path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" },
      { name: "steam.exe", pid: 19430, window: true, title: "Steam", path: "C:\\Program Files (x86)\\Steam\\steam.exe" },
    ];
    m.installed = [
      { name: "Telegram Desktop", path: "C:\\Users\\user\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe" },
      { name: "Discord", path: "C:\\Users\\user\\AppData\\Local\\Discord\\app-1.0.9187\\Discord.exe" },
      { name: "Spotify", path: "C:\\Users\\user\\AppData\\Roaming\\Spotify\\Spotify.exe" },
    ];
    return;
  }
  apiFetch("/api/processes").then((r) => r.json()).then((list) => {
    if (modal !== m) return;
    m.apps = list;
    renderModal();
  }).catch(() => {});
  apiFetch("/api/installed").then((r) => r.json()).then((list) => {
    if (modal !== m) return;
    m.installed = list;
    apAutoPath(m);
    renderModal();
  }).catch(() => { if (modal === m) { m.installed = []; renderModal(); } });
}

function apOpenAdd() {
  const route = apDefaultRoute();
  modal = { kind: "ap-add", q: "", path: "", auto: false, action: route.action, proxy: route.proxy, children: true, ks: apGlobalKS(), tcpOnly: false, apps: [], installed: null };
  apLoadApps(modal);
  renderModal();
}
function apOpenWindows() {
  modal = { kind: "ap-windows", apps: null };
  if (DEMO) { apLoadApps(modal); renderModal(); return; }
  renderModal();
  const m = modal;
  apiFetch("/api/processes").then((r) => r.json()).then((list) => { if (modal === m) { m.apps = list; renderModal(); } })
    .catch(() => { if (modal === m) { m.apps = []; renderModal(); } });
}
function apOpenEdit(i) {
  const r = cfg().rules[i];
  modal = { kind: "ap-edit", index: i, value: r.process };
  renderModal();
}
function apOpenGroupNew() {
  const route = apDefaultRoute();
  modal = { kind: "ap-group", name: "", members: [...apSelected].sort((a, b) => a - b), action: route.action, proxy: route.proxy };
  renderModal();
}
function apOpenGroupName(name) {
  modal = { kind: "ap-gname", old: name, name };
  renderModal();
}

// apCandidates lists running and installed apps that match the query,
// best match first; running programs with a window win ties.
function apCandidates(m, q, limit) {
  q = String(q || "").trim().toLowerCase().replace(/\.exe$/i, "");
  const seen = new Set();
  const out = [];
  const push = (name, path, src, extra) => {
    const k = String(path || name).toLowerCase();
    if (!path || seen.has(k)) return;
    const score = pickMatch(q, name, path);
    if (q && !score) return;
    seen.add(k);
    out.push({ name, path, src, score: score + (src === "run" && extra && extra.window ? 0.5 : 0), extra });
  };
  (m.apps || []).forEach((a) => push(a.name.replace(/\.exe$/i, ""), a.path, "run", a));
  (m.installed || []).forEach((a) => push(a.name, a.path, "inst"));
  out.sort((a, b) => b.score - a.score);
  return out.slice(0, limit);
}
function apAutoPath(m) {
  if (!m.q.trim() || (m.path && !m.auto)) return;
  const best = apCandidates(m, m.q, 1)[0];
  if (best && best.score >= 3) { m.path = best.path; m.auto = true; }
  else if (m.auto) { m.path = ""; }
}

function apAddHTML() {
  const m = modal;
  const list = m.q.trim() ? apCandidates(m, m.q, 6) : apCandidates(m, "", 40).filter((c) => c.src === "run" && c.extra && c.extra.window).slice(0, 6);
  const cur = String(m.path || "").toLowerCase();
  const chips = list.map((c) => `<button type="button" class="ap-pick${cur === String(c.path).toLowerCase() ? " on" : ""}" data-act="ap-pick" data-name="${esc(c.name)}" data-path="${esc(c.path)}">${appIconHTML(c.path, "width:22px;height:22px;border-radius:5px;font-size:11px")}<span class="txt"><span class="nm">${esc(c.name)}</span><span class="sub">${esc(c.extra && c.extra.title ? c.extra.title : c.path)}</span></span><span class="src">${c.src === "run" ? "запущено" : "установлено"}</span></button>`).join("");
  const empty = m.q.trim()
    ? (m.installed === null ? "Ищу установленные приложения…" : "Не найдено. Укажите путь вручную или через «Обзор…».")
    : "Открытых окон нет.";
  const box = (on) => icon(on ? "checkbox" : "square", 16);
  return `<div class="scrim"><form class="dialog ap-dlg" id="dlg">
    <div class="ap-dlg-h"><span class="ic">${icon("plus", 16)}</span><div><h2>Добавить правило приложения</h2><div class="dsub">Настройка маршрутизации трафика программы</div></div></div>
    <div class="body">
      <label class="lbl" for="ap-add-q">Поиск приложения по названию</label>
      <div class="field search">${icon("search")}<input id="ap-add-q" value="${esc(m.q)}" placeholder="Например: Telegram, Discord, Steam…" autocomplete="off" autofocus></div>
      <div class="ap-pathline"><span class="lbl">Путь (.exe)</span>${m.auto && m.path ? `<span class="auto">найден автоматически</span>` : ""}</div>
      <div class="proc-line"><div class="field"><input class="mono" id="ap-add-path" value="${esc(m.path)}" placeholder="Подставится при вводе названия" autocomplete="off"></div><button class="btn" type="button" data-act="ap-browse">${icon("folder")}Обзор…</button></div>
      <div class="help">Пусто — правило по имени файла. Знак * — любые символы в пути: *\\Discord\\app-*\\Discord.exe</div>
      <div class="ap-or"><span>${m.q.trim() ? "совпадения" : "или выберите открытое окно"}</span></div>
      <div class="ap-picks">${chips || `<div class="ap-none">${esc(empty)}</div>`}</div>
      <label class="lbl" style="margin-top:14px">Маршрутизировать через</label>
      ${apRouteSelect("ap-add-route", m.action, m.proxy)}
      <button type="button" class="ap-checkline" data-act="ap-add-children">${box(m.children)}<span><b>Проксировать дочерние процессы</b><small>Помощники, обновления и всё, что запускает программа, идут по этому же правилу</small></span></button>
      <button type="button" class="ap-checkline" data-act="ap-add-ks">${box(m.ks)}<span><b>Kill switch — защита от утечки IP</b><small>Если прокси недоступен или Ashgate выключен, программа не выходит в сеть напрямую</small></span></button>
      <label class="lbl" style="margin-top:12px">Протокол</label>
      <div class="seg"><button type="button" class="${m.tcpOnly ? "" : "on"}" data-act="ap-add-proto" data-value="all">TCP + UDP</button><button type="button" class="${m.tcpOnly ? "on" : ""}" data-act="ap-add-proto" data-value="tcp">Только TCP</button></div>
    </div>
    <div class="footer"><button class="btn pri" type="submit">Добавить в список</button><button class="btn" type="button" data-act="cancel">Отмена</button></div>
  </form></div>`;
}

function apWindowsHTML() {
  const m = modal;
  const have = new Set((cfg().rules || []).map((r) => apKey(r.process)));
  const list = (m.apps || []).filter((a) => a.window);
  const rows = list.map((a) => {
    const added = have.has(apKey(a.path)) || have.has(apKey(a.name));
    return `<div class="ap-win">${appIconHTML(a.path, "width:28px;height:28px;border-radius:7px;font-size:12px")}<span class="txt"><span class="nm">${esc(a.title || a.name)}</span><span class="sub">${esc(a.name)} · PID ${a.pid} · ${esc(a.path)}</span></span>
      ${added ? `<span class="done">${icon("check", 14)}Уже в правилах</span>` : `<button class="btn sm pri" type="button" data-act="ap-win-add" data-name="${esc(a.name)}" data-path="${esc(a.path)}">Добавить</button>`}</div>`;
  }).join("");
  const body = m.apps === null ? `<div class="ap-none">Загружаю окна…</div>` : rows || `<div class="ap-none">Открытых окон не найдено.</div>`;
  return `<div class="scrim"><form class="dialog ap-dlg" id="dlg">
    <div class="ap-dlg-h"><span class="ic">${icon("window", 16)}</span><div><h2>Запущенные окна Windows</h2><div class="dsub">Выберите программу, чтобы сразу добавить её в правила</div></div></div>
    <div class="body"><div class="ap-wins">${body}</div></div>
    <div class="footer"><button class="btn" type="button" data-act="cancel">Закрыть</button></div>
  </form></div>`;
}

function apEditHTML() {
  const m = modal;
  const r = cfg().rules[m.index] || {};
  return `<div class="scrim"><form class="dialog narrow ap-dlg" id="dlg">
    <div class="ap-dlg-h"><span class="ic">${icon("edit", 16)}</span><div><h2>Путь процесса</h2><div class="dsub">${esc(apLabel(r.process))}</div></div></div>
    <div class="body"><label class="lbl" for="ap-edit-v">Имя файла, путь или маска</label>
    <div class="field"><input class="mono" id="ap-edit-v" value="${esc(m.value)}" autocomplete="off" autofocus></div>
    <div class="help">Знак * — любое количество символов в пути, например *\\Discord\\app-*\\Discord.exe. Имя без расширения (chrome) значит chrome.exe.</div></div>
    <div class="footer"><button class="btn pri" type="submit">Сохранить</button><button class="btn" type="button" data-act="cancel">Отмена</button></div>
  </form></div>`;
}

function apGroupNewHTML() {
  const m = modal;
  const rules = cfg().rules;
  const members = m.members.map((j) => `<span class="ap-member">${appIconHTML(rules[j].process, "width:18px;height:18px;border-radius:5px;font-size:9px")}${esc(apLabel(rules[j].process))}<button type="button" data-act="ap-gnew-drop" data-i="${j}" title="Убрать из группы">${icon("close", 12)}</button></span>`).join("");
  return `<div class="scrim"><form class="dialog ap-dlg" id="dlg">
    <div class="ap-dlg-h"><span class="ic">${icon("folder", 16)}</span><div><h2>Создать группу приложений</h2><div class="dsub">${m.members.length} ${appWord(m.members.length)} под общим тумблером и маршрутом</div></div></div>
    <div class="body"><label class="lbl" for="ap-gnew-name">Название группы</label>
    <div class="field"><input id="ap-gnew-name" value="${esc(m.name)}" placeholder="Например: Мессенджеры, Игры…" autocomplete="off" autofocus></div>
    <div class="ap-presets"><span>Быстрые варианты:</span>${AP_GROUP_PRESETS.map((p) => `<button type="button" data-act="ap-gnew-preset" data-name="${esc(p)}">${esc(p)}</button>`).join("")}</div>
    <label class="lbl" style="margin-top:14px">Входят (${m.members.length})</label><div class="ap-members-edit">${members || `<span class="ap-none">Никого не осталось.</span>`}</div>
    <label class="lbl" style="margin-top:14px">Маршрутизировать всю группу через</label>${apRouteSelect("ap-gnew-route", m.action, m.proxy)}
    <div class="help">Группу можно выключить одним тумблером и в любой момент разгруппировать обратно.</div></div>
    <div class="footer"><button class="btn pri" type="submit"${m.members.length ? "" : " disabled"}>Сгруппировать (${m.members.length})</button><button class="btn" type="button" data-act="cancel">Отмена</button></div>
  </form></div>`;
}

function apGroupNameHTML() {
  const m = modal;
  return `<div class="scrim"><form class="dialog narrow ap-dlg" id="dlg">
    <div class="ap-dlg-h"><span class="ic">${icon("folder", 16)}</span><div><h2>Переименовать группу</h2><div class="dsub">${esc(m.old)}</div></div></div>
    <div class="body"><label class="lbl" for="ap-gname-v">Название</label><div class="field"><input id="ap-gname-v" value="${esc(m.name)}" autocomplete="off" autofocus></div></div>
    <div class="footer"><button class="btn pri" type="submit">Сохранить</button><button class="btn" type="button" data-act="cancel">Отмена</button></div>
  </form></div>`;
}

const AP_MODALS = { "ap-add": apAddHTML, "ap-windows": apWindowsHTML, "ap-edit": apEditHTML, "ap-group": apGroupNewHTML, "ap-gname": apGroupNameHTML };

// apReadModal copies inputs into the modal before it is redrawn.
function apReadModal() {
  if (!modal) return;
  const v = (id) => { const n = document.getElementById(id); return n ? n.value : null; };
  if (modal.kind === "ap-add") {
    const q = v("ap-add-q");
    const p = v("ap-add-path");
    if (q !== null) modal.q = q;
    if (p !== null && p !== modal.path) { modal.path = p; modal.auto = false; }
    if (document.getElementById("ap-add-route")) { const r = apReadRoute("ap-add-route"); modal.action = r.action; modal.proxy = r.proxy; }
  } else if (modal.kind === "ap-group") {
    const n = v("ap-gnew-name");
    if (n !== null) modal.name = n;
    if (document.getElementById("ap-gnew-route")) { const r = apReadRoute("ap-gnew-route"); modal.action = r.action; modal.proxy = r.proxy; }
  } else if (modal.kind === "ap-edit") {
    const n = v("ap-edit-v");
    if (n !== null) modal.value = n;
  } else if (modal.kind === "ap-gname") {
    const n = v("ap-gname-v");
    if (n !== null) modal.name = n;
  }
}

function appsModalClick(id, act) {
  if (!modal) return;
  apReadModal();
  switch (id) {
    case "ap-pick":
      modal.q = act.dataset.name;
      modal.path = act.dataset.path;
      modal.auto = false;
      return renderModal();
    case "ap-add-children": modal.children = !modal.children; return renderModal();
    case "ap-add-ks": modal.ks = !modal.ks; return renderModal();
    case "ap-add-proto": modal.tcpOnly = act.dataset.value === "tcp"; return renderModal();
    case "ap-browse":
      if (DEMO) return;
      return post("/api/browse").then((res) => {
        if (res.path && modal && modal.kind === "ap-add") {
          apReadModal();
          modal.path = res.path;
          modal.auto = false;
          if (!modal.q.trim()) modal.q = apLabel(res.path);
          renderModal();
        }
      }).catch((err) => { if (err.message && err.message !== "отменено") showToast(err.message); });
    case "ap-win-add": {
      const route = apDefaultRoute();
      const process = act.dataset.path || act.dataset.name;
      apAddRule({ enabled: true, process, action: route.action, proxy: route.proxy });
      return renderModal();
    }
    case "ap-gnew-preset": modal.name = act.dataset.name; return renderModal();
    case "ap-gnew-drop": modal.members = modal.members.filter((j) => j !== Number(act.dataset.i)); return renderModal();
    default:
  }
}

// apAddRule puts a new rule first, so it wins over older ones. An existing
// rule for the same program is switched on instead of duplicated.
function apAddRule(rule) {
  const rules = cfg().rules;
  const dup = rules.find((r) => apKey(r.process) === apKey(rule.process));
  const label = apLabel(rule.process);
  if (dup) {
    if (!apOn(dup.enabled)) { dup.enabled = true; apSave(`Правило для ${label} уже было — включено`); }
    else showToast(`Правило для ${label} уже есть`);
    return;
  }
  if (!rule.proxy) delete rule.proxy;
  rules.unshift(rule);
  apSelected.clear();
  apSave(`${label} добавлено в активные`);
}

function appsSubmit() {
  apReadModal();
  const m = modal;
  if (m.kind === "ap-add") {
    let process = String(m.path || "").trim().replace(/^"+|"+$/g, "");
    if (!process) {
      process = m.q.trim();
      if (process && !/\.[A-Za-z0-9]+$/.test(process)) process = process.replace(/\s+/g, "") + ".exe";
    }
    if (!process) { showToast("Введите название приложения"); return; }
    if (/^svchost\.exe$/i.test(baseName(process))) { showToast("Не указывайте svchost.exe — для системного DNS есть «Системный резолвер» в настройках"); return; }
    if (m.action === "proxy" && !m.proxy) { showToast("Сначала добавьте прокси"); return; }
    const rule = { enabled: true, process, action: m.action, proxy: m.proxy };
    if (!m.children) rule.children = false;
    if (m.ks !== apGlobalKS()) rule.killSwitch = m.ks;
    if (m.tcpOnly) rule.tcpOnly = true;
    modal = null;
    renderModal();
    apAddRule(rule);
    return;
  }
  if (m.kind === "ap-edit") {
    const v = String(m.value || "").trim().replace(/^"+|"+$/g, "");
    if (!v) { showToast("Укажите имя файла, путь или маску"); return; }
    if (/^svchost\.exe$/i.test(baseName(v))) { showToast("Не указывайте svchost.exe"); return; }
    const r = cfg().rules[m.index];
    r.process = v;
    modal = null;
    renderModal();
    apSave("Путь правила изменён");
    return;
  }
  if (m.kind === "ap-group") {
    const name = String(m.name || "").trim();
    if (!name) { showToast("Введите название группы"); return; }
    if (apGroup(name)) { showToast("Группа с таким названием уже есть"); return; }
    if (!m.members.length) return;
    const rules = cfg().rules;
    const picked = new Set(m.members);
    picked.forEach((j) => {
      rules[j].group = name;
      rules[j].action = m.action;
      if (m.proxy) rules[j].proxy = m.proxy; else delete rules[j].proxy;
    });
    // Gather the members where the first of them stood.
    const first = Math.min(...m.members);
    const moved = m.members.map((j) => rules[j]);
    const rest = rules.filter((_, j) => !picked.has(j));
    const at = rest.indexOf(rules.slice(0, first).filter((_, j) => !picked.has(j)).pop());
    rest.splice(at + 1, 0, ...moved);
    cfg().rules = rest;
    const g = { name, enabled: true, action: m.action, collapsed: false };
    if (m.proxy) g.proxy = m.proxy;
    apGroups().push(g);
    apSelected.clear();
    modal = null;
    renderModal();
    apSave(`Группа «${name}» создана: ${moved.length} ${appWord(moved.length)}`);
    return;
  }
  if (m.kind === "ap-gname") {
    const name = String(m.name || "").trim();
    if (!name) { showToast("Введите название"); return; }
    if (name !== m.old && apGroup(name)) { showToast("Группа с таким названием уже есть"); return; }
    const g = apGroup(m.old);
    if (g) {
      g.name = name;
      cfg().rules.forEach((r) => { if (r.group === m.old) r.group = name; });
    }
    modal = null;
    renderModal();
    apSave(`Группа переименована: «${name}»`);
  }
}

function appsInput(e) {
  if (e.target.id === "ap-q") {
    apQuery = e.target.value;
    fillApps();
    return true;
  }
  if (modal && modal.kind === "ap-add" && (e.target.id === "ap-add-q" || e.target.id === "ap-add-path")) {
    apReadModal();
    if (e.target.id === "ap-add-q") apAutoPath(modal);
    // Redraw without losing the caret.
    const id = e.target.id;
    const pos = e.target.selectionStart;
    renderModal();
    const again = document.getElementById(id);
    if (again) { again.focus(); try { again.setSelectionRange(pos, pos); } catch (err) { /* ignore */ } }
    return true;
  }
  return false;
}
