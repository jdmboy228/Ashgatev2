// End-to-end UI tests of the real Ashgate window (WebView2) on the Windows
// runner. One app instance is driven through every page, dialog and main
// flow; then it is restarted and everything must still be there.
import { test, expect, type Page } from "@playwright/test";
import * as fs from "node:fs";
import * as path from "node:path";
import { App, OUT, cleanupPolicy, desktop, fixtures, readConfig, type Problem } from "./app";

const fx = fixtures();
const CLIENT = "C:\\ashgate-e2e\\apps\\ashgate-e2e-client.exe";
// A path companion that never runs here: it only has to be a valid path the
// page and the server accept, so the drawer and the dialog can be driven.
const COMPANION = "C:\\Program Files\\ldplayer9box\\Ld9BoxHeadless.exe";
const SIZES: [number, number][] = [[1100, 720], [760, 520]];
const findings: Problem[] = [];
let app: App;
let page: Page;

function shotPath(name: string) {
  const p = path.join(OUT, "ui", "screens", `${name}.png`);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  return p;
}

// screens takes the current view at every size and checks its layout.
async function screens(name: string) {
  for (const [w, h] of SIZES) {
    await page.setViewportSize({ width: w, height: h });
    await page.waitForTimeout(300);
    await page.screenshot({ path: shotPath(`${name}-${w}x${h}`) });
    for (const p of await layoutProblems(page)) findings.push({ ...p, where: `${name} ${w}x${h}` });
  }
  await page.setViewportSize({ width: SIZES[0][0], height: SIZES[0][1] });
}

// layoutProblems finds clipped or spilling text and controls pushed out of
// the window. Ellipsis and scroll containers are fine.
async function layoutProblems(p: Page): Promise<Problem[]> {
  return p.evaluate(() => {
    const out: { kind: string; text: string }[] = [];
    const vw = window.innerWidth;
    const scrollsX = (el: Element | null): boolean => {
      for (let e = el; e && e !== document.body; e = e.parentElement) {
        const ox = getComputedStyle(e).overflowX;
        if (ox === "auto" || ox === "scroll") return true;
      }
      return false;
    };
    const desc = (el: Element) => {
      const id = el.id ? "#" + el.id : "";
      const cls = el.className && typeof el.className === "string" ? "." + el.className.trim().split(/\s+/).join(".") : "";
      return `${el.tagName.toLowerCase()}${id}${cls} "${(el.textContent || "").trim().slice(0, 40)}"`;
    };
    for (const el of Array.from(document.querySelectorAll("body *"))) {
      const cs = getComputedStyle(el);
      if (cs.display === "none" || cs.visibility === "hidden" || (el as HTMLElement).offsetParent === null && cs.position !== "fixed") continue;
      const r = el.getBoundingClientRect();
      if (r.width < 2 || r.height < 2) continue;
      const ownText = Array.from(el.childNodes).some((n) => n.nodeType === 3 && (n.textContent || "").trim().length > 0);
      if (ownText && el.scrollWidth > el.clientWidth + 2 && el.clientWidth > 0) {
        if (cs.textOverflow !== "ellipsis" && cs.overflowX !== "auto" && cs.overflowX !== "scroll" && !/textarea|input|select/i.test(el.tagName)) {
          out.push({ kind: cs.overflowX === "visible" ? "text spills out" : "text clipped", text: desc(el) });
        }
      }
      if ((el.matches("button, input, select, textarea, h1, h2") || ownText) && (r.right > vw + 2 || r.left < -2) && !scrollsX(el.parentElement)) {
        out.push({ kind: "outside the window", text: desc(el) });
      }
    }
    return out;
  });
}

async function nav(id: "rules" | "proxies" | "log" | "settings") {
  await page.locator(`[data-nav="${id}"]`).click();
  await expect(page.locator(`[data-nav="${id}"]`)).toHaveClass(/active/);
  await expect(page.locator("#page h1")).toBeVisible();
  const text = (await page.locator("#page").innerText()).trim();
  expect(text.length, `page ${id} is blank`).toBeGreaterThan(20);
}

const dlg = () => page.locator("#modal form#dlg");
async function closeDialog() {
  if (await dlg().count()) {
    const cancel = dlg().locator('[data-act="cancel"]');
    if (await cancel.count()) await cancel.first().click();
    else await page.keyboard.press("Escape");
  }
  await expect(dlg()).toHaveCount(0);
}

async function noFieldErrors(where: string) {
  const errs = await page.locator("#modal .field-err").allInnerTexts();
  expect(errs, `validation errors on valid input (${where})`).toEqual([]);
}

// typeKept types into a dialog field and checks the text survives the
// dialog's own redraws (its app lists load in the background): a redraw used
// to drop what was typed.
async function typeKept(field: import("@playwright/test").Locator, text: string) {
  await field.fill(text);
  await page.waitForTimeout(2000);
  await expect(field, "the dialog lost typed text when it redrew").toHaveValue(text);
}

async function toast(re: RegExp) {
  await expect(page.locator("#toast")).toBeVisible();
  await expect(page.locator("#toast")).toHaveText(re);
}

// The wrapper holds the rule card and its companion drawer as siblings, so
// the drawer is found from the wrapper, not from the card.
function clientUnit() {
  return page.locator(".ap-unit-wrap", {
    has: page.locator(".ap-card:not(.group)", { hasText: "ashgate-e2e-client" }),
  }).first();
}
function clientRule(): any {
  return readConfig().rules.find((r: any) => /ashgate-e2e-client/i.test(String(r.process)));
}
// Rule and group menus are portal popovers: they are drawn in #ap-portal on
// <body>, never inside a card, so a card's overflow or a scrolled list can
// never clip them.
function portalMenu() {
  return page.locator("#ap-portal .ap-pop.menu");
}
async function closePortal() {
  if (await page.locator("#ap-portal:visible").count()) {
    await page.keyboard.press("Escape");
    await expect(page.locator("#ap-portal"), "Escape did not close the portal menu").toBeHidden();
  }
}
// dismissMenus closes an open row menu and portal popover: Escape closes the
// row menu first, so it may take two presses.
async function dismissMenus() {
  for (let i = 0; i < 2; i++) {
    if (!(await page.locator("#menu:visible").count()) && !(await page.locator("#ap-portal:visible").count())) return;
    await page.keyboard.press("Escape");
  }
}
// ruleUnit is one rule's wrapper; the companion drawer is its sibling, so it
// is found from the wrapper and not from the card.
function ruleUnit(name: string) {
  return page.locator(".ap-unit-wrap", { has: page.locator(".ap-card:not(.group)", { hasText: name }) }).first();
}
// activeOrder is the text of the active units in display order: the page
// sorts them by tier (traffic, waiting, not running), alphabetically inside
// a tier, so no timer can shuffle equal cards.
async function activeOrder(): Promise<string[]> {
  return page.locator('[data-ap-list="active"] > [data-unit-key]').evaluateAll((els) =>
    els.map((e) => (e.textContent || "").toLowerCase().replace(/\s+/g, " ").trim()));
}
async function expectAbove(above: string, below: string, why: string) {
  const order = await activeOrder();
  const a = order.findIndex((t) => t.includes(above));
  const b = order.findIndex((t) => t.includes(below));
  expect(a, `${why}: «${above}» is not in «Активные правила»`).toBeGreaterThanOrEqual(0);
  expect(b, `${why}: «${below}» is not in «Активные правила»`).toBeGreaterThanOrEqual(0);
  expect(a, `${why}: «${above}» must sort above «${below}» — ${JSON.stringify(order)}`).toBeLessThan(b);
}
// openRuleMenu opens a card's «…» menu (a rule's or a group's) in the portal.
async function openRuleMenu(card: import("@playwright/test").Locator) {
  await closePortal();
  await card.locator('[data-act="ap-menu"]').first().click();
  await expect(portalMenu(), "the menu did not open in #ap-portal").toBeVisible();
  return portalMenu();
}
async function openCompanions() {
  const card = clientUnit().locator(".ap-card:not(.group)").first();
  await expect(card, "the ashgate-e2e-client rule card is missing").toBeVisible();
  const menu = await openRuleMenu(card);
  const item = menu.locator('[data-act="ap-companions"]');
  await expect(item, "the rule menu has no «Связанные процессы / Найти трафик…» item").toBeVisible();
  await item.click();
  await expect(dlg()).toBeVisible();
  await expect(dlg().locator(".ap-dlg-h h2")).toHaveText("Связанные процессы");
}
// addCompanion types a path into the open dialog and waits for the save.
async function addCompanion(path: string) {
  const field = dlg().locator("#ap-comp-manual");
  await expect(field, "the companions dialog has no manual field").toBeVisible();
  await field.fill(path);
  await dlg().locator('button[data-act="ap-comp-manual"]').click();
  await expect.poll(() => (clientRule()?.companions || []), {
    timeout: 15_000,
    message: "the companion was not saved to config.json",
  }).toContain(path);
  await expect(dlg().locator(".ap-comp-item", { hasText: "Ld9BoxHeadless" })).toBeVisible();
}
// companionGone waits until the save removing the companion has landed.
async function companionGone(path: string) {
  await expect.poll(() => (clientRule()?.companions || []), {
    timeout: 15_000,
    message: "the companion was not removed from config.json",
  }).not.toContain(path);
}

// liveness clicks every visible button in scope and checks that each one
// does something: a DOM change, a request, a dialog, a menu or a toast.
async function liveness(scope: string, label: string) {
  const skip = [
    "#side-power", "#win-min", "#win-max", "#win-close", "[data-nav]",
    '[data-act="open-folder"]', '[data-act="update-open"]', '[data-act="ap-browse"]',
    '[data-act="paste-vless"]', '[data-act="proxy-del"]', '[data-act="ap-del"]',
    // Companion controls change config or only exist inside the dialog:
    // expanding a drawer must not let a shifted index hit «Отвязать».
    '[data-act="ap-sub-remove"]', '[data-act="ap-sub-mask"]',
    '[data-act="ap-comp-del"]', '[data-act="ap-radar-capture"]',
    '[data-act="ap-hint-attach"]', '[data-act="ap-hint-dismiss"]',
  ].join(",");
  const buttons = page.locator(`${scope} button:visible`);
  const n = await buttons.count();
  for (let i = 0; i < n; i++) {
    const b = buttons.nth(i);
    // A menu opened by the previous button must not cover the next one.
    await dismissMenus();
    if (!(await b.isVisible()) || (await b.isDisabled()) || (await b.evaluate((el, s) => el.matches(s), skip))) continue;
    const name = ((await b.getAttribute("aria-label")) || (await b.innerText()) || (await b.getAttribute("data-act")) || "button").trim();
    let requests = 0;
    const onReq = () => { requests++; };
    page.on("request", onReq);
    await page.evaluate(() => {
      (window as any).__mut = 0;
      (window as any).__obs?.disconnect();
      const o = new MutationObserver((m) => { (window as any).__mut += m.length; });
      o.observe(document.body, { subtree: true, childList: true, attributes: true, characterData: true });
      (window as any).__obs = o;
    });
    // Ignore the 1 s state poll: count requests other than /api/state.
    const stateReqs: string[] = [];
    const onState = (r: any) => { if (/\/api\/state/.test(r.url())) stateReqs.push(r.url()); };
    page.on("request", onState);
    try { await b.click({ timeout: 3000 }); } catch { continue; }
    await page.waitForTimeout(1000);
    page.off("request", onReq);
    page.off("request", onState);
    const mut = await page.evaluate(() => (window as any).__mut as number);
    const opened = (await dlg().count()) > 0 || (await page.locator("#menu:visible").count()) > 0 ||
      (await page.locator("#ap-portal:visible").count()) > 0 || (await page.locator("#toast:visible").count()) > 0;
    if (mut === 0 && requests - stateReqs.length === 0 && !opened) {
      findings.push({ kind: "button does nothing", text: name, where: label });
    }
    // Undo: close what opened, flip switches back.
    if (await dlg().count()) await closeDialog();
    await dismissMenus();
    if (await page.locator("#menu:visible").count()) await page.mouse.click(5, 300);
    if (await b.evaluate((el) => el.matches('.toggle, .ap-switch, [data-act="pause"], [data-act="errors-only"], [data-act="ap-select"]')).catch(() => false)) {
      await b.click().catch(() => {});
      await page.waitForTimeout(500);
    }
  }
}

test.describe.serial("Ashgate window", () => {
  test.beforeAll(async () => {
    app = await App.launch();
    page = app.page;
    // Attach first, then reload: errors while the page loads are caught too.
    await page.reload();
    await page.waitForFunction(() => !!document.querySelector("#page")?.children.length);
  });

  // A dialog left open by a failed step must not block every later test.
  test.afterEach(async () => {
    if (!page) return;
    if (await dlg().count()) await closeDialog().catch(() => {});
    await dismissMenus().catch(() => {});
  });

  test.afterAll(async () => {
    fs.mkdirSync(path.join(OUT, "ui"), { recursive: true });
    fs.writeFileSync(path.join(OUT, "ui", "findings.json"), JSON.stringify({ findings, problems: app?.problems || [] }, null, 2));
    await app?.quit();
    cleanupPolicy();
  });

  test("every page renders", async () => {
    for (const id of ["rules", "proxies", "log", "settings"] as const) {
      await nav(id);
      await screens(`page-${id}`);
    }
    desktop("desktop-window");
  });

  test("proxy dialog in every type", async () => {
    await nav("proxies");
    await page.locator('[data-act="proxy-add"]').first().click();
    await expect(dlg()).toBeVisible();
    for (const t of ["socks5", "http", "vless", "sub"]) {
      await dlg().locator(`[data-act="ptype"][data-value="${t}"]`).click();
      await screens(`dialog-proxy-${t}`);
    }
    await closeDialog();
  });

  test("add, edit and delete SOCKS5 and HTTP proxies", async () => {
    await nav("proxies");
    const add = async (name: string, type: string, addr: string) => {
      await page.locator('[data-act="proxy-add"]').first().click();
      await dlg().locator(`[data-act="ptype"][data-value="${type}"]`).click();
      await dlg().locator("#p-name").fill(name);
      await dlg().locator("#p-addr").fill(addr);
      await dlg().locator("#p-user").fill(fx.user);
      await dlg().locator("#p-pass").fill(fx.pass);
      await dlg().locator('button[type="submit"]').click();
      await expect(dlg(), `the ${type} dialog did not close`).toHaveCount(0).catch(async (e) => { await noFieldErrors(type); throw e; });
      await expect(page.locator(".prow .main", { hasText: name })).toBeVisible();
    };
    // Valid input that must be accepted: Cyrillic name with a space, an IPv6 address.
    await add("Мой прокси 1", "socks5", `[::1]:${fx.socks.split(":").pop()}`);
    await add("HTTP тест", "http", fx.http);

    // Edit: rename the HTTP proxy.
    const row = page.locator(".prow", { hasText: "HTTP тест" });
    await row.click();
    await row.locator('[data-act="proxy-edit"]').click();
    await dlg().locator("#p-name").fill("HTTP тест 2");
    await dlg().locator('button[type="submit"]').click();
    await expect(dlg()).toHaveCount(0);
    await expect(page.locator(".prow .main", { hasText: "HTTP тест 2" })).toBeVisible();

    // Delete it again (confirm dialog).
    const row2 = page.locator(".prow", { hasText: "HTTP тест 2" });
    await row2.click();
    await row2.locator('[data-act="proxy-del"]').click();
    await expect(dlg()).toBeVisible();
    await screens("dialog-confirm");
    await dlg().locator('button[type="submit"]').click();
    await expect(page.locator(".prow .main", { hasText: "HTTP тест 2" })).toHaveCount(0);
  });

  // Switching away from «Подписка» left the subscription URL in the draft,
  // and every save failed with «не удалось прочитать запрос».
  test("a proxy saves after switching away from «Подписка»", async () => {
    await nav("proxies");
    await page.locator('[data-act="proxy-add"]').first().click();
    await dlg().locator('[data-act="ptype"][data-value="sub"]').click();
    await dlg().locator("#p-suburl").fill("https://sub.example.invalid/sub/x");
    await dlg().locator('[data-act="ptype"][data-value="socks5"]').click();
    await dlg().locator("#p-name").fill("После подписки");
    await dlg().locator("#p-addr").fill(fx.socks);
    await dlg().locator('button[type="submit"]').click();
    await expect(dlg(), "the dialog did not close").toHaveCount(0);
    await expect(page.locator(".prow .main", { hasText: "После подписки" })).toBeVisible();
    await expect.poll(() => readConfig().proxies.map((p: any) => p.name), { message: "config.json has no new proxy" }).toContain("После подписки");
    const row = page.locator(".prow", { hasText: "После подписки" });
    await row.click();
    await row.locator('[data-act="proxy-del"]').click();
    await dlg().locator('button[type="submit"]').click();
    await expect(page.locator(".prow .main", { hasText: "После подписки" })).toHaveCount(0);
  });

  test("paste a vless:// link and parse it", async () => {
    await nav("proxies");
    await page.locator('[data-act="proxy-add"]').first().click();
    await dlg().locator('[data-act="ptype"][data-value="vless"]').click();
    await dlg().locator("#p-link").fill(fx.plainLink);
    await dlg().locator('[data-act="parse-link"]').click();
    await expect(dlg().locator("#v-net")).toHaveValue("xhttp");
    await expect(dlg().locator("#v-sec")).toHaveValue("reality");
    expect(await dlg().locator("#v-uuid").inputValue()).toMatch(/^[0-9a-f-]{36}$/);
    await dlg().locator("#p-name").fill("VLESS тест");
    await noFieldErrors("vless parse");
    await dlg().locator('button[type="submit"]').click();
    await expect(dlg()).toHaveCount(0);
    await expect(page.locator(".prow .main", { hasText: "VLESS тест" })).toBeVisible();

    // The clipboard button: put the RAW link on the clipboard first.
    const ctx = page.context();
    await ctx.grantPermissions(["clipboard-read", "clipboard-write"]).catch(() => {});
    await page.evaluate((l) => navigator.clipboard.writeText(l).catch(() => {}), fx.rawLink);
    await page.locator('[data-act="paste-vless"]').click();
    // The dialog opens only after the clipboard read resolves.
    const opened = await dlg().waitFor({ state: "visible", timeout: 5000 }).then(() => true, () => false);
    if (opened) {
      await screens("dialog-paste-vless");
      const link = await dlg().locator("#p-link").inputValue().catch(() => "");
      if (!link.startsWith("vless://")) findings.push({ kind: "clipboard", text: "«Вставить vless://» opened the dialog without the link from the clipboard" });
      await closeDialog();
    } else {
      findings.push({ kind: "clipboard", text: "«Вставить vless://» did nothing with a vless link on the clipboard" });
    }
  });

  test("add and refresh a 3x-ui subscription", async () => {
    await nav("proxies");
    await page.locator('[data-act="proxy-add"]').first().click();
    await dlg().locator('[data-act="ptype"][data-value="sub"]').click();
    await dlg().locator("#p-name").fill("Подписка e2e");
    await dlg().locator("#p-suburl").fill(fx.subURL);
    await dlg().locator('button[type="submit"]').click();
    // On a refusal, say why: the dialog's error text, a screenshot, and
    // what the subscription server saw.
    await expect(dlg()).toHaveCount(0, { timeout: 30_000 }).catch(async (e) => {
      await page.screenshot({ path: shotPath("fail-subscription") }).catch(() => {});
      const why = (await page.locator("#modal .field-err").allInnerTexts().catch(() => [])).join(" | ");
      let hits = "";
      try { hits = await (await fetch("http://127.0.0.1:19999/hits")).text(); } catch { /* no control API */ }
      throw new Error(`the subscription dialog stayed open: "${why}"; server hits: ${hits.slice(0, 600)}; ${e}`);
    });
    const row = page.locator(".prow", { hasText: "Подписка e2e" });
    await expect(row).toBeVisible();
    await expect(row).toContainText(/2 сервера/);
    await expect(row).toContainText(/XHTTP/);
    await screens("page-proxies-subscription");
    // Refresh from the row menu.
    await row.locator('[data-act="menu-proxy"]').click();
    await expect(page.locator("#menu")).toBeVisible();
    await screens("menu-proxy");
    await page.locator('#menu [data-menu="sub-refresh"]').click();
    await toast(/Подписка обновлена/);
  });

  test("apps: add a rule, route, switch, dialogs, delete", async () => {
    await nav("rules");
    await page.locator('[data-act="ap-add"]').first().click();
    await expect(dlg()).toBeVisible();
    await screens("dialog-ap-add");
    // The exe found for a typed name and a picked app stay in the path
    // field: a redraw used to put the old field contents back. The test
    // servers run for this whole step, and unlike a WebView2 helper they
    // are never filtered out as a background process. The copied client is
    // not running here, so it would not be listed.
    const pathField = dlg().locator("#ap-add-path");
    await dlg().locator("#ap-add-q").fill("ashgate-e2e-servers");
    await expect(pathField, "the path found for the name was dropped").toHaveValue(/ashgate-e2e-servers\.exe$/i);
    const chip = dlg().locator('[data-act="ap-pick"]').first();
    await expect(chip).toBeVisible();
    const chipPath = (await chip.getAttribute("data-path")) || "";
    await pathField.fill("");
    await chip.click();
    await expect(pathField, "a picked app did not fill the path").toHaveValue(chipPath);
    await typeKept(pathField, CLIENT);
    const route = dlg().locator("#ap-add-route");
    const value = await route.locator("option", { hasText: "Подписка e2e" }).first().getAttribute("value");
    await route.selectOption(value || "");
    await dlg().locator('button[type="submit"]').click();
    await expect(dlg()).toHaveCount(0);
    const card = page.locator(".ap-card", { hasText: "ashgate-e2e-client" });
    await expect(card).toBeVisible();

    // A second rule so grouping can be tried.
    await page.locator('[data-act="ap-add"]').first().click();
    await expect(dlg()).toBeVisible();
    await typeKept(dlg().locator("#ap-add-path"), "C:\\Windows\\System32\\curl.exe");
    await dlg().locator('button[type="submit"]').click();
    await expect(dlg()).toHaveCount(0);
    await expect(page.locator(".ap-card", { hasText: "curl" })).toBeVisible();

    // Switch off and on.
    const sw = card.locator('[data-act="ap-toggle"]');
    await sw.click();
    await expect(card).toHaveClass(/dim/);
    await sw.click();
    await expect(card).not.toHaveClass(/dim/);

    // Route popover.
    await card.locator('[data-act="ap-route"]').click();
    await screens("popover-route");
    await page.keyboard.press("Escape");
    await page.mouse.click(5, 300);

    // Row menu, then the edit dialog.
    await card.locator('[data-act="ap-menu"]').click();
    await screens("menu-app");
    const edit = page.locator('[data-act="ap-edit"]').first();
    if (await edit.isVisible()) {
      await edit.click();
      await expect(dlg()).toBeVisible();
      await screens("dialog-ap-edit");
      await closeDialog();
    }

    // From windows.
    await page.locator('[data-act="ap-windows"]').first().click();
    await expect(dlg()).toBeVisible();
    await screens("dialog-ap-windows");
    await closeDialog();

    // Group: select both rules, name the group, rename it.
    for (const c of await page.locator('.ap-card [data-act="ap-select"]').all()) await c.click();
    const gnew = page.locator('[data-act="ap-group-new"]').first();
    if (await gnew.isVisible()) {
      await gnew.click();
      await expect(dlg()).toBeVisible();
      await screens("dialog-ap-group");
      // A preset fills the name (a redraw used to clear it again).
      await dlg().locator('[data-act="ap-gnew-preset"]', { hasText: "Мессенджеры" }).click();
      await expect(dlg().locator("#ap-gnew-name"), "a preset did not fill the group name").toHaveValue("Мессенджеры");
      await dlg().locator("#ap-gnew-name").fill("Группа e2e");
      await dlg().locator('button[type="submit"]').click();
      await expect(dlg()).toHaveCount(0);
        const rename = page.locator('[data-act="ap-grename"]').first();
      if (!(await rename.isVisible())) await page.locator('.ap-card.group [data-act="ap-menu"]').first().click().catch(() => {});
      if (await page.locator('[data-act="ap-grename"]').first().isVisible().catch(() => false)) {
        await page.locator('[data-act="ap-grename"]').first().click();
        await screens("dialog-ap-gname");
        await closeDialog();
      }
      // Renaming closed the group menu: open it again to ungroup.
      if (!(await page.locator('[data-act="ap-gsplit"]').first().isVisible().catch(() => false))) {
        await page.locator('.ap-card.group [data-act="ap-menu"]').first().click().catch(() => {});
      }
      await page.locator('[data-act="ap-gsplit"]').first().click().catch(() => {});
      } else {
      findings.push({ kind: "groups", text: "no «group» button after selecting two rules" });
    }

    // Delete the curl rule (no confirmation by design).
    // Not the group card, which also contains the curl rule if ungrouping failed.
    const curl = page.locator(".ap-card:not(.group)", { hasText: "curl" });
    await curl.locator('[data-act="ap-menu"]').click();
    await page.locator('[data-act="ap-del"]').first().click();
    await expect(page.locator(".ap-card", { hasText: "curl" })).toHaveCount(0);
    await screens("page-rules-filled");
  });

  // A companion is a process whose traffic follows the rule although it is
  // not the rule's own exe. The drawer and the dialog are the only ways to
  // see and change it, and the config must keep it across a restart.
  test("companions: attach, drawer, radar, remove", async () => {
    await nav("rules");
    const consoleBefore = app.problems.length;

    // Open from the rule menu.
    await openCompanions();
    await screens("dialog-ap-companions");

    // «Засечь новый трафик» starts and stops the measurement in place.
    const radar = dlg().locator('button[data-act="ap-radar-capture"]');
    await expect(radar).toContainText("Засечь новый трафик");
    await radar.click();
    await expect(radar).toContainText("Остановить замер");
    await expect(radar).toHaveClass(/ap-capture-on/);
    await radar.click();
    await expect(radar).toContainText("Засечь новый трафик");

    // Attach a path by hand; it appears in the attached list at once.
    await addCompanion(COMPANION);
    await closeDialog();

    // The rule shows a collapsed pill; expanding lists the companion.
    const unit = clientUnit();
    const pill = unit.locator('[data-act="ap-sub-toggle"]');
    await expect(pill, "the rule has no companion pill").toContainText("+1 процесс");
    await expect(unit.locator(".ap-sublist"), "the drawer starts open").toHaveCount(0);
    await pill.click();
    const sub = unit.locator(".ap-sublist");
    await expect(sub).toBeVisible();
    const row = sub.locator(".ap-sub-row", { hasText: "Ld9BoxHeadless" });
    await expect(row.locator(".ap-origin"), "the drawer row is not marked «привязан»").toHaveText("привязан");
    await screens("rules-companion-open");

    // Collapse it again.
    await pill.click();
    await expect(unit.locator(".ap-sublist")).toHaveCount(0);
    await expect(pill).not.toHaveClass(/\bopen\b/);

    // Remove it from the drawer with «×».
    await pill.click();
    await expect(unit.locator(".ap-sublist")).toBeVisible();
    await unit.locator(".ap-sub-row", { hasText: "Ld9BoxHeadless" })
      .locator('button[data-act="ap-sub-remove"]').click();
    await companionGone(COMPANION);
    await expect(unit.locator('[data-act="ap-sub-toggle"]'), "the pill stayed after the companion was removed").toHaveCount(0);
    await expect(unit.locator(".ap-sublist")).toHaveCount(0);

    // Attach and remove it from the dialog too.
    await openCompanions();
    await addCompanion(COMPANION);
    await dlg().locator('.ap-comp-item [data-act="ap-comp-del"]').first().click();
    await companionGone(COMPANION);
    await expect(dlg().locator(".ap-none", { hasText: "Пока нет привязанных процессов" })).toBeVisible();
    await closeDialog();

    // Leave one attached for the restart check, collapsed.
    await openCompanions();
    await addCompanion(COMPANION);
    await closeDialog();
    const pill2 = clientUnit().locator('[data-act="ap-sub-toggle"]');
    await expect(pill2).toContainText("+1 процесс");
    if (await clientUnit().locator(".ap-sublist").count()) await pill2.click();
    await expect(clientUnit().locator(".ap-sublist")).toHaveCount(0);

    expect(app.problems.slice(consoleBefore), "console errors while driving the companions dialog").toEqual([]);
  });

  // There is no manual priority any more: a card's place is its real state
  // (traffic, running and waiting, not running), and every menu is a portal
  // popover on <body>, fixed and opaque above the cards.
  test("apps: tiers, portal menu, no priority controls, process tree", async () => {
    await nav("rules");
    const consoleBefore = app.problems.length;
    const PRIORITY = ['[data-act="ap-up"]', '[data-act="ap-down"]', '[data-act="ap-gup"]', '[data-act="ap-gdown"]'].join(",");

    // The test servers run for the whole UI run; the copied client does not.
    // One rule is «running and waiting», the other «not running», and the
    // waiting one must sort above it with no timer and no priority setting.
    await page.locator('[data-act="ap-add"]').first().click();
    await expect(dlg()).toBeVisible();
    await dlg().locator("#ap-add-q").fill("ashgate-e2e-servers");
    await expect(dlg().locator("#ap-add-path"), "the path found for the name was dropped").toHaveValue(/ashgate-e2e-servers\.exe$/i);
    const route = dlg().locator("#ap-add-route");
    const value = await route.locator("option", { hasText: "Подписка e2e" }).first().getAttribute("value");
    await route.selectOption(value || "");
    await dlg().locator('button[type="submit"]').click();
    await expect(dlg()).toHaveCount(0);
    const servers = ruleUnit("ashgate-e2e-servers");
    await expect(servers.locator(".ap-card").first()).toBeVisible();
    await expectAbove("ashgate-e2e-servers", "ashgate-e2e-client", "a running app must sort above a stopped one");

    // No manual priority anywhere: no move buttons, nothing draggable, no
    // «сверху вниз» / «Перетащите карточку» text.
    expect(await page.locator(PRIORITY).count(), "priority buttons are back on the Apps page").toBe(0);
    expect(await page.locator('#page [draggable="true"]').count(), "cards are draggable again").toBe(0);
    const pageText = (await page.locator("#page").innerText()).toLowerCase();
    expect(pageText).not.toContain("сверху вниз");
    expect(pageText).not.toContain("перетащите карточку");
    await expect(page.locator("#page .ap-pop"), "a popover is rendered inside the page again").toHaveCount(0);

    // The rule menu: fixed, opaque, in #ap-portal, and it wins the hit test
    // over the card that sits underneath it. The taller window gives the
    // menu room below its card; «every page renders» put it back anyway.
    await page.setViewportSize({ width: 1100, height: 1000 });
    const menu = await openRuleMenu(servers.locator(".ap-card").first());
    await page.waitForTimeout(300); // the 120 ms opening animation
    const look = await menu.evaluate((el) => {
      const cs = getComputedStyle(el);
      const r = el.getBoundingClientRect();
      const m = /^rgba?\(([^)]+)\)$/.exec(cs.backgroundColor);
      const parts = m ? m[1].split(/[ ,/]+/).filter(Boolean) : [];
      const at = (x: number, y: number) => {
        const h = document.elementFromPoint(x, y);
        return h ? { portal: !!h.closest("#ap-portal"), card: !!h.closest(".ap-card"), tag: h.tagName } : null;
      };
      const cx = r.left + r.width / 2;
      return {
        inPortal: !!el.closest("#ap-portal"), inPage: !!el.closest("#page"),
        position: cs.position, zIndex: Number(cs.zIndex), opacity: Number(cs.opacity),
        alpha: parts.length >= 4 ? Number(parts[3]) : 1, bg: cs.backgroundColor,
        center: at(cx, r.top + r.height / 2), bottom: at(cx, r.bottom - 3),
      };
    });
    expect(look.inPortal, "the menu is not inside #ap-portal").toBe(true);
    expect(look.inPage, "the menu is still inside #page").toBe(false);
    expect(look.position, "the menu is not position:fixed").toBe("fixed");
    expect(look.zIndex, "the menu is below the cards").toBeGreaterThanOrEqual(60);
    expect(look.opacity, "the menu is translucent").toBe(1);
    expect(look.alpha, `the menu background ${look.bg} is not opaque`).toBe(1);
    expect(look.center?.portal, "a click in the middle of the menu hits something else").toBe(true);
    expect(look.bottom?.portal, "the bottom edge of the menu does not hit the menu").toBe(true);

    // The next card sits under the menu, and the menu must win the hit test
    // there: the card behind it must not intercept the click.
    const under = await page.evaluate(() => {
      const pop = document.querySelector("#ap-portal .ap-pop.menu");
      const pr = pop!.getBoundingClientRect();
      let best: { h: number; x: number; y: number; name: string } | null = null;
      for (const c of Array.from(document.querySelectorAll('[data-ap-list="active"] .ap-card'))) {
        const r = c.getBoundingClientRect();
        const top = Math.max(pr.top, r.top);
        const bottom = Math.min(pr.bottom, r.bottom);
        const h = bottom - top;
        if (h < 8) continue;
        if (best && h <= best.h) continue;
        const x = Math.min(pr.right - 4, Math.max(pr.left, r.left) + 24);
        best = { h, x, y: top + Math.min(20, h / 2), name: (c.textContent || "").replace(/\s+/g, " ").slice(0, 40) };
      }
      return best;
    });
    expect(under, "the open menu covers no card: the overlap cannot be checked").not.toBeNull();
    const hit = await page.evaluate(({ x, y }) => {
      const h = document.elementFromPoint(x, y);
      return h ? { portal: !!h.closest("#ap-portal"), card: !!h.closest(".ap-card"), tag: h.tagName } : null;
    }, { x: (under as any).x, y: (under as any).y });
    expect(hit?.portal, `the card «${(under as any).name}» behind the menu wins the hit test (${JSON.stringify(hit)})`).toBe(true);
    expect(hit?.card).toBe(false);

    // No priority items inside the rule menu either.
    expect(await menu.locator(PRIORITY).count()).toBe(0);
    expect(await menu.locator('[draggable="true"]').count()).toBe(0);
    expect((await menu.innerText()).toLowerCase()).not.toContain("сверху вниз");

    // A telemetry tick must not rebuild the open menu (that replays its
    // animation and swallows clicks).
    await menu.evaluate((el) => { (el as any).__keep = "menu"; });
    await page.waitForTimeout(1200); // at least two state polls
    expect(await menu.evaluate((el) => (el as any).__keep), "the open menu was rebuilt by a telemetry tick").toBe("menu");
    await page.keyboard.press("Escape");
    await expect(page.locator("#ap-portal"), "Escape did not close the rule menu").toBeHidden();
    await page.setViewportSize({ width: SIZES[0][0], height: SIZES[0][1] });

    // The group menu is the same portal popover and has no priority items.
    for (const c of await page.locator('.ap-card [data-act="ap-select"]').all()) await c.click();
    const gnew = page.locator('[data-act="ap-group-new"]').first();
    await expect(gnew, "no «group» button after selecting two rules").toBeVisible();
    await gnew.click();
    await expect(dlg()).toBeVisible();
    await dlg().locator("#ap-gnew-name").fill("Группа портала");
    await dlg().locator('button[type="submit"]').click();
    await expect(dlg()).toHaveCount(0);
    const gcard = page.locator(".ap-card.group", { hasText: "Группа портала" });
    await expect(gcard).toBeVisible();
    const gmenu = await openRuleMenu(gcard);
    expect(await gmenu.locator(PRIORITY).count(), "priority buttons in the group menu").toBe(0);
    expect(await gmenu.locator('[draggable="true"]').count()).toBe(0);
    expect((await gmenu.innerText()).toLowerCase()).not.toContain("сверху вниз");
    await gmenu.locator('[data-act="ap-gsplit"]').click();
    await expect(page.locator(".ap-card.group", { hasText: "Группа портала" })).toHaveCount(0);

    // The drawer is a compact process tree: guides, the saved companion
    // marked «привязан», and its «×» to unbind it.
    const unit = clientUnit();
    const pill = unit.locator('[data-act="ap-sub-toggle"]');
    await expect(pill, "the client rule has no companion pill").toContainText("+1 процесс");
    await pill.click();
    const sub = unit.locator(".ap-sublist");
    await expect(sub).toBeVisible();
    const row = sub.locator(".ap-sub-row", { hasText: "Ld9BoxHeadless" });
    await expect(row.locator(".ap-origin"), "the drawer row is not marked «привязан»").toHaveText("привязан");
    expect(await row.locator(".ap-tree-guides .ap-tc").count(), "the drawer row has no tree guides").toBeGreaterThan(0);
    await expect(row.locator('button[data-act="ap-sub-remove"]'), "the drawer row has no «×»").toBeVisible();
    // One live process gets no count chip.
    await expect(row.locator(".ap-sub-cnt")).toHaveCount(0);
    await screens("rules-portal-tree");
    await pill.click();
    await expect(unit.locator(".ap-sublist")).toHaveCount(0);

    expect(app.problems.slice(consoleBefore), "console errors on the Apps page").toEqual([]);
  });

  test("settings change and save", async () => {
    await nav("settings");
    const toggle = (k: string) => page.locator(`button.toggle[data-act="toggle"][data-key="${k}"]`);
    for (const k of ["kill", "bypass", "verbose"]) {
      const on = (await toggle(k).getAttribute("aria-pressed")) === "true";
      await toggle(k).click();
      await expect(toggle(k)).toHaveAttribute("aria-pressed", on ? "false" : "true");
    }
    await page.locator('[data-act="seg"][data-key="udp"][data-value="direct"]').click();
    await page.locator("#dns-servers").fill("1.1.1.1:53, 9.9.9.9:53");
    await page.locator("#dns-servers").press("Tab");
    const dd = page.locator("#direct-domains");
    await dd.fill((await dd.inputValue()) + "\ne2e-ui.example");
    await dd.press("Tab");
    await toggle("auto").click();
    await page.waitForTimeout(2500); // settings save 400 ms after the last change
    const c = readConfig();
    expect(c.dns.servers).toEqual(["1.1.1.1:53", "9.9.9.9:53"]);
    expect(c.udpUnsupported).toBe("direct");
    expect(c.directDomains).toContain("e2e-ui.example");
    expect(c.log.level).toBe("debug");
    await screens("page-settings-changed");
  });

  // Leaving Settings by a tab click: its mousedown ends the edit, and the
  // save used to be dropped because the page was no longer Settings.
  test("settings typed before a tab click are saved", async () => {
    await nav("settings");
    const dns = page.locator("#dns-servers");
    await dns.fill("1.0.0.1:53, 9.9.9.9:53");
    await page.locator('[data-nav="rules"]').click();
    await expect.poll(() => readConfig().dns.servers, { timeout: 5000, message: "the DNS servers typed before the tab click were not saved" })
      .toEqual(["1.0.0.1:53", "9.9.9.9:53"]);
    await nav("settings");
    await expect(dns).toHaveValue("1.0.0.1:53, 9.9.9.9:53");
    // Put back what the restart test expects.
    await dns.fill("1.1.1.1:53, 9.9.9.9:53");
    await page.locator('[data-nav="proxies"]').click();
    await expect.poll(() => readConfig().dns.servers, { timeout: 5000 }).toEqual(["1.1.1.1:53", "9.9.9.9:53"]);
  });

  test("log page tools", async () => {
    await nav("log");
    await page.locator("#log-filter").fill("ashgate");
    await page.locator('#log-seg [data-act="proto"][data-value="TCP"]').click();
    await page.locator('#pause-btn').click();
    await page.locator('#pause-btn').click();
    await page.locator('[data-act="clear"]').click();
    await expect(dlg()).toBeVisible();
    await closeDialog();
    await page.locator("#log-filter").fill("");
  });

  // «Без правила» swaps the live feed for the programs bypassing the rules;
  // its extra strip and chip buttons must not spill or log errors.
  test("log: «Без правила» mode", async () => {
    await nav("log");
    const consoleBefore = app.problems.length;
    const btn = page.locator("#log-unmatched-btn");
    await expect(btn).toBeVisible();
    await btn.click();
    await expect(btn).toHaveClass(/\bon\b/);
    await expect(page.locator('[data-act="clear"]')).toContainText("Очистить ленту");
    await screens("page-log-unmatched");
    await btn.click();
    await expect(btn).not.toHaveClass(/\bon\b/);
    await expect(page.locator('[data-act="clear"]')).toContainText("Очистить экран");
    await screens("page-log");
    expect(app.problems.slice(consoleBefore), "console errors in «Без правила»").toEqual([]);
  });

  test("start and stop capture", async () => {
    await nav("rules");
    await page.locator("#side-power").click();
    const alert = dlg();
    const run = page.locator(".side-card.run");
    await expect(run.or(alert)).toBeVisible({ timeout: 30_000 });
    if (await alert.count()) {
      await screens("dialog-alert-start");
      const text = await alert.innerText();
      await alert.locator('button[type="submit"]').click();
      throw new Error("capture did not start: " + text.replace(/\s+/g, " "));
    }
    await screens("page-rules-running");
    // With capture on, the running app waits for incoming traffic and its
    // card says so; the stopped app says it is not running, and the waiting
    // one sorts above it: the three-tier order, judged by real state.
    await expect(ruleUnit("ashgate-e2e-servers").locator(".ap-tele"), "a running app without traffic must say it waits")
      .toContainText("Ждёт входящий трафик", { timeout: 30_000 });
    await expect(ruleUnit("ashgate-e2e-client").locator(".ap-tele"), "a stopped app must say it is not running")
      .toContainText("Не запущено");
    await expectAbove("ashgate-e2e-servers", "ashgate-e2e-client", "the waiting app must stay above the stopped one");

    // A group with a waiting app in it waits too.
    for (const c of await page.locator('.ap-card [data-act="ap-select"]').all()) await c.click();
    const gnew = page.locator('[data-act="ap-group-new"]').first();
    await expect(gnew, "no «group» button after selecting two rules").toBeVisible();
    await gnew.click();
    await expect(dlg()).toBeVisible();
    await dlg().locator("#ap-gnew-name").fill("Ждущие e2e");
    await dlg().locator('button[type="submit"]').click();
    await expect(dlg()).toHaveCount(0);
    const gcard = page.locator(".ap-card.group", { hasText: "Ждущие e2e" });
    await expect(gcard.locator(".ap-tele"), "a group of a waiting app must say it waits").toContainText("Ждёт входящий трафик");
    // Put the list back for the restart check.
    const gmenu = await openRuleMenu(gcard);
    await gmenu.locator('[data-act="ap-gsplit"]').click();
    await expect(gcard, "the group was not split again").toHaveCount(0);

    await page.locator("#side-power").click();
    await expect(page.locator(".side-card.run")).toHaveCount(0, { timeout: 20_000 });
  });

  test("buttons all do something", async () => {
    for (const id of ["proxies", "rules", "log", "settings"] as const) {
      await nav(id);
      await liveness("#page", id);
    }
    await liveness("#nav", "nav");
  });

  test("close hides to the tray; a second launch brings it back", async () => {
    // WebView2 keeps document.visibilityState "visible" when its host window
    // is hidden, so ask the app: /api/state says hidden while in the tray.
    const hidden = () => page.evaluate(async () => {
      const r = await fetch("/api/state", { headers: { "X-Ashgate-Token": (window as any).__ashgateToken } });
      return !!(await r.json()).hidden;
    });
    await page.locator("#win-close").click();
    await expect.poll(hidden, { timeout: 10_000, message: "the window did not hide to the tray" }).toBe(true);
    desktop("desktop-tray");
    const { execFileSync } = await import("node:child_process");
    try { execFileSync(path.join(process.env.ProgramFiles || "C:\\Program Files", "Ashgate", "ashgate.exe"), [], { timeout: 20_000 }); } catch { /* the second copy exits */ }
    await expect.poll(hidden, { timeout: 15_000, message: "a second launch did not bring the window back" }).toBe(false);
    desktop("desktop-restored");
  });

  test("everything persists after a restart", async () => {
    const before = readConfig();
    await app.quit();
    app = await App.launch();
    page = app.page;
    await nav("proxies");
    for (const name of ["Мой прокси 1", "VLESS тест", "Подписка e2e"]) {
      await expect(page.locator(".prow .main", { hasText: name })).toBeVisible();
    }
    await nav("rules");
    await expect(page.locator(".ap-card", { hasText: "ashgate-e2e-client" })).toBeVisible();
    // The companion attached in the previous test is still there, in the
    // config and on the rule.
    const saved = readConfig().rules.find((r: any) => /ashgate-e2e-client/i.test(String(r.process)));
    expect(saved?.companions || [], "the companion did not survive the restart").toContain(COMPANION);
    await expect(clientUnit().locator('[data-act="ap-sub-toggle"]'), "the companion pill did not survive the restart")
      .toContainText("+1 процесс");
    await nav("settings");
    await expect(page.locator('button.toggle[data-key="verbose"]')).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator('button.toggle[data-key="auto"]')).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator("#dns-servers")).toHaveValue("1.1.1.1:53, 9.9.9.9:53");
    const after = readConfig();
    expect(after.proxies.map((p: any) => p.name)).toEqual(before.proxies.map((p: any) => p.name));
    expect(after.rules.length).toBe(before.rules.length);
    // Leave the machine as found: autostart off.
    await page.locator('button.toggle[data-key="auto"]').click();
    await page.waitForTimeout(1500);
  });

  test("no console errors, layout problems or dead buttons", async () => {
    fs.mkdirSync(path.join(OUT, "ui"), { recursive: true });
    fs.writeFileSync(path.join(OUT, "ui", "findings.json"), JSON.stringify({ findings, problems: app.problems }, null, 2));
    const report = [...app.problems, ...findings].map((p) => `${p.kind}: ${p.text}${p.where ? " (" + p.where + ")" : ""}`);
    expect(report, "UI problems").toEqual([]);
  });
});

export {};
