// End-to-end UI tests of the real Ashgate window (WebView2) on the Windows
// runner. One app instance is driven through every page, dialog and main
// flow; then it is restarted and everything must still be there.
import { test, expect, type Page } from "@playwright/test";
import * as fs from "node:fs";
import * as path from "node:path";
import { App, OUT, cleanupPolicy, desktop, fixtures, readConfig, type Problem } from "./app";

const fx = fixtures();
const CLIENT = "C:\\ashgate-e2e\\apps\\ashgate-e2e-client.exe";
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

async function toast(re: RegExp) {
  await expect(page.locator("#toast")).toBeVisible();
  await expect(page.locator("#toast")).toHaveText(re);
}

// liveness clicks every visible button in scope and checks that each one
// does something: a DOM change, a request, a dialog, a menu or a toast.
async function liveness(scope: string, label: string) {
  const skip = [
    "#side-power", "#win-min", "#win-max", "#win-close", "[data-nav]",
    '[data-act="open-folder"]', '[data-act="update-open"]', '[data-act="ap-browse"]',
    '[data-act="paste-vless"]', '[data-act="proxy-del"]', '[data-act="ap-del"]',
  ].join(",");
  const buttons = page.locator(`${scope} button:visible`);
  const n = await buttons.count();
  for (let i = 0; i < n; i++) {
    const b = buttons.nth(i);
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
    const opened = (await dlg().count()) > 0 || (await page.locator("#menu:visible").count()) > 0 || (await page.locator("#toast:visible").count()) > 0;
    if (mut === 0 && requests - stateReqs.length === 0 && !opened) {
      findings.push({ kind: "button does nothing", text: name, where: label });
    }
    // Undo: close what opened, flip switches back.
    if (await dlg().count()) await closeDialog();
    if (await page.locator("#menu:visible").count()) await page.keyboard.press("Escape");
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
    if (await dlg().count()) {
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
    await expect(dlg()).toHaveCount(0, { timeout: 30_000 });
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
    await dlg().locator("#ap-add-path").fill(CLIENT);
    const route = dlg().locator("#ap-add-route");
    const value = await route.locator("option", { hasText: "Подписка e2e" }).first().getAttribute("value");
    await route.selectOption(value || "");
    await dlg().locator('button[type="submit"]').click();
    await expect(dlg()).toHaveCount(0);
    // Rules are saved with the dirty bar.
    if (await page.locator('[data-act="rules-save"]').isVisible().catch(() => false)) {
      await page.locator('[data-act="rules-save"]').click();
    }
    const card = page.locator(".ap-card", { hasText: "ashgate-e2e-client" });
    await expect(card).toBeVisible();

    // A second rule so grouping can be tried.
    await page.locator('[data-act="ap-add"]').first().click();
    await dlg().locator("#ap-add-path").fill("C:\\Windows\\System32\\curl.exe");
    await dlg().locator('button[type="submit"]').click();
    if (await page.locator('[data-act="rules-save"]').isVisible().catch(() => false)) await page.locator('[data-act="rules-save"]').click();
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
      await dlg().locator("#ap-gnew-name").fill("Группа e2e");
      await dlg().locator('button[type="submit"]').click();
      await expect(dlg()).toHaveCount(0);
      if (await page.locator('[data-act="rules-save"]').isVisible().catch(() => false)) await page.locator('[data-act="rules-save"]').click();
      const rename = page.locator('[data-act="ap-grename"]').first();
      if (!(await rename.isVisible())) await page.locator('.ap-card.group [data-act="ap-menu"]').first().click().catch(() => {});
      if (await page.locator('[data-act="ap-grename"]').first().isVisible().catch(() => false)) {
        await page.locator('[data-act="ap-grename"]').first().click();
        await screens("dialog-ap-gname");
        await closeDialog();
      }
      await page.locator('[data-act="ap-gsplit"]').first().click().catch(() => {});
      if (await page.locator('[data-act="rules-save"]').isVisible().catch(() => false)) await page.locator('[data-act="rules-save"]').click();
    } else {
      findings.push({ kind: "groups", text: "no «group» button after selecting two rules" });
    }

    // Delete the curl rule (no confirmation by design).
    const curl = page.locator(".ap-card", { hasText: "curl" });
    await curl.locator('[data-act="ap-menu"]').click();
    await page.locator('[data-act="ap-del"]').first().click();
    if (await page.locator('[data-act="rules-save"]').isVisible().catch(() => false)) await page.locator('[data-act="rules-save"]').click();
    await expect(page.locator(".ap-card", { hasText: "curl" })).toHaveCount(0);
    await screens("page-rules-filled");
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

  test("log page tools", async () => {
    await nav("log");
    await page.locator("#log-filter").fill("ashgate");
    await page.locator('#log-seg [data-act="proto"][data-value="TCP"]').click();
    await page.locator('[data-act="pause"]').click();
    await page.locator('[data-act="pause"]').click();
    await page.locator('[data-act="clear"]').click();
    await expect(dlg()).toBeVisible();
    await closeDialog();
    await page.locator("#log-filter").fill("");
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
    await page.locator("#win-close").click();
    await page.waitForTimeout(1500);
    desktop("desktop-tray");
    const hidden = await page.evaluate(() => document.visibilityState);
    expect(hidden, "the window did not hide").toBe("hidden");
    const { execFileSync } = await import("node:child_process");
    try { execFileSync(path.join(process.env.ProgramFiles || "C:\\Program Files", "Ashgate", "ashgate.exe"), [], { timeout: 20_000 }); } catch { /* the second copy exits */ }
    await expect.poll(() => page.evaluate(() => document.visibilityState), { timeout: 15_000 }).toBe("visible");
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
