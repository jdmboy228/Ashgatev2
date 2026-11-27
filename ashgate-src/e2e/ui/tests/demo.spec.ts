// Browser-level checks of the Apps page in demo mode (index.html?demo=1),
// with the state injected by the test. CI downloads no browser
// (PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD), so these run only where one is
// installed:
//
//   ASHGATE_DEMO_UI=1 npx playwright test demo.spec.ts
//
// ASHGATE_DEMO_BROWSER picks the browser channel (default msedge).
//
// They cover what the WebView2 run cannot make deterministic: the three
// traffic tiers, the 2.5 s pause hysteresis, DOM-node reuse when a card
// changes tier, the portal popover, and the folded service shells.
import { test, expect, chromium, type Browser, type Page } from "@playwright/test";
import * as fs from "node:fs";
import * as http from "node:http";
import * as path from "node:path";

const ENABLED = process.env.ASHGATE_DEMO_UI === "1";
const CHANNEL = process.env.ASHGATE_DEMO_BROWSER || "msedge";

// Rule keys are what apKey/stableKey use: the process, lower case.
const K = {
  discord: "*\\discord\\app-*\\discord.exe",
  telegram: "c:\\users\\user\\appdata\\roaming\\telegram desktop\\telegram.exe",
  curl: "curl.exe",
  cursor: "cursor.exe",
  spotify: "spotify.exe",
  obs64: "obs64.exe",
};

function uiDir(): string {
  const candidates = [
    path.resolve(__dirname, "..", "..", "..", "internal", "gui", "ui"),
    path.resolve("..", "..", "internal", "gui", "ui"),
    path.resolve("ashgate-src", "internal", "gui", "ui"),
  ];
  for (const c of candidates) if (fs.existsSync(path.join(c, "index.html"))) return c;
  throw new Error("the UI files were not found in: " + candidates.join(", "));
}

// serve serves the UI directory on a free local port.
function serve(root: string): Promise<{ url: string; close: () => void }> {
  const types: Record<string, string> = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png",
  };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url || "/", "http://x");
    const rel = decodeURIComponent(u.pathname === "/" ? "/index.html" : u.pathname);
    const file = path.join(root, rel);
    if (!file.startsWith(root)) { res.writeHead(403).end(); return; }
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404).end(); return; }
      res.writeHead(200, { "content-type": types[path.extname(file)] || "application/octet-stream" });
      res.end(data);
    });
  });
  return new Promise((ok) => srv.listen(0, "127.0.0.1", () => {
    const addr = srv.address() as any;
    ok({ url: `http://127.0.0.1:${addr.port}`, close: () => srv.close() });
  }));
}

// run executes app.js code in the page, where its top-level bindings
// (state, fillApps, apUnits, apRuleTier …) are visible as bare names.
function run<T = any>(page: Page, body: string, arg?: any): Promise<T> {
  return page.evaluate(([src, a]) => (0, eval)(src as string)(a), [body, arg] as [string, any]) as Promise<T>;
}

// tiers lists the active units in display order with their tier.
function tiers(page: Page) {
  return run<{ key: string; tier: number; text: string }[]>(page, `() => {
    const now = Date.now();
    return Array.from(document.querySelectorAll('[data-ap-list="active"] > [data-unit-key]')).map((el) => {
      const key = el.dataset.unitKey;
      const u = apUnits().find((x) => x.stableKey === key);
      return { key, tier: u ? apUnitTier(u, now) : -1, text: (el.textContent || "").replace(/\\s+/g, " ").trim() };
    });
  }`);
}

function ruleTier(page: Page, key: string): Promise<number> {
  return run(page, `(key) => {
    const u = apUnits().find((x) => x.stableKey === "r:" + key);
    return u ? apRuleTier(cfg().rules[u.index], Date.now()) : -1;
  }`, key);
}

test.describe.serial("Apps page in demo mode", () => {
  test.skip(!ENABLED, "set ASHGATE_DEMO_UI=1 and run where a browser is installed");

  let browser: Browser;
  let page: Page;
  let server: { url: string; close: () => void };

  test.beforeAll(async () => {
    server = await serve(uiDir());
    browser = await chromium.launch({ channel: CHANNEL, headless: true });
    page = await browser.newPage({ viewport: { width: 1100, height: 720 } });
    await page.goto(`${server.url}/index.html?demo=1#rules`);
    await page.waitForFunction(() => document.querySelectorAll('[data-ap-list="active"] > [data-unit-key]').length > 0);
  });

  test.afterAll(async () => {
    await browser?.close().catch(() => {});
    server?.close();
  });

  test("three tiers: traffic, waiting, not running", async () => {
    const units = await tiers(page);
    expect(units.length, "the demo page rendered no rules").toBeGreaterThan(0);
    for (let i = 1; i < units.length; i++) {
      expect(units[i].tier, `tier order: ${JSON.stringify(units.map((u) => [u.key, u.tier]))}`)
        .toBeGreaterThanOrEqual(units[i - 1].tier);
    }
    const unit = (s: string) => {
      const u = units.find((x) => x.key.includes(s));
      expect(u, `no unit for ${s}`).toBeTruthy();
      return u!;
    };
    // Discord and Telegram live in one group, so the group carries tier 0.
    const group = unit("g:");
    expect(group.tier, "a group with traffic is not in the first tier").toBe(0);
    expect(group.text).toContain("поток");
    expect(unit(K.curl).tier, "a running app without traffic is not in the waiting tier").toBe(1);
    expect(unit(K.obs64).tier, "a stopped app is not in the last tier").toBe(2);
    expect(unit(K.curl).text, "the waiting card does not say it waits").toContain("Ждёт входящий трафик");
    expect(unit(K.obs64).text, "the stopped card does not say it is not running").toContain("Не запущено");

    // A group with a waiting app says it waits too.
    await run(page, `([d, t]) => {
      apHotUntil.clear();
      state.ruleStats[d] = { flows: 0, up: 0, down: 0, upRate: 0, downRate: 0 };
      state.ruleStats[t] = { flows: 0, up: 0, down: 0, upRate: 0, downRate: 0 };
      fillApps();
    }`, [K.discord, K.telegram]);
    await expect(page.locator('[data-ap-list="active"] [data-unit-key^="g:"] .ap-tele').first())
      .toContainText("Ждёт входящий трафик");
    expect((await tiers(page)).find((u) => u.key.startsWith("g:"))!.tier, "a waiting group is not in the waiting tier").toBe(1);
  });

  test("a short traffic pause holds the card for 2.5 s", async () => {
    await run(page, `(key) => {
      apHotUntil.clear();
      state.alive[key] = true;
      state.ruleStats[key] = { flows: 5, up: 1, down: 2, upRate: 10, downRate: 20 };
      fillApps();
    }`, K.curl);
    expect(await ruleTier(page, K.curl)).toBe(0);

    await run(page, `(key) => {
      state.ruleStats[key] = { flows: 0, up: 1, down: 2, upRate: 0, downRate: 0 };
      fillApps();
    }`, K.curl);
    expect(await ruleTier(page, K.curl), "a brief pause dropped the card at once").toBe(0);
    const order = (await tiers(page)).map((u) => u.key);
    expect(order.indexOf("r:" + K.curl), "the card left the traffic tier during the pause")
      .toBeLessThan(order.indexOf("r:" + K.cursor));

    await page.waitForTimeout(2700);
    expect(await ruleTier(page, K.curl), "the card did not leave the traffic tier after the pause").toBe(1);
  });

  test("an exited app drops to the bottom tier at once, keeping its node", async () => {
    await run(page, `(key) => {
      apHotUntil.clear();
      state.alive[key] = true;
      state.ruleStats[key] = { flows: 3, up: 1, down: 2, upRate: 1, downRate: 1 };
      fillApps();
      document.querySelector('[data-unit-key="r:' + key + '"]').__demoNode = "kept";
    }`, K.curl);

    // The app exits while a draining socket still reports flows > 0:
    // !alive must immediately drop it to tier 2 AND show «Не запущено»
    // instead of stale active traffic text.
    await run(page, `(key) => {
      state.alive[key] = false;
      state.ruleStats[key] = { flows: 2, up: 1, down: 2, upRate: 512, downRate: 1024 };
      fillApps();
    }`, K.curl);
    const after = await run<{ order: string[]; tiers: number[]; mark: string; text: string }>(page, `() => {
      const list = Array.from(document.querySelectorAll('[data-ap-list="active"] > [data-unit-key]'));
      const el = list.find((e) => e.dataset.unitKey === "r:${K.curl}");
      const now = Date.now();
      return {
        order: list.map((e) => e.dataset.unitKey),
        tiers: list.map((e) => { const u = apUnits().find((x) => x.stableKey === e.dataset.unitKey); return u ? apUnitTier(u, now) : -1; }),
        mark: el && el.__demoNode,
        text: el ? el.textContent : "",
      };
    }`);
    expect(after.mark, "the card node was replaced when it changed tier").toBe("kept");
    const idx = after.order.indexOf("r:" + K.curl);
    expect(after.tiers[idx], "the exited app is not in the bottom tier").toBe(2);
    expect(after.text).toContain("Не запущено");
    expect(after.text, "a stopped app must not display stale active flow counts").not.toContain("поток");
    for (let i = 1; i < after.tiers.length; i++) {
      expect(after.tiers[i]).toBeGreaterThanOrEqual(after.tiers[i - 1]);
    }
    // Zero out the draining counter before later tests.
    await run(page, `(key) => {
      state.ruleStats[key] = { flows: 0, up: 1, down: 2, upRate: 0, downRate: 0 };
      fillApps();
    }`, K.curl);
  });

  test("the rule menu is a fixed opaque portal popover above the cards", async () => {
    // Fold the group and give the window room, so the rule's menu opens
    // below its card and over the next one; put both back afterwards.
    const groupCard = page.locator('[data-ap-list="active"] .ap-card.group').first();
    if (await page.locator('[data-ap-list="active"] .ap-card.member').count()) {
      await groupCard.locator('[data-act="ap-collapse"]').click();
      await expect(page.locator('[data-ap-list="active"] .ap-card.member')).toHaveCount(0);
    }
    await page.setViewportSize({ width: 1100, height: 1000 });
    const card = page.locator(`[data-unit-key="r:${K.cursor}"] .ap-card`).first();
    await expect(card).toBeVisible();
    await card.locator('[data-act="ap-menu"]').click();
    const menu = page.locator("#ap-portal .ap-pop.menu");
    await expect(menu).toBeVisible();
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

    // A card sits under the menu: the menu must win the hit test there.
    const under = await page.evaluate(() => {
      const pop = document.querySelector("#ap-portal .ap-pop.menu");
      const pr = pop.getBoundingClientRect();
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

    // A telemetry tick must not rebuild the menu or replay its animation.
    await menu.evaluate((el) => { (el as any).__keep = 1; });
    const anims = await menu.evaluate((el) => el.getAnimations().map((a) => a.startTime));
    await run(page, `() => fillApps()`);
    expect(await menu.evaluate((el) => (el as any).__keep), "the open menu was rebuilt by a tick").toBe(1);
    expect(await menu.evaluate((el) => el.getAnimations().map((a) => a.startTime)), "the opening animation replayed")
      .toEqual(anims);

    await page.keyboard.press("Escape");
    await expect(page.locator("#ap-portal"), "Escape did not close the menu").toBeHidden();
    await page.setViewportSize({ width: 1100, height: 720 });
    await groupCard.locator('[data-act="ap-collapse"]').click();
    await expect(page.locator('[data-ap-list="active"] .ap-card.member').first()).toBeVisible();
  });

  test("no manual priority controls remain", async () => {
    const priority = '[data-act="ap-up"], [data-act="ap-down"], [data-act="ap-gup"], [data-act="ap-gdown"]';
    for (const sel of [priority, '[draggable="true"]']) {
      expect(await page.locator(sel).count(), sel).toBe(0);
    }
    const text = (await page.locator("#page").innerText()).toLowerCase();
    expect(text).not.toContain("сверху вниз");
    expect(text).not.toContain("перетащите карточку");

    // The group menu has no priority items either.
    const group = page.locator('[data-ap-list="active"] .ap-card.group').first();
    await group.locator('[data-act="ap-menu"]').click();
    const menu = page.locator("#ap-portal .ap-pop.menu");
    await expect(menu).toBeVisible();
    expect(await menu.locator(priority + ', [draggable="true"]').count()).toBe(0);
    expect((await menu.innerText()).toLowerCase()).not.toContain("сверху вниз");
    await page.keyboard.press("Escape");
    await expect(page.locator("#ap-portal")).toBeHidden();
  });

  test("the drawer is a compact process tree", async () => {
    const unit = page.locator(".ap-members .ap-unit-wrap", {
      has: page.locator(".ap-card.member", { hasText: "Discord" }),
    }).first();
    const pill = unit.locator('[data-act="ap-sub-toggle"]');
    await expect(pill, "the rule has no companion pill").toContainText("+6 процессов");
    await expect(unit.locator(".ap-sublist"), "the drawer starts open").toHaveCount(0);
    await pill.click();
    const sub = unit.locator(".ap-sublist");
    await expect(sub).toBeVisible();
    // Two dormant service shells are folded into one line.
    await expect(sub.locator(".ap-sub-row")).toHaveCount(4);
    await expect(sub.locator(".ap-origin.bound")).toHaveText("привязан");
    expect(await sub.locator(".ap-tree-guides .ap-tc").count(), "no tree guides").toBeGreaterThan(4);
    await expect(sub.locator('button[data-act="ap-sub-remove"]')).toHaveCount(1);

    const quiet = sub.locator(".ap-sub-quiet-bar");
    await expect(quiet).toContainText("2 служебных");
    await quiet.click();
    await expect(sub.locator(".ap-sub-row"), "expanding the folded shells showed nothing").toHaveCount(6);
    await expect(sub.locator(".ap-sub-row", { hasText: "powershell" }).locator(".ap-sub-cnt")).toHaveText("×2");
    await expect(sub.locator(".ap-sub-quiet-bar.open")).toContainText("Скрыть служебные (2)");
    await quiet.click();
    await expect(sub.locator(".ap-sub-row")).toHaveCount(4);
  });
});

export {};
