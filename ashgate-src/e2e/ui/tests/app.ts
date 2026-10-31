// Launch, attach to and quit the installed Ashgate. Remote debugging is
// turned on only for the process started here (CI); the policy fallback is
// removed again in quitApp/cleanup.
import { chromium, type Browser, type Page, type ConsoleMessage } from "@playwright/test";
import { spawn, execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

export const OUT = process.env.E2E_OUT || path.resolve("out");
export const EXE = path.join(process.env.ProgramFiles || "C:\\Program Files", "Ashgate", "ashgate.exe");
export const CONFIG = path.join(process.env.ProgramData || "C:\\ProgramData", "Ashgate", "config.json");
const PORT = 9222;
const POLICY = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\WebView2\\AdditionalBrowserArguments";
let policyUsed = false;

export type Fixtures = {
  xhttpLink: string; rawLink: string; plainLink: string; subURL: string;
  socks: string; http: string; user: string; pass: string;
};

export function fixtures(): Fixtures {
  return JSON.parse(fs.readFileSync(path.join(OUT, "fixtures.json"), "utf8"));
}

export type Problem = { kind: string; text: string; where?: string };

export class App {
  browser!: Browser;
  page!: Page;
  problems: Problem[] = [];
  pid = 0;

  static async launch(): Promise<App> {
    const app = new App();
    await app.start(!policyUsed);
    if (!(await app.attach(60_000))) {
      // WebView2 ignored the variable: use the policy for this job only.
      app.quitProcess();
      execFileSync("reg", ["add", POLICY, "/v", "ashgate.exe", "/t", "REG_SZ", "/d", `--remote-debugging-port=${PORT}`, "/f"]);
      policyUsed = true;
      await app.start(false);
      if (!(await app.attach(60_000))) throw new Error("cannot attach to the Ashgate window over CDP");
    }
    return app;
  }

  private async start(withEnv: boolean) {
    const env = { ...process.env };
    delete env.WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS;
    if (withEnv) env.WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = `--remote-debugging-port=${PORT}`;
    const child = spawn(EXE, [], { env, detached: true, stdio: "ignore" });
    child.unref();
    this.pid = child.pid || 0;
  }

  private async attach(timeout: number): Promise<boolean> {
    const end = Date.now() + timeout;
    while (Date.now() < end) {
      try {
        this.browser = await chromium.connectOverCDP(`http://127.0.0.1:${PORT}`, { timeout: 5000 });
        for (let i = 0; i < 40; i++) {
          const pages = this.browser.contexts().flatMap((c) => c.pages());
          const p = pages.find((pg) => pg.url().startsWith("http://127.0.0.1:"));
          if (p) {
            this.page = p;
            this.watch();
            await p.waitForFunction(() => !!(window as any).__ashgateToken && !!document.querySelector("#page")?.children.length);
            return true;
          }
          await new Promise((r) => setTimeout(r, 500));
        }
      } catch {
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
    return false;
  }

  private watch() {
    this.page.on("console", (m: ConsoleMessage) => {
      if (m.type() !== "error") return;
      const url = m.location()?.url || "";
      // A missing app icon is a cached 404 by design (/api/icon).
      if (/\/api\/icon\b/.test(url) || /\/api\/icon\b/.test(m.text())) return;
      this.problems.push({ kind: "console", text: m.text(), where: url });
    });
    this.page.on("pageerror", (e) => this.problems.push({ kind: "pageerror", text: String(e) }));
  }

  // quitApp closes the window the way «Выход» does.
  async quit() {
    try { await this.browser?.close(); } catch { /* detached */ }
    this.quitProcess();
  }

  private quitProcess() {
    try { execFileSync(EXE, ["quit"], { timeout: 30_000 }); } catch { /* not running */ }
    const end = Date.now() + 20_000;
    while (Date.now() < end) {
      const out = execFileSync("tasklist", ["/FI", "IMAGENAME eq ashgate.exe", "/NH"]).toString();
      if (!/ashgate\.exe/i.test(out)) return;
      execFileSync("powershell", ["-NoProfile", "-Command", "Start-Sleep -Milliseconds 300"]);
    }
  }
}

export function cleanupPolicy() {
  if (!policyUsed) return;
  try { execFileSync("reg", ["delete", POLICY, "/v", "ashgate.exe", "/f"]); } catch { /* gone */ }
}

export function readConfig(): any {
  return JSON.parse(fs.readFileSync(CONFIG, "utf8"));
}

// desktop saves a screenshot of the whole desktop (the native frame too).
export function desktop(name: string) {
  const file = path.join(OUT, "ui", "screens", `${name}.png`).replace(/'/g, "''");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  execFileSync("powershell", ["-NoProfile", "-Command",
    "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;" +
    "$b=[System.Windows.Forms.SystemInformation]::VirtualScreen;" +
    "$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height;" +
    "$g=[System.Drawing.Graphics]::FromImage($bmp);$g.CopyFromScreen($b.Left,$b.Top,0,0,$bmp.Size);" +
    `$bmp.Save('${file}',[System.Drawing.Imaging.ImageFormat]::Png)`]);
}
