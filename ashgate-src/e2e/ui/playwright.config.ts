import { defineConfig } from "@playwright/test";
import * as path from "node:path";

// The tests attach to the installed Ashgate over the Chrome DevTools
// Protocol (WebView2 remote debugging, CI only). No browser is downloaded.
const out = process.env.E2E_OUT || path.resolve("out");

export default defineConfig({
  testDir: "tests",
  workers: 1,
  fullyParallel: false,
  retries: 0,
  timeout: 15 * 60 * 1000,
  expect: { timeout: 15_000 },
  outputDir: path.join(out, "ui", "test-results"),
  reporter: [
    ["list"],
    ["junit", { outputFile: path.join(out, "ui", "junit.xml") }],
    ["html", { outputFolder: path.join(out, "ui", "report"), open: "never" }],
  ],
  use: { actionTimeout: 15_000 },
});
