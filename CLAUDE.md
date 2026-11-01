# Ashgate

The app is in `ashgate-src/` (Go module `ashgate`). The installer is `installer.iss`, built by
`build-installer.ps1`. Windows end-to-end tests are in `ashgate-src/e2e/` and run in
`.github/workflows/windows-e2e.yml`.

## Server rules

- This Linux server has a small disk (~10 GB). Never install browsers or GUI packages via snap or apt (no chromium snap, no cups, no gnome/gtk/mesa).
- If you need a browser on this server, use headless Chrome via Playwright only for the duration of the check, then remove it (npx playwright uninstall --all, delete ~/.cache/ms-playwright).
- UI checks normally run in the GitHub Actions Windows runner, not on this server.
- After heavy work, clean caches: go clean -cache, npm cache clean --force.

## CI

- For every failed GitHub Actions run, use the `ci-log-analyzer` subagent
  (`.claude/agents/ci-log-analyzer.md`) with the run id. Do not read raw Windows runner logs in
  the main session.

## E2E progress (2026-11-01)

- Green on version 0.9.1: push run 41315227236, and the long workflow_dispatch run 41316470292
  (failover back to XHTTP after 1204 s, 10-minute stability and growth). All 8 jobs pass.
- App bugs found and fixed are in `ashgate-src/CHANGELOG.md` under 0.9.1.
- 0.9.2 (branch `dns-leaks`, PR #1): DNS never reaches the provider for routed apps (Windows DNS
  client through the tunnel except .ru/.рф/.su and bypass names, DoH for Ashgate's own lookups).
  Push run 41347818766 green; the long workflow_dispatch run is not done yet. Locally, build with
  `-overlay` stubs for `internal/vless/xray.go` and `inproc.go`: a full Xray build does not fit the disk.
- go-webview2 is a patched copy in `ashgate-src/third_party/go-webview2`, pulled in by `replace` in
  go.mod. See its PATCHES.md, and keep the patch when updating the module.
- Flagged, not changed:
  - The page keeps polling `/api/state` every 3 s while in the tray.
  - `schtasks.exe` runs once a minute for the autostart check.
  - `ashgate.exe` has no VERSIONINFO resource.
