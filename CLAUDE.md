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
