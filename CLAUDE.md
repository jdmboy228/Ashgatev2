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

Done:
- `windows-e2e.yml` is green on push: run 41298533622 (all 8 jobs, version 0.9.1).
- Dispatch run 41299555403 (long tests): connectivity passed, including the return to XHTTP after
  1205 s with exactly 2 switches. Two failures remain, listed below.
- App bugs found and fixed in 0.9.1 are in `ashgate-src/CHANGELOG.md`.

Pending:
- **Goroutine growth.** Not a leak: goroutines stay flat at 37, apart from two ~60 s spikes that go
  back to 37. The 10-min run failed because the test client's 10-min HTTP timeout
  (`e2e/cmd/client/main.go` `client()`) cut the 630 s `hold` stream at 600 s. Fix: give `hold` a
  timeout of secs+60 s. Optionally compare medians of the first and last 5 samples in
  `perf_test.go`.
- **UI apps step.** A race in `ui.spec.ts`: the second "ap-add" fills `#ap-add-path` while
  `renderModal()` rebuilds the dialog. Fix: wait for the dialog, then fill and check
  `toHaveValue` inside `toPass()`. Small app bug behind it: `renderModal()` in `app.js` loses the
  focused field and the typed text when the installed-apps list arrives. Fix: call `apReadModal()`
  first and restore the focus.
- **go-webview2 patch.** Its `PermissionRequested` (pkg/edge/chromium.go) passes `kind` by value to
  `GetPermissionKind`, so the clipboard-read allow never matches and WebView2 asks for the
  clipboard. Fix: a patched copy of the module via `replace` in go.mod (pass `&kind`), or fix it
  upstream. Not done: the other option, allowing every permission kind, is too broad.
