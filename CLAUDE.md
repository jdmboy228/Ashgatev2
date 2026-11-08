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

## E2E progress (2026-11-08)

- 0.9.3 (PR #2, branch `audit-0.9.3`, includes 0.9.2 from PR #1): VLESS TCP in-process
  (`vless.DialTCP`), batched WinDivert I/O, lossless UDP, adaptive handshake gate, leak fixes,
  UI fixes. See `ashgate-src/CHANGELOG.md` under 0.9.3.
- Green on 0.9.3: PR run 42502394766 and the long workflow_dispatch run 42502418664 (failover
  back to XHTTP after 1205 s, 10-minute growth flat). All jobs pass.
- Load test on the CI runner (varies with the runner), 0.9.1 → 0.9.3: RAW 46.7 → 72–135 MB/s,
  XHTTP 28.2 → 66–124 MB/s; Ashgate CPU per 100 MB 4.1 → 1.1–2.2 s (RAW), 6.3 → 1.3–2.6 s
  (XHTTP). The page no longer polls in the tray. Failover to RAW still takes ~86 s in the test
  (the early check needs failing app traffic, which that test does not make).
- The leak test runs at log level debug: ashgate.log then says why each DNS packet went direct.
  Windows reports System (PID 4) as the owner of the DNS client's socket; its DNS must take the
  system DNS path (engine.decide).
- Local builds (1 CPU, small disk): every go command under
  `flock $CLAUDE_JOB_DIR/tmp/go.lock` with `GOFLAGS=-p=1`. Everything except `./internal/vless/`
  is built with `-overlay` stubs for `internal/vless/xray.go` and `inproc.go` (drop
  `inproc_test.go`), so Xray is never compiled, and never with `-race`. Never build `./e2e/...`
  locally: the harness imports Xray and a Windows Xray build fills the disk.
- go-webview2 is a patched copy in `ashgate-src/third_party/go-webview2`, pulled in by `replace` in
  go.mod. See its PATCHES.md, and keep the patch when updating the module.
- Known limits, not changed: datagrams over 8 KB through VLESS are truncated (as in Xray);
  later IP fragments may not be captured by WinDivert at all; `update.bat` still trusts the
  clone's `.git/config` (it builds the clone's code elevated anyway).
