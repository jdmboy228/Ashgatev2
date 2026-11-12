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

## Failover (2026-11-10, PR #3, branch `failover-fast`)

- No timer: the active server of a subscription is judged by real traffic. Evidence comes from
  `engine.RelayHealth` (relays that sent and wait, relays that ended unanswered) and from the
  byte counters of the subscription's rules (`gui/subs.go`). One check through the tunnel
  (3.5 s) confirms; the state machine is `internal/failover`. See README «Подписка 3x-ui».
- An idle tunnel is never checked. E2E tests that want a switch or a return must make client
  traffic (`harness.StartTraffic`, `harness.WaitActive`); a session is ready when a client
  request gets through (`harness.WaitTunnel`), not when a health check arrives.
- After a test cuts a server off, wait for the return to XHTTP (`harness.WaitActive`) before
  the next subtest: the return ends open connections once.
- Measured in CI (run 42832884352): stall noticed 5.7 s, requests through RAW 6.0 s, refused
  port 6.5 s, return to XHTTP 27 s after it answered again.
- The loop ticks four times a second, in every controller a test leaves running. Tests of the
  loop set their hooks on their own controller (`controller.fo`, see `foRig` in
  `gui/subs_test.go`) after stopping its loop; package-level hooks raced under `-race`.

## Android (2026-11-12, branch `android-mvp`)

- The app is `android/` (Kotlin, package `io.ashgate.android`); its Go core is
  `ashgate-src/mobile` (bound with gomobile) and `ashgate-src/internal/mobilecfg` (profiles and
  the Xray document). See `android/README.md`.
- Xray's own TUN inbound reads the VpnService descriptor (`xray.tun.fd`); there is no local
  SOCKS or HTTP port. Ashgate is never in the allowed apps, so its sockets need no `protect()`.
- Never install the Android SDK, NDK or Gradle here. The APK and all Android tests run only in
  `.github/workflows/android.yml` (no Gradle wrapper in the repo; CI pins Gradle).
- Locally only `go test ./internal/mobilecfg/` runs, with the `-overlay` stubs below (the stub
  for `xray.go` also needs `Run`). `mobile/router_test.go` imports Xray: CI only.

## E2E progress (2026-11-08)

- 0.9.3 (PR #2, branch `audit-0.9.3`, includes 0.9.2 from PR #1): VLESS TCP in-process
  (`vless.DialTCP`), batched WinDivert I/O, lossless UDP, adaptive handshake gate, leak fixes,
  UI fixes. See `ashgate-src/CHANGELOG.md` under 0.9.3.
- Green on 0.9.3: PR run 42502394766 and the long workflow_dispatch run 42502418664 (failover
  back to XHTTP after 1205 s, 10-minute growth flat). All jobs pass.
- Load test on the CI runner (varies with the runner), 0.9.1 → 0.9.3: RAW 46.7 → 72–135 MB/s,
  XHTTP 28.2 → 66–124 MB/s; Ashgate CPU per 100 MB 4.1 → 1.1–2.2 s (RAW), 6.3 → 1.3–2.6 s
  (XHTTP). The page no longer polls in the tray. Failover took ~86 s then; see Failover above.
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
