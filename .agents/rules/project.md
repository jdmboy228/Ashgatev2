---
trigger: always_on
---

# Ashgate

The app is in `ashgate-src/` (Go module `ashgate`). The installer is `installer.iss`, built by
`build-installer.ps1`. Windows end-to-end tests are in `ashgate-src/e2e/` and run in
`.github/workflows/windows-e2e.yml`.

## Versioning

- Always bump the application version when preparing changes for `main`, keeping all three
  version sources in sync (verified by CI `Versions agree`):
  `ashgate-src/internal/version/version.go`, `version.json` (with updated `release_notes`),
  and `ashgate-src/winres/winres.json` (manifest identity, `file_version`, `product_version`,
  `FileVersion`, `ProductVersion`), plus `ashgate-src/CHANGELOG.md`.

## Failover (PR #3, `failover-fast`)

- No timer: the active server of a subscription is judged by real traffic. Evidence comes from
  `engine.RelayHealth` (relays that sent and wait, relays that ended unanswered) and from the
  byte counters of the subscription's rules (`gui/subs.go`). One check through the tunnel
  (3.5 s) confirms; the state machine is `internal/failover`. See README «Подписка 3x-ui».
- An idle tunnel is never checked. E2E tests that want a switch or a return must make client
  traffic (`harness.StartTraffic`, `harness.WaitActive`); a session is ready when a client
  request gets through (`harness.WaitTunnel`), not when a health check arrives.
- After a test cuts a server off, wait for the return to XHTTP (`harness.WaitActive`) before
  the next subtest: the return ends open connections once.
- The loop ticks four times a second, in every controller a test leaves running. Tests of the
  loop set their hooks on their own controller (`controller.fo`, see `foRig` in
  `gui/subs_test.go`) after stopping its loop; package-level hooks raced under `-race`.

## Project Notes & Constraints

- The leak test runs at log level debug: `ashgate.log` says why each DNS packet went direct.
  Windows reports System (PID 4) as the owner of the DNS client's socket; its DNS must take the
  system DNS path (`engine.decide`).
- `go-webview2` is a patched copy in `ashgate-src/third_party/go-webview2`, pulled in by
  `replace` in `go.mod`. See its `PATCHES.md`, and keep the patch when updating the module.
- Known limits, not changed: datagrams over 8 KB through VLESS are truncated (as in Xray);
  later IP fragments may not be captured by WinDivert at all; `update.bat` still trusts the
  clone's `.git/config` (it builds the clone's code elevated anyway).
