# Ashgate's copy of go-webview2

Upstream: github.com/jchv/go-webview2 v0.0.0-20260205173254-56598839c808 (MIT, see LICENSE).
Used through `replace` in ../../go.mod. The demo in `cmd/` and the upstream CI file are left out.

Changes:

- `pkg/edge/chromium.go`, `PermissionRequested`: `get_PermissionKind` now gets `&kind`
  instead of the value of `kind`. With the value, every request read as kind 0 (unknown), so
  the library's clipboard-read allow never applied and WebView2 showed a clipboard prompt.
- `webviewloader/module.go`: removed the `nativeModule` (`LoadLibraryW("WebView2Loader")`)
  disk-search path so `CreateCoreWebView2EnvironmentWithOptions`, `CompareBrowserVersions`,
  and `GetInstalledVersion` always load `WebView2Loader.dll` exclusively from the embedded
  in-memory copy (`loadFromMemory`), preventing DLL sideloading from CWD or user `PATH`.
