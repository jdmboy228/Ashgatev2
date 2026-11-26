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
- `webview.go`, `pkg/edge/chromium.go`, `webviewloader/module.go`: added
  `BrowserExecutableFolder` to `WebViewOptions` and `edge.Chromium` and forwarded it to
  `CreateCoreWebView2EnvironmentWithOptions` (with `runtime.KeepAlive` on the UTF-16 string
  pointers across the `winloader.Proc.Call` boundary), so an elevated host can pin the
  machine-wide `HKLM` WebView2 Runtime under Program Files instead of letting
  `WebView2Loader.dll` fall back to user-writable `HKCU` registry keys.
