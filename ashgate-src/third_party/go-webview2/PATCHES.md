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
- `pkg/edge/chromium.go`: added `initFailed`, fixed COM `HRESULT` sign checks (`int32(res) < 0`
  and nil interface checks instead of `int64(res) < 0` + `log.Fatalf`) in
  `EnvironmentCompleted` and `CreateCoreWebView2ControllerCompleted`, guarded `GetMessageW`
  errors (`r == 0 || int32(r) == -1`), and made `Embed()` return `false` when initialization
  fails instead of crashing or dereferencing a nil `e.webview`.
- `pkg/edge/corewebview2.go`, `pkg/edge/ICoreWebViewSettings.go`: check the COM `HRESULT`
  return value (`int32(hr) < 0`) instead of Win32 `GetLastError` in `GetSettings`,
  `PutAreDevToolsEnabled`, `GetAreDefaultContextMenusEnabled`, and
  `PutAreDefaultContextMenusEnabled`.
- `webview.go`: return `nil` (after `w.Destroy()`) instead of calling `log.Fatal` if applying
  WebView2 settings fails in `NewWithOptions`.
- `pkg/edge/ICoreWebView2Controller.go`, `pkg/edge/corewebview2.go`, `pkg/edge/chromium.go`:
  pass `token` (not `&token`) and check `int32(hr) < 0` in `AddAcceleratorKeyPressed` and
  `AddNavigationCompleted` (avoiding stack pointer overwrite), and zero `*ppvObject` + return
  `E_NOINTERFACE` (`0x80004002`) in `Chromium.QueryInterface`.
