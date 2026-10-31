# Third-party notices

Ashgate is MIT licensed. It does not vendor the following component.

## WinDivert 2.2.2

- Project: https://github.com/basil00/WinDivert
- Release used at package time: https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip
- Files placed next to `ashgate.exe`: `WinDivert.dll`, `WinDivert64.sys`
- License: GNU Lesser General Public License 3.0 **or** GNU General Public License 2.0
- License text: https://github.com/basil00/WinDivert/blob/v2.2.2/LICENSE

Ashgate loads the unmodified official DLL at runtime and does not link it into
the Go binary. The signed driver is the upstream build (variant A by default;
variants B and C differ by signature, not by code). Do not replace
`WinDivert64.sys` with a locally built driver: an unsigned driver will not load
on a normal Windows 10/11 installation.

Distribute `WinDivert.dll` and `WinDivert64.sys` together with their license
when you redistribute a build of Ashgate.

## Xray-core

- Module: https://github.com/XTLS/Xray-core
- Version linked into `ashgate.exe`: v26.10.31 (Go module v1.260327.1-0.20261031132019-a4a3dff5b20c)
- License: Mozilla Public License 2.0
- License text: https://github.com/XTLS/Xray-core/blob/v26.10.31/LICENSE

Ashgate links this module as a library. It is not a separate executable.
MPL-2.0 covers the Xray-core source; Ashgate's own code stays MIT. Source for
this version is the module above.

## WebView2 host

- Module: https://github.com/jchv/go-webview2
- License: MIT
- Ashgate links this package into `ashgate.exe`. The Microsoft Edge WebView2
  runtime is not bundled; Windows 10/11 normally already has it.

## Fonts embedded in the window

The window ships two font families as WOFF2 files under `internal/gui/ui/fonts`.
Both are licensed under the SIL Open Font License 1.1
(https://openfontlicense.org). The license does not allow selling the fonts by
themselves.

- Inter, weights 400/500/600, Latin and Cyrillic subsets.
  Copyright (c) The Inter Project Authors. https://github.com/rsms/inter
- JetBrains Mono, weight 400, Latin subset, used for addresses and timestamps.
  Copyright (c) The JetBrains Mono Project Authors. https://www.jetbrains.com/lp/mono/
