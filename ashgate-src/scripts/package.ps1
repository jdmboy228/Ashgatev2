# Package ashgate.exe with the signed WinDivert 2.2.2 driver.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$ver = "2.2.2"
New-Item -ItemType Directory -Force -Path build, dist | Out-Null
$zip = Join-Path build "WinDivert-$ver-A.zip"
# SHA-256 of the official release zip (the same as in update.bat). The
# driver ships inside the package, so a tampered or partial download must
# never be used.
$zipHash = "63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15"
if ((Test-Path $zip) -and (Get-FileHash $zip -Algorithm SHA256).Hash -ne $zipHash) { Remove-Item $zip }
if (-not (Test-Path $zip)) {
    Invoke-WebRequest -Uri "https://github.com/basil00/WinDivert/releases/download/v$ver/WinDivert-$ver-A.zip" -OutFile $zip
}
if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne $zipHash) {
    Remove-Item $zip
    throw "WinDivert-$ver-A.zip: SHA-256 does not match the official release"
}
$dest = Join-Path build "windivert"
if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
Expand-Archive -Path $zip -DestinationPath $dest
$dll = Get-ChildItem -Recurse $dest -Filter WinDivert.dll | Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
$sys = Get-ChildItem -Recurse $dest -Filter WinDivert64.sys | Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
if (-not $dll -or -not $sys) { throw "WinDivert x64 files not found in $zip" }

$winres = Join-Path $root "winres\winres.json"
$out = Join-Path $root "cmd\ashgate\rsrc"
try {
    go run github.com/tc-hib/go-winres@v0.3.1 make --in $winres --arch amd64 --out $out
} catch {
    Write-Warning "go-winres failed; administrator rights will be requested at runtime"
}

$env:CGO_ENABLED = "0"
go build -trimpath -ldflags "-s -w -H windowsgui" -o (Join-Path dist "ashgate.exe") ./cmd/ashgate
Copy-Item $dll.FullName (Join-Path dist "WinDivert.dll") -Force
Copy-Item $sys.FullName (Join-Path dist "WinDivert64.sys") -Force
Copy-Item (Join-Path $root "configs\ashgate.example.json") (Join-Path dist "ashgate.example.json") -Force
Copy-Item (Join-Path $root "README.md") (Join-Path dist "README.md") -Force
Copy-Item (Join-Path $root "LICENSE") (Join-Path dist "LICENSE") -Force
Copy-Item (Join-Path $root "THIRD_PARTY_NOTICES.md") (Join-Path dist "THIRD_PARTY_NOTICES.md") -Force

$rel = "0.3.0"
$verFile = Join-Path $root "internal\version\version.go"
if (Test-Path $verFile) {
    $m = Select-String -Path $verFile -Pattern 'const Version = "([^"]+)"' | Select-Object -First 1
    if ($m) { $rel = $m.Matches[0].Groups[1].Value }
}
$zipOut = Join-Path dist "ashgate-$rel-windows-amd64.zip"
$zipLegacy = Join-Path dist "ashgate-windows-amd64.zip"
if (Test-Path $zipOut) { Remove-Item $zipOut }
if (Test-Path $zipLegacy) { Remove-Item $zipLegacy }
$files = @(
    (Join-Path dist "ashgate.exe"),
    (Join-Path dist "WinDivert.dll"),
    (Join-Path dist "WinDivert64.sys"),
    (Join-Path dist "ashgate.example.json"),
    (Join-Path dist "README.md"),
    (Join-Path dist "LICENSE"),
    (Join-Path dist "THIRD_PARTY_NOTICES.md")
)
Compress-Archive -Path $files -DestinationPath $zipOut
Copy-Item $zipOut $zipLegacy
Write-Host "wrote $zipOut"
