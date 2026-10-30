# Build the Ashgate installer: ashgate-src\dist\Setup.exe
#
#   powershell -ExecutionPolicy Bypass -File build-installer.ps1
#   powershell -ExecutionPolicy Bypass -File build-installer.ps1 -Iscc "D:\Inno Setup 6\ISCC.exe"
#
# Needs Go and Inno Setup 6.3 or newer (https://jrsoftware.org/isdl.php).
# The exe is built by ashgate-src\scripts\package.ps1: plain go build, no
# packer such as UPX, and WinDivert checked against its official SHA-256.
param([string]$Iscc)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$src = Join-Path $root 'ashgate-src'

# 1. Version. internal\version\version.go is the source; version.json, which
#    the in-app update check reads from GitHub, must say the same.
$m = Select-String -Path (Join-Path $src 'internal\version\version.go') -Pattern 'const Version = "([^"]+)"' | Select-Object -First 1
if (-not $m) { throw 'Version not found in ashgate-src\internal\version\version.go' }
$ver = $m.Matches[0].Groups[1].Value
if ($ver -notmatch '^\d+(\.\d+){0,3}$') { throw "Version '$ver' must be numbers only, such as 0.7.3 (Windows file version)." }
$manifest = Get-Content -Raw -Encoding UTF8 (Join-Path $root 'version.json') | ConvertFrom-Json
if ($manifest.version -ne $ver) {
    throw "version.json says $($manifest.version), the code says $ver. Update version.json first."
}

# 2. Inno Setup compiler.
if (-not $Iscc) {
    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd) { $Iscc = $cmd.Source }
}
if (-not $Iscc) {
    foreach ($d in @("${env:ProgramFiles(x86)}\Inno Setup 6", "$env:ProgramFiles\Inno Setup 6", "$env:LOCALAPPDATA\Programs\Inno Setup 6")) {
        $p = Join-Path $d 'ISCC.exe'
        if (Test-Path $p) { $Iscc = $p; break }
    }
}
if (-not $Iscc -or -not (Test-Path $Iscc)) {
    throw 'Inno Setup 6 not found. Install it from https://jrsoftware.org/isdl.php or pass -Iscc <path to ISCC.exe>.'
}

# 3. ashgate.exe and WinDivert into ashgate-src\dist.
Push-Location $src
try {
    & (Join-Path $src 'scripts\package.ps1')
} finally {
    Pop-Location
}
foreach ($f in 'ashgate.exe', 'WinDivert.dll', 'WinDivert64.sys') {
    if (-not (Test-Path (Join-Path $src "dist\$f"))) { throw "dist\$f is missing after the build." }
}

# 4. Setup.exe.
$setup = Join-Path $src 'dist\Setup.exe'
if (Test-Path $setup) { Remove-Item $setup }
& $Iscc /Q "/DAppVersion=$ver" (Join-Path $root 'installer.iss')
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $setup)) { throw "Inno Setup failed (exit code $LASTEXITCODE)." }

Write-Host ""
Write-Host "Ashgate $ver installer: $setup" -ForegroundColor Green
Write-Host "Publish it on GitHub Releases; version.json points the update check there."
