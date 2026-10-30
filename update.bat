<# : Batch part. PowerShell reads this whole block as a comment.
@echo off
setlocal
title Ashgate update
rem Ashgate runs as administrator, so replacing it needs the same rights.
rem No ( ) blocks here: a folder such as "Program Files (x86)" would break them.
fltmc >nul 2>&1 && goto :admin
echo Requesting administrator rights...
if "%~1"=="" goto :elevate
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '\"%~1\"' -Verb RunAs"
exit /b
:elevate
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b
:admin
set "ASHGATE_UPDATE_SELF=%~f0"
set "ASHGATE_UPDATE_TARGET=%~1"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Expression ([IO.File]::ReadAllText($env:ASHGATE_UPDATE_SELF, [Text.Encoding]::UTF8))"
set "rc=%errorlevel%"
echo.
pause
exit /b %rc%
#>

# ---------------------------------------------------------------------------
# Ashgate update: pull the code, build it, replace the installed ashgate.exe
# and start it again. Double-click update.bat in the root of the clone.
#
#   update.bat                 update the copy that runs now (or the autostart
#                              task, the service, or ashgate-src\dist)
#   update.bat "C:\Apps\Ashgate"   update the copy in that folder
#
# The running window is closed the way «Выход» does it (ashgate quit), so
# capture stops cleanly and comes back on after the update. A failed build
# never touches the installed copy; the previous exe is kept as
# ashgate.old.exe.
# ---------------------------------------------------------------------------

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:stopped = $false
$script:replaced = $false
$script:oldExe = $null
$script:svcStopped = $false

function Step($n, $t) { Write-Host ""; Write-Host "[$n/6] $t" -ForegroundColor Cyan }
function Info($t) { Write-Host "      $t" -ForegroundColor Gray }
function Warn($t) { Write-Host "      $t" -ForegroundColor Yellow }
function Fail($t) {
  Write-Host ""
  Write-Host "Обновление остановлено: $t" -ForegroundColor Red
  if ($script:stopped -and -not $script:replaced) {
    if ($script:svcStopped) { Start-Service -Name Ashgate -ErrorAction SilentlyContinue; Write-Host "Служба Ashgate запущена снова." -ForegroundColor Yellow }
    elseif ($script:oldExe -and (Test-Path $script:oldExe)) { Start-Process -FilePath $script:oldExe; Write-Host "Прежняя версия запущена снова." -ForegroundColor Yellow }
  } elseif (-not $script:stopped) {
    Write-Host "Установленная версия не изменилась." -ForegroundColor Yellow
  }
  exit 1
}

Write-Host "Ashgate · обновление" -ForegroundColor White

$here = Split-Path -Parent $env:ASHGATE_UPDATE_SELF
if (Test-Path (Join-Path $here 'ashgate-src\go.mod')) { $src = Join-Path $here 'ashgate-src' }
elseif (Test-Path (Join-Path $here 'go.mod')) { $src = $here }
else { Fail "рядом с update.bat нет папки ashgate-src. Положите update.bat в корень клона Ashgate." }

# ---------- 1. tools ----------
Step 1 "Проверяю Go и Git"
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  # Installed a minute ago? The elevated window may not see the new PATH yet.
  foreach ($d in @("$env:ProgramFiles\Go\bin", "$env:LOCALAPPDATA\Programs\Go\bin")) {
    if (Test-Path (Join-Path $d 'go.exe')) { $env:Path = "$d;$env:Path"; break }
  }
}
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  Fail "не найден Go. Установите его с https://go.dev/dl/ (файл .msi для Windows) и запустите update.bat снова."
}
Info ((& go version) -join ' ')
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  $d = "$env:ProgramFiles\Git\cmd"
  if (Test-Path (Join-Path $d 'git.exe')) { $env:Path = "$d;$env:Path" }
}
$hasGit = [bool](Get-Command git -ErrorAction SilentlyContinue)
if (-not $hasGit) { Warn "Git не найден: соберу код, который уже лежит в папке (https://git-scm.com/download/win)." }

# ---------- 2. code ----------
Step 2 "Скачиваю свежий код"
$repo = $null
$commit = ''
if ($hasGit) {
  $repo = (& git -C $src rev-parse --show-toplevel 2>$null | Select-Object -First 1)
}
if ($repo) {
  # The window runs elevated; let git trust a clone made by the same user.
  $safe = 'safe.directory=' + ($repo -replace '\\', '/')
  & git -c $safe -C $repo pull --ff-only
  if ($LASTEXITCODE -ne 0) {
    Warn "Не удалось получить обновления (нет сети или в папке есть свои правки). Соберу код, который уже есть."
  }
  $commit = (& git -c $safe -C $repo log -1 --format='%h' 2>$null | Select-Object -First 1)
  Info ("Код: " + (& git -c $safe -C $repo log -1 --format='%h · %s · %cr' 2>$null | Select-Object -First 1))
} elseif ($hasGit) {
  Warn "Папка — не клон репозитория: соберу код, который уже есть."
}
$ver = '?'
$verLine = Select-String -Path (Join-Path $src 'internal\version\version.go') -Pattern 'const Version = "([^"]+)"' | Select-Object -First 1
if ($verLine) { $ver = $verLine.Matches[0].Groups[1].Value }

# ---------- 3. build ----------
Step 3 "Собираю Ashgate $ver"
$stage = Join-Path $src 'build\update'
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stage | Out-Null

$wdVer = '2.2.2'
$wdZip = Join-Path $src "build\WinDivert-$wdVer-A.zip"
if (-not (Test-Path $wdZip)) {
  Info "Скачиваю драйвер WinDivert $wdVer…"
  try {
    Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/basil00/WinDivert/releases/download/v$wdVer/WinDivert-$wdVer-A.zip" -OutFile $wdZip -ErrorAction Stop
  } catch {
    Remove-Item $wdZip -ErrorAction SilentlyContinue
    Warn "Драйвер не скачался: оставлю WinDivert, который уже лежит рядом с ashgate.exe."
  }
}
$wdDll = $null
$wdSys = $null
if (Test-Path $wdZip) {
  $wdDir = Join-Path $src 'build\windivert'
  Remove-Item -Recurse -Force $wdDir -ErrorAction SilentlyContinue
  Expand-Archive -Path $wdZip -DestinationPath $wdDir -Force
  $wdDll = Get-ChildItem -Recurse $wdDir -Filter WinDivert.dll | Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
  $wdSys = Get-ChildItem -Recurse $wdDir -Filter WinDivert64.sys | Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
}

Push-Location $src
$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
# Icon and manifest (administrator rights, DPI). Optional: Ashgate asks for
# the rights itself when the manifest is missing.
& go run github.com/tc-hib/go-winres@v0.3.1 make --in winres\winres.json --arch amd64 --out cmd\ashgate\rsrc
if ($LASTEXITCODE -ne 0) { Warn "Значок и манифест не встроены — Ashgate всё равно запросит права администратора." }
Info "Компилирую… (первый раз — несколько минут)"
& go build -trimpath -ldflags "-s -w -H windowsgui" -o (Join-Path $stage 'ashgate.exe') ./cmd/ashgate
$built = $LASTEXITCODE
Pop-Location
if ($built -ne 0 -or -not (Test-Path (Join-Path $stage 'ashgate.exe'))) { Fail "сборка не удалась (ошибки выше)." }
Info "Готово: $stage\ashgate.exe"

# ---------- 4. where is the installed copy ----------
Step 4 "Ищу установленный Ashgate"
$target = $env:ASHGATE_UPDATE_TARGET
$how = 'указана при запуске'
if (-not $target) {
  $p = Get-Process -Name ashgate -ErrorAction SilentlyContinue | Where-Object { $_.Path } | Select-Object -First 1
  if ($p) { $target = Split-Path -Parent $p.Path; $how = 'работающая копия' }
}
$svc = Get-CimInstance Win32_Service -Filter "Name='Ashgate'" -ErrorAction SilentlyContinue
if (-not $target -and $svc) {
  $exe = $svc.PathName
  if ($exe -match '^"([^"]+)"') { $exe = $Matches[1] } elseif ($exe -match '^(\S+\.exe)') { $exe = $Matches[1] }
  if (Test-Path $exe) { $target = Split-Path -Parent $exe; $how = 'служба Ashgate' }
}
if (-not $target) {
  $task = Get-ScheduledTask -TaskName 'Ashgate' -ErrorAction SilentlyContinue
  if ($task) {
    $exe = $task.Actions[0].Execute.Trim('"')
    if (Test-Path $exe) { $target = Split-Path -Parent $exe; $how = 'задача «Запускать с Windows»' }
  }
}
if (-not $target) { $target = Join-Path $src 'dist'; $how = 'папка сборки' }
$target = [IO.Path]::GetFullPath($target)
$script:oldExe = Join-Path $target 'ashgate.exe'
Info "$target ($how)"

# ---------- 5. close the old version ----------
Step 5 "Закрываю старую версию"
$resumeUnknown = $false
if ($svc -and $svc.State -eq 'Running') {
  Info "Останавливаю службу Ashgate…"
  Stop-Service -Name Ashgate -Force -ErrorAction SilentlyContinue
  $script:svcStopped = $true
  $script:stopped = $true
}
if (Get-Process -Name ashgate -ErrorAction SilentlyContinue) {
  # The new exe asks the running window to exit like «Выход»: capture stops,
  # the kill switch is restored, and capture comes back after the restart.
  $q = (Start-Process -FilePath (Join-Path $stage 'ashgate.exe') -ArgumentList 'quit' -NoNewWindow -Wait -PassThru).ExitCode
  if ($q -eq 0) {
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Process -Name ashgate -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
  }
  if (Get-Process -Name ashgate -ErrorAction SilentlyContinue) {
    if ($q -eq 3) { Warn "Запущенная версия не умеет закрываться по команде (ashgate quit) — завершаю её принудительно." }
    else { Warn "Ashgate не закрылся сам — завершаю принудительно." }
    $resumeUnknown = $true
    Stop-Process -Name ashgate -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
  }
  $script:stopped = $true
  Info "Старая версия закрыта."
} elseif (-not $script:svcStopped) {
  Info "Ashgate не был запущен."
}

# ---------- 6. replace and start ----------
Step 6 "Ставлю новую версию и запускаю"
New-Item -ItemType Directory -Force -Path $target | Out-Null
function Put($from, $name) {
  $to = Join-Path $target $name
  if ((Test-Path $to) -and ((Get-FileHash $from).Hash -eq (Get-FileHash $to).Hash)) { return }
  for ($i = 0; $i -lt 20; $i++) {
    try { Copy-Item -LiteralPath $from -Destination $to -Force -ErrorAction Stop; return } catch { Start-Sleep -Milliseconds 500 }
  }
  throw "не удалось заменить $name — файл занят другой программой"
}
try {
  if (Test-Path $script:oldExe) { Copy-Item -LiteralPath $script:oldExe -Destination (Join-Path $target 'ashgate.old.exe') -Force -ErrorAction SilentlyContinue }
  Put (Join-Path $stage 'ashgate.exe') 'ashgate.exe'
  $script:replaced = $true
  if ($wdDll) { Put $wdDll.FullName 'WinDivert.dll' }
  if ($wdSys) {
    try { Put $wdSys.FullName 'WinDivert64.sys' } catch { Warn "WinDivert64.sys ещё занят драйвером — оставлен прежний файл той же версии." }
  }
} catch {
  Fail $_.Exception.Message
}
if (-not (Test-Path (Join-Path $target 'WinDivert.dll')) -or -not (Test-Path (Join-Path $target 'WinDivert64.sys'))) {
  Warn "В папке нет WinDivert.dll или WinDivert64.sys — без них Ashgate не включится."
}
if ($script:svcStopped) {
  Start-Service -Name Ashgate -ErrorAction SilentlyContinue
  Info "Служба Ashgate запущена."
} else {
  Start-Process -FilePath (Join-Path $target 'ashgate.exe') -WorkingDirectory $target
  Info "Окно Ashgate открыто."
}

Write-Host ""
$tag = $ver
if ($commit) { $tag = "$ver · $commit" }
Write-Host "Готово: Ashgate $tag" -ForegroundColor Green
Write-Host "      $target\ashgate.exe" -ForegroundColor Gray
if ($resumeUnknown) { Warn "Старая версия была закрыта принудительно: если перехват был включён, нажмите «Вкл» в окне." }
if (Test-Path (Join-Path $target 'ashgate.old.exe')) { Info "Прежняя версия сохранена как ashgate.old.exe." }
exit 0
