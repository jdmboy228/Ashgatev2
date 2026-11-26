# External comparison runner. It does not read a client's logs or API to
# decide a result. A transport the client cannot do is recorded as
# unsupported. A client that never connects is recorded as an error.
# The process exits 0 once results.json and mapping.json are written.
param(
    [Parameter(Mandatory)][string]$Xray,
    [Parameter(Mandatory)][string]$SingBox,
    [Parameter(Mandatory)][string]$V2rayN,
    [Parameter(Mandatory)][string]$Ashgate,
    [Parameter(Mandatory)][string]$Lab,
    [Parameter(Mandatory)][string]$Probe,
    [int]$Rounds = 3,
    [int]$SoakMinutes = 10,
    [int]$ThroughputSeconds = 8,
    [string]$Out = ""
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$script:Compare = $PSScriptRoot
$script:Python = "python"
$script:AshgateExe = $Ashgate
$script:SingBoxExe = $SingBox
$script:V2Exe = $V2rayN
$script:Lab = $Lab
$script:Rules = Join-Path $PSScriptRoot "rules.json"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "this comparison must run in an elevated session"
}

if (-not $Out) { $Out = Join-Path $PSScriptRoot "..\compare-out" }
New-Item -ItemType Directory -Force $Out | Out-Null
$script:Out = (Resolve-Path $Out).Path
$script:CapDir = Join-Path $script:Out "captures"
New-Item -ItemType Directory -Force $script:CapDir | Out-Null
$script:Bin = Join-Path $script:Out "bin"
New-Item -ItemType Directory -Force $script:Bin | Out-Null
$script:ProbeExe = Join-Path $script:Bin "compare-probe.exe"
$script:ControlExe = Join-Path $script:Bin "compare-control.exe"
Copy-Item $Probe $script:ProbeExe -Force
Copy-Item $Probe $script:ControlExe -Force

$script:Caps = @{
    ashgate    = @{ xhttp = $true;  raw = $true;  failover = $true;  kill = $true }
    "sing-box" = @{ xhttp = $false; raw = $true;  failover = $false; kill = $false }
    v2rayn     = @{ xhttp = $true;  raw = $true;  failover = $true;  kill = $false }
}
$script:Tools = @("ashgate", "sing-box", "v2rayn")
$script:Side = @{}
$script:V2Ready = $false
$script:V2Noted = $false
$script:Secrets = New-Object System.Collections.Generic.List[string]
$script:LabProc = $null

function Write-Step([string]$Message) {
    Write-Host ("{0} {1}" -f (Get-Date -Format "HH:mm:ss"), $Message)
}

function Hide-Secrets([string]$Text) {
    if (-not $Text) { return "" }
    foreach ($s in $script:Secrets) {
        if ($s -and $s.Length -ge 6) { $Text = $Text.Replace($s, "***") }
    }
    return $Text
}

function Get-Tail([string]$Path) {
    if (-not (Test-Path $Path)) { return "" }
    $item = Get-Item $Path
    if ($item.PSIsContainer) {
        $file = Get-ChildItem $Path -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $file) { return "" }
        $Path = $file.FullName
    }
    $lines = @(Get-Content $Path -Tail 30 -ErrorAction SilentlyContinue)
    return Hide-Secrets ($lines -join "`n")
}

function Get-Shuffled([string[]]$Items) {
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($i in $Items) { $list.Add($i) }
    for ($i = $list.Count - 1; $i -gt 0; $i--) {
        $j = Get-Random -Minimum 0 -Maximum ($i + 1)
        $tmp = $list[$i]
        $list[$i] = $list[$j]
        $list[$j] = $tmp
    }
    return @($list)
}

function Invoke-Probe([string]$Exe, [string[]]$ArgList) {
    $text = & $Exe @ArgList 2>&1 | Out-String
    $line = @($text -split "`r?`n" | Where-Object { $_ -match '^\s*\{' } | Select-Object -Last 1)
    if (-not $line) { return @{ ok = $false; error = "no json from workload"; bytes = [int64]0 } }
    $o = $line | ConvertFrom-Json
    $bytes = [int64]0
    if ($o.bytes) { $bytes = [int64]$o.bytes }
    $median = 0.0
    $p95 = 0.0
    if ($o.median_ms) { $median = [double]$o.median_ms }
    if ($o.p95_ms) { $p95 = [double]$o.p95_ms }
    return @{ ok = [bool]$o.ok; error = Hide-Secrets ([string]$o.error); bytes = $bytes; median_ms = $median; p95_ms = $p95 }
}

function Get-Tree([int]$Root) {
    $all = @(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId)
    $ids = [System.Collections.Generic.List[int]]::new()
    if ($Root -gt 0) { $ids.Add($Root) }
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($p in $all) {
            $procId = [int]$p.ProcessId
            $parentId = [int]$p.ParentProcessId
            if ($ids.Contains($parentId) -and -not $ids.Contains($procId)) {
                $ids.Add($procId)
                $changed = $true
            }
        }
    }
    return @($ids)
}

function Get-Cpu([int[]]$Ids) {
    $sum = 0.0
    foreach ($id in $Ids) {
        $p = Get-Process -Id $id -ErrorAction SilentlyContinue
        if ($p) { $sum += $p.TotalProcessorTime.TotalSeconds }
    }
    return $sum
}

function Get-Mem([int[]]$Ids) {
    $private = [int64]0
    $ws = [int64]0
    foreach ($id in $Ids) {
        $p = Get-Process -Id $id -ErrorAction SilentlyContinue
        if ($p) {
            $private += [int64]$p.PrivateMemorySize64
            $ws += [int64]$p.WorkingSet64
        }
    }
    return @{ private_mb = [math]::Round($private / 1MB, 2); working_set_mb = [math]::Round($ws / 1MB, 2) }
}

function Get-Listen([int]$Root) {
    $ids = @(Get-Tree $Root)
    $names = @{}
    foreach ($id in $ids) {
        $p = Get-Process -Id $id -ErrorAction SilentlyContinue
        if ($p) { $names[$id] = $p.ProcessName }
    }
    $rows = @()
    $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $ids -contains $_.OwningProcess })
    foreach ($c in $tcp) {
        $role = "child"
        if ([int]$c.OwningProcess -eq $Root) { $role = "client" }
        $rows += @{ proto = "tcp"; local = "$($c.LocalAddress):$($c.LocalPort)"; process = [string]$names[[int]$c.OwningProcess]; role = $role }
    }
    $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $ids -contains $_.OwningProcess -and $_.LocalPort -lt 49152 })
    foreach ($c in $udp) {
        $role = "child"
        if ([int]$c.OwningProcess -eq $Root) { $role = "client" }
        $rows += @{ proto = "udp"; local = "$($c.LocalAddress):$($c.LocalPort)"; process = [string]$names[[int]$c.OwningProcess]; role = $role }
    }
    return $rows
}

function Save-Side([string]$Tool, $Client) {
    if ($null -eq $script:Side -or $script:Side -isnot [System.Collections.IDictionary]) {
        $script:Side = @{}
    }
    $map = $script:Side
    if (-not $map.ContainsKey($Tool)) {
        $map[$Tool] = @{ secrets = @{}; ports = @(); actions = @($Client.Actions) }
    }
    $slot = $map[$Tool]
    $found = $slot["secrets"]
    foreach ($row in @(Find-Secrets @($Client.ScanRoots))) {
        if ($row.path) { $found[$row.path] = @($row.kinds) }
    }
    if (@($slot["ports"]).Count -eq 0 -and $Client.Pid) {
        $slot["ports"] = @(Get-Listen ([int]$Client.Pid))
    }
}

function Get-Cap([string]$Tool) {
    $caps = $script:Caps
    if ($null -eq $caps -or $caps -isnot [System.Collections.IDictionary]) {
        throw "client capability table was not initialized"
    }
    $cap = $caps[$Tool]
    if ($null -eq $cap) { throw "no capability entry for $Tool" }
    return $cap
}

function Stop-NamedClients {
    foreach ($name in @("ashgate", "sing-box", "v2rayN")) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
            & taskkill.exe /T /F /PID $_.Id 2>&1 | Out-Null
        }
    }
    if ($script:LabProc -and -not $script:LabProc.HasExited) {
        $labPid = [int]$script:LabProc.Id
        Get-CimInstance Win32_Process -Filter "Name = 'xray.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
            if ([int]$_.ParentProcessId -ne $labPid) {
                & taskkill.exe /T /F /PID $_.ProcessId 2>&1 | Out-Null
            }
        }
    }
}

function Reset-Gates {
    Invoke-RestMethod -Method Post -Uri "$($script:Control)/gate?name=xhttp&mode=pass" | Out-Null
    Invoke-RestMethod -Method Post -Uri "$($script:Control)/gate?name=raw&mode=pass" | Out-Null
}

function Invoke-Captured([string]$Name, [string[]]$Names, [scriptblock]$Body) {
    & pktmon stop 2>&1 | Out-Null
    & pktmon filter remove 2>&1 | Out-Null
    $etl = Join-Path $script:CapDir "$Name.etl"
    & pktmon start --capture --pkt-size 0 --file-name $etl --file-size 256 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "packet capture did not start" }
    Start-Sleep -Milliseconds 1200
    try {
        # Callers dot-source this function so the body sees their variables.
        . $Body
    } finally {
        Start-Sleep -Milliseconds 700
        & pktmon stop 2>&1 | Out-Null
    }
    $pcap = Join-Path $script:CapDir "$Name.pcapng"
    & pktmon etl2pcap $etl --out $pcap 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { & pktmon pcapng $etl -o $pcap 2>&1 | Out-Null }
    if (-not (Test-Path $pcap)) { throw "packet capture produced no file" }
    $json = Join-Path $script:CapDir "$Name.json"
    $arg = @("pcap", "-in", $pcap, "-out", $json, "-net", "198.51.100.0/24", "-net", "2001:db8:2::/48")
    foreach ($n in $Names) { if ($n) { $arg += @("-name", $n) } }
    & $script:Lab @arg
    if ($LASTEXITCODE -ne 0) { throw "packet summary failed" }
    Remove-Item $etl, $pcap -Force -ErrorAction SilentlyContinue
    $script:LastCapture = Get-Content -Raw $json | ConvertFrom-Json
}

function Count-Name($Summary, [string]$Name) {
    $n = 0
    if (-not $Summary -or -not $Summary.packets) { return 0 }
    foreach ($p in @($Summary.packets)) {
        $hit = $false
        foreach ($d in @($p.dns)) {
            if (([string]$d).TrimEnd(".").ToLower() -eq $Name.ToLower()) { $hit = $true }
        }
        if ($hit) { $n++ }
    }
    return $n
}

function Count-Ip($Summary, [string]$Fragment) {
    $n = 0
    $frag = $Fragment.ToLower()
    if (-not $Summary -or -not $Summary.packets) { return 0 }
    foreach ($p in @($Summary.packets)) {
        $src = ([string]$p.src).ToLower()
        $dst = ([string]$p.dst).ToLower()
        if ($src.Contains($frag) -or $dst.Contains($frag)) { $n++ }
    }
    return $n
}

function Wait-Connected($Proc, [string]$LogPath) {
    $launch = [Diagnostics.Stopwatch]::StartNew()
    $deadline = (Get-Date).AddSeconds(90)
    $err = ""
    $ok = $false
    while ((Get-Date) -lt $deadline) {
        if ($Proc.HasExited) {
            $err = "client process exited $($Proc.ExitCode). $(Get-Tail $LogPath)"
            break
        }
        $r = Invoke-Probe $script:ProbeExe @("ping", "--url", $script:Ping, "--timeout", "4s")
        if ($r.ok) { $ok = $true; break }
        Start-Sleep -Milliseconds 800
    }
    if (-not $ok -and -not $err) { $err = "no response within 90s. $(Get-Tail $LogPath)" }
    return @{ ok = $ok; error = Hide-Secrets $err; seconds = [math]::Round($launch.Elapsed.TotalSeconds, 2) }
}

function Stop-OneClient($Client) {
    if (-not $Client -or -not $Client.Pid) { return }
    $procId = [int]$Client.Pid
    switch ($Client.Tool) {
        "ashgate" {
            & $script:AshgateExe quit 2>&1 | Out-Null
            Start-Sleep -Seconds 1
            if ($Client.Config) { & $script:AshgateExe cleanup -config $Client.Config 2>&1 | Out-Null }
        }
    }
    $alive = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if ($alive) { & taskkill.exe /T /F /PID $procId 2>&1 | Out-Null }
    if ($Client.Tool -eq "v2rayn") {
        Get-Process -Name v2rayN -ErrorAction SilentlyContinue | ForEach-Object { & taskkill.exe /T /F /PID $_.Id 2>&1 | Out-Null }
    }
}

function Start-Ashgate([string]$Transport, [bool]$KillSwitch, [bool]$Failover) {
    $dir = Join-Path $script:Out "clients\ashgate"
    New-Item -ItemType Directory -Force $dir | Out-Null
    $cfg = Join-Path $dir "config.json"
    $mode = $(if ($Failover) { "failover" } else { "single" })
    $ks = $(if ($KillSwitch) { "true" } else { "false" })
    $setup = [Diagnostics.Stopwatch]::StartNew()
    & $script:Python (Join-Path $script:Compare "configs.py") ashgate --lab $script:LabJson --rules $script:Rules --probe $script:ProbeExe --out $cfg --kill-switch $ks --mode $mode --transport $Transport
    if ($LASTEXITCODE -ne 0) {
        return @{ Ok = $false; Error = "could not write configuration"; Pid = 0; Tool = "ashgate"; Actions = @(); ScanRoots = @() }
    }
    $setup.Stop()
    & $script:AshgateExe quit 2>&1 | Out-Null
    & $script:AshgateExe cleanup -config $cfg 2>&1 | Out-Null
    $proc = Start-Process -FilePath $script:AshgateExe -ArgumentList @("--autostart", "-config", $cfg) -PassThru
    $wait = Wait-Connected $proc (Join-Path $dir "ashgate.log")
    return @{
        Ok = $wait.ok; Error = $wait.error; Pid = $proc.Id; Tool = "ashgate"; Config = $cfg
        Actions = @("write configuration file", "start the client")
        SetupSeconds = [math]::Round($setup.Elapsed.TotalSeconds, 2)
        LaunchSeconds = $wait.seconds
        ScanRoots = @($dir, (Join-Path $env:LOCALAPPDATA "Ashgate"), (Join-Path $env:ProgramData "Ashgate"))
        Log = (Join-Path $dir "ashgate.log")
    }
}

function Start-SingBox([string]$Transport) {
    if ($Transport -ne "raw") {
        return @{ Ok = $false; Unsupported = $true; Error = "this build has no XHTTP transport"; Pid = 0; Tool = "sing-box"; Actions = @(); ScanRoots = @() }
    }
    $dir = Join-Path $script:Out "clients\sing-box"
    New-Item -ItemType Directory -Force $dir | Out-Null
    $cfg = Join-Path $dir "config.json"
    $log = Join-Path $dir "sing-box.log"
    $setup = [Diagnostics.Stopwatch]::StartNew()
    & $script:Python (Join-Path $script:Compare "configs.py") singbox --lab $script:LabJson --rules $script:Rules --probe-name "compare-probe.exe" --out $cfg --log $log --transport raw
    if ($LASTEXITCODE -ne 0) {
        return @{ Ok = $false; Error = "could not write configuration"; Pid = 0; Tool = "sing-box"; Actions = @(); ScanRoots = @($dir) }
    }
    $setup.Stop()
    $check = & $script:SingBoxExe check -c $cfg 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        return @{ Ok = $false; Error = ("configuration check failed. " + (Hide-Secrets $check)); Pid = 0; Tool = "sing-box"; Actions = @("write configuration file"); ScanRoots = @($dir) }
    }
    $proc = Start-Process -FilePath $script:SingBoxExe -ArgumentList @("run", "-c", $cfg) -PassThru -WindowStyle Hidden
    $wait = Wait-Connected $proc $log
    return @{
        Ok = $wait.ok; Error = $wait.error; Pid = $proc.Id; Tool = "sing-box"
        Actions = @("write configuration file", "start the client")
        SetupSeconds = [math]::Round($setup.Elapsed.TotalSeconds, 2)
        LaunchSeconds = $wait.seconds
        ScanRoots = @($dir); Log = $log
    }
}

function Start-V2rayN([string]$Transport) {
    $dir = Split-Path $script:V2Exe -Parent
    $db = $script:V2Db
    $gui = $script:V2Gui
    if (-not $script:V2Ready) {
        return @{ Ok = $false; Error = "application data was not created. $($script:V2SetupNote)"; Pid = 0; Tool = "v2rayn"; Actions = @(); ScanRoots = @() }
    }
    $setup = [Diagnostics.Stopwatch]::StartNew()
    & $script:Python (Join-Path $script:Compare "configs.py") v2rayn --lab $script:LabJson --rules $script:Rules --db $db --gui $gui --probe-name "compare-probe.exe" --transport $Transport
    if ($LASTEXITCODE -ne 0) {
        return @{ Ok = $false; Error = "could not import the server profile"; Pid = 0; Tool = "v2rayn"; Actions = @(); ScanRoots = @((Join-Path $dir "guiConfigs")) }
    }
    $setup.Stop()
    $proc = Start-Process -FilePath $script:V2Exe -WorkingDirectory $dir -PassThru
    $logDir = Join-Path $dir "guiLogs"
    $wait = Wait-Connected $proc $logDir
    $actions = @("import the server profile", "enable the per-app tunnel", "start the client")
    if (-not $script:V2Noted) {
        $actions = @("create the application data files") + $actions
        $script:V2Noted = $true
    }
    return @{
        Ok = $wait.ok; Error = $wait.error; Pid = $proc.Id; Tool = "v2rayn"; Actions = $actions
        SetupSeconds = [math]::Round($setup.Elapsed.TotalSeconds, 2)
        LaunchSeconds = $wait.seconds
        ScanRoots = @((Join-Path $dir "guiConfigs"), (Join-Path $dir "guiLogs"), (Join-Path $dir "binConfigs"), (Join-Path $env:LOCALAPPDATA "v2rayN"))
        Log = $logDir
    }
}

function Start-Client([string]$Tool, [string]$Transport, [bool]$KillSwitch, [bool]$Failover) {
    Reset-Gates
    switch ($Tool) {
        "ashgate" { return Start-Ashgate $Transport $KillSwitch $Failover }
        "sing-box" { return Start-SingBox $(if ($Failover) { "raw" } else { $Transport }) }
        "v2rayn" { return Start-V2rayN $(if ($Failover) { "failover" } else { $Transport }) }
        default { throw "unknown client" }
    }
}

function Measure-Transfer([int]$Root, [string]$Url, [string]$Mode) {
    $cpu0 = Get-Cpu @(Get-Tree $Root)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $bytes = [int64]0
    $err = ""
    while ($sw.Elapsed.TotalSeconds -lt $script:ThroughputSeconds) {
        $r = Invoke-Probe $script:ProbeExe @($Mode, "--url", $Url, "--bytes", "8388608", "--timeout", "25s")
        if (-not $r.ok) { $err = $r.error; break }
        $bytes += [int64]$r.bytes
    }
    $elapsed = [math]::Max($sw.Elapsed.TotalSeconds, 0.001)
    $cpu1 = Get-Cpu @(Get-Tree $Root)
    $mem = Get-Mem @(Get-Tree $Root)
    $mb = $bytes / 1MB
    $per = $null
    if ($mb -gt 0) { $per = [math]::Round(([math]::Max(0, $cpu1 - $cpu0) * 100) / $mb, 3) }
    return @{
        megabytes_per_second = $(if ($mb -gt 0) { [math]::Round($mb / $elapsed, 3) } else { $null })
        cpu_seconds_per_100mb = $per
        private_mb = $mem.private_mb
        working_set_mb = $mem.working_set_mb
        error = $err
    }
}

function Measure-Steady([string]$Tool, [string]$Transport) {
    $tag = "{0}-{1}-{2}" -f $Tool, $Transport, ([guid]::NewGuid().ToString("N").Substring(0, 6))
    $client = $null
    try {
        $client = Start-Client $Tool $Transport $false $false
        if (-not $client.Ok) {
            return @{ status = $(if ($client.Unsupported) { "unsupported" } else { "error" }); reason = [string]$client.Error; error = [string]$client.Error; actions = @($client.Actions) }
        }
        Save-Side $Tool $client
        $udpName = (New-Guid).ToString("N").Substring(0, 12) + ".probe.example"
        $tcpName = (New-Guid).ToString("N").Substring(0, 12) + ".probe.example"
        $lookupName = (New-Guid).ToString("N").Substring(0, 12) + ".probe.example"
        $bypassName = (New-Guid).ToString("N").Substring(0, 12) + ".probe.ru"
        ipconfig /flushdns | Out-Null
        $dnsProbe = @{ udp = $false; tcp = $false; lookup = $false }
        . Invoke-Captured "$tag-dns" @($udpName, $tcpName, $lookupName, $bypassName) {
            $a = Invoke-Probe $script:ProbeExe @("dns", "--proto", "udp", "--server", "1.1.1.1:53", "--name", $udpName, "--timeout", "4s")
            $b = Invoke-Probe $script:ProbeExe @("dns", "--proto", "tcp", "--server", "1.1.1.1:53", "--name", $tcpName, "--timeout", "4s")
            $c = Invoke-Probe $script:ProbeExe @("lookup", "--name", $lookupName, "--timeout", "6s")
            Invoke-Probe $script:ProbeExe @("lookup", "--name", $bypassName, "--timeout", "6s") | Out-Null
            $dnsProbe.udp = [bool]$a.ok
            $dnsProbe.tcp = [bool]$b.ok
            $dnsProbe.lookup = [bool]$c.ok
        }
        $dnsCap = $script:LastCapture
        $v4 = @{ ok = $false }
        . Invoke-Captured "$tag-v4" @() {
            $r = Invoke-Probe $script:ProbeExe @("ping", "--url", $script:Ping, "--timeout", "8s")
            $v4.ok = [bool]$r.ok
        }
        $v4cap = $script:LastCapture
        $v6 = @{ ok = $false }
        . Invoke-Captured "$tag-v6" @() {
            $r = Invoke-Probe $script:ProbeExe @("ping", "--url", $script:Ping6, "--timeout", "8s")
            $v6.ok = [bool]$r.ok
        }
        $v6cap = $script:LastCapture
        $ctl = @{ ok = $false }
        . Invoke-Captured "$tag-ctl" @() {
            $r = Invoke-Probe $script:ControlExe @("ping", "--url", $script:PingControl, "--timeout", "6s")
            $ctl.ok = [bool]$r.ok
        }
        $ctlcap = $script:LastCapture
        Invoke-RestMethod -Method Post -Uri "$($script:Control)/gate?name=$Transport&mode=refuse" | Out-Null
        $disc = @{ ok = $false }
        try {
            . Invoke-Captured "$tag-disc" @() {
                $r = Invoke-Probe $script:ProbeExe @("ping", "--url", $script:Ping, "--timeout", "6s")
                $disc.ok = [bool]$r.ok
            }
            $disccap = $script:LastCapture
        } finally {
            Reset-Gates
        }
        $down = Measure-Transfer $client.Pid $script:Down "down"
        $up = Measure-Transfer $client.Pid $script:Up "up"
        $lat = Invoke-Probe $script:ProbeExe @("latency", "--url", $script:Ping, "--count", "20", "--timeout", "5s")
        return @{
            status = "measured"
            actions = @($client.Actions)
            setup_seconds = $client.SetupSeconds
            launch_to_first_response_seconds = $client.LaunchSeconds
            dns_udp_tunnel_packets = (Count-Name $dnsCap $udpName)
            dns_tcp_tunnel_packets = (Count-Name $dnsCap $tcpName)
            dns_lookup_tunnel_packets = (Count-Name $dnsCap $lookupName)
            dns_lookup_bypass_packets = (Count-Name $dnsCap $bypassName)
            dns_udp_probe_ok = [bool]$dnsProbe.udp
            dns_tcp_probe_ok = [bool]$dnsProbe.tcp
            dns_lookup_probe_ok = [bool]$dnsProbe.lookup
            ipv4_leak_packets = (Count-Ip $v4cap "198.51.100.10")
            ipv4_probe_ok = [bool]$v4.ok
            ipv6_leak_packets = (Count-Ip $v6cap "2001:db8:2")
            ipv6_probe_ok = [bool]$v6.ok
            control_leak_packets = (Count-Ip $ctlcap "198.51.100.200")
            control_probe_ok = [bool]$ctl.ok
            disconnect_leak_packets = (Count-Ip $disccap "198.51.100.10")
            disconnect_probe_ok = [bool]$disc.ok
            down_megabytes_per_second = $down.megabytes_per_second
            down_cpu_seconds_per_100mb = $down.cpu_seconds_per_100mb
            down_private_mb = $down.private_mb
            up_megabytes_per_second = $up.megabytes_per_second
            up_cpu_seconds_per_100mb = $up.cpu_seconds_per_100mb
            up_private_mb = $up.private_mb
            latency_median_ms = $(if ($lat.ok) { $lat.median_ms } else { $null })
            latency_p95_ms = $(if ($lat.ok) { $lat.p95_ms } else { $null })
            error = Hide-Secrets (@($down.error, $up.error, $(if (-not $lat.ok) { $lat.error } else { "" })) -join " ").Trim()
        }
    } catch {
        return @{ status = "error"; error = Hide-Secrets $_.Exception.Message; actions = @() }
    } finally {
        if ($client) { Stop-OneClient $client }
        Stop-NamedClients
        Start-Sleep -Seconds 2
    }
}

function Measure-Failover([string]$Tool) {
    if (-not (Get-Cap $Tool).failover) {
        return @{ status = "unsupported"; reason = "failover between XHTTP and RAW requires both transports" }
    }
    $client = $null
    try {
        $client = Start-Client $Tool "xhttp" $false $true
        if (-not $client.Ok) { return @{ status = "error"; error = [string]$client.Error } }
        $before = Invoke-RestMethod "$($script:Control)/stats"
        Invoke-RestMethod -Method Post -Uri "$($script:Control)/gate?name=xhttp&mode=refuse" | Out-Null
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $ping = @{ ok = $false }
        $now = $before
        while ($sw.Elapsed.TotalSeconds -lt 200) {
            $ping = Invoke-Probe $script:ProbeExe @("ping", "--url", $script:Ping, "--timeout", "6s")
            $now = Invoke-RestMethod "$($script:Control)/stats"
            if ([int64]$now.raw -gt [int64]$before.raw -and $ping.ok) { break }
            Start-Sleep -Seconds 5
        }
        $increased = [int64]$now.raw -gt [int64]$before.raw
        return @{
            status = "measured"
            seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            backup_passed_increased = [bool]$increased
            probe_ok_after = [bool]$ping.ok
            switched = [bool]($increased -and $ping.ok)
        }
    } catch {
        return @{ status = "error"; error = Hide-Secrets $_.Exception.Message }
    } finally {
        Reset-Gates
        if ($client) { Stop-OneClient $client }
        Stop-NamedClients
        Start-Sleep -Seconds 2
    }
}

function Measure-Crash([string]$Tool, [string]$Transport, [bool]$KillSwitch) {
    $reason = ""
    if (-not $KillSwitch) {
        $reason = "no documented kill switch; crash and disconnect were still observed on the ordinary configuration"
    }
    $client = $null
    try {
        $client = Start-Client $Tool $Transport $KillSwitch $false
        if (-not $client.Ok) {
            return @{ status = $(if ($KillSwitch) { "error" } else { "unsupported" }); reason = $reason; error = [string]$client.Error }
        }
        $tag = "crash-$Tool"
        Invoke-RestMethod -Method Post -Uri "$($script:Control)/gate?name=$Transport&mode=refuse" | Out-Null
        $disc = @{ ok = $false }
        $disccap = $null
        try {
            . Invoke-Captured "$tag-disc" @() {
                $r = Invoke-Probe $script:ProbeExe @("ping", "--url", $script:Ping, "--timeout", "6s")
                $disc.ok = [bool]$r.ok
            }
            $disccap = $script:LastCapture
        } finally { Reset-Gates }
        $main = @{ ok = $false }
        . Invoke-Captured "$tag-main" @() {
            Stop-Process -Id $client.Pid -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            $r = Invoke-Probe $script:ProbeExe @("ping", "--url", $script:Ping, "--timeout", "6s")
            $main.ok = [bool]$r.ok
        }
        $mainCap = $script:LastCapture
        Stop-OneClient $client
        Stop-NamedClients
        Start-Sleep -Seconds 2
        $client = Start-Client $Tool $Transport $KillSwitch $false
        $tree = @{ ok = $false }
        $treeCap = $null
        if ($client.Ok) {
            . Invoke-Captured "$tag-tree" @() {
                & taskkill.exe /T /F /PID $client.Pid 2>&1 | Out-Null
                Start-Sleep -Seconds 1
                $r = Invoke-Probe $script:ProbeExe @("ping", "--url", $script:Ping, "--timeout", "6s")
                $tree.ok = [bool]$r.ok
            }
            $treeCap = $script:LastCapture
        }
        $status = $(if ($KillSwitch) { "measured" } else { "unsupported" })
        return @{
            status = $status
            reason = $reason
            feature_enabled = [bool]$KillSwitch
            transport = $Transport
            disconnect_leak_packets = $(if ($disccap) { Count-Ip $disccap "198.51.100.10" } else { $null })
            disconnect_probe_ok = [bool]$disc.ok
            crash_main_leak_packets = $(if ($mainCap) { Count-Ip $mainCap "198.51.100.10" } else { $null })
            crash_main_probe_ok = [bool]$main.ok
            crash_tree_leak_packets = $(if ($treeCap) { Count-Ip $treeCap "198.51.100.10" } else { $null })
            crash_tree_probe_ok = [bool]$tree.ok
        }
    } catch {
        return @{ status = "error"; error = Hide-Secrets $_.Exception.Message; reason = $reason }
    } finally {
        Reset-Gates
        if ($client) { Stop-OneClient $client }
        Stop-NamedClients
        Start-Sleep -Seconds 2
    }
}

function Measure-Soak([string]$Tool, [string]$Transport) {
    if ($script:SoakMinutes -le 0) { return @{ status = "skipped"; reason = "soak length was zero" } }
    $client = $null
    try {
        $client = Start-Client $Tool $Transport $false $false
        if (-not $client.Ok) { return @{ status = "error"; error = [string]$client.Error } }
        $samples = @()
        $start = Get-Date
        $end = $start.AddMinutes($script:SoakMinutes)
        $nextPing = $start
        while ((Get-Date) -lt $end) {
            if ((Get-Date) -ge $nextPing) {
                Invoke-Probe $script:ProbeExe @("ping", "--url", $script:Ping, "--timeout", "8s") | Out-Null
                $nextPing = (Get-Date).AddSeconds(15)
            }
            $mem = Get-Mem @(Get-Tree $client.Pid)
            $samples += @{
                t_seconds = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                private_mb = $mem.private_mb
                working_set_mb = $mem.working_set_mb
            }
            $remain = ($end - (Get-Date)).TotalSeconds
            if ($remain -le 0) { break }
            Start-Sleep -Seconds ([math]::Min(30, [math]::Max(1, $remain)))
        }
        $first = $samples[0]
        $last = $samples[-1]
        $maxP = ($samples | Measure-Object -Property private_mb -Maximum).Maximum
        return @{
            status = "measured"
            transport = $Transport
            minutes = $script:SoakMinutes
            private_mb_first = $first.private_mb
            private_mb_last = $last.private_mb
            private_mb_max = $maxP
            private_mb_delta = [math]::Round($last.private_mb - $first.private_mb, 2)
            working_set_mb_first = $first.working_set_mb
            working_set_mb_last = $last.working_set_mb
            working_set_mb_delta = [math]::Round($last.working_set_mb - $first.working_set_mb, 2)
            samples = @($samples)
        }
    } catch {
        return @{ status = "error"; error = Hide-Secrets $_.Exception.Message }
    } finally {
        if ($client) { Stop-OneClient $client }
        Stop-NamedClients
        Start-Sleep -Seconds 2
    }
}

function Start-Lab {
    $dir = Join-Path $script:Out "lab"
    New-Item -ItemType Directory -Force $dir | Out-Null
    $stdout = Join-Path $dir "lab.out"
    $stderr = Join-Path $dir "lab.err"
    $script:LabProc = Start-Process -FilePath $script:Lab -ArgumentList @("serve", "-xray", $script:XrayPath, "-out", $dir) -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $deadline = (Get-Date).AddSeconds(60)
    $json = Join-Path $dir "lab.json"
    while (-not (Test-Path $json)) {
        if ($script:LabProc.HasExited -or (Get-Date) -gt $deadline) {
            throw "lab did not start. $(Get-Tail $stderr)"
        }
        Start-Sleep -Milliseconds 300
    }
    $script:LabJson = $json
    $lab = Get-Content -Raw $json | ConvertFrom-Json
    $script:Control = [string]$lab.controlUrl
    $script:Ping = [string]$lab.echoPing
    $script:Ping6 = [string]$lab.echoV6
    $script:PingControl = [string]$lab.echoControl
    $script:Down = [string]$lab.echoDown
    $script:Up = [string]$lab.echoUp
    foreach ($s in @($lab.xhttp.uuid, $lab.raw.uuid, $lab.realityPublicKey, $lab.realityPrivateKey, $lab.shortId, $lab.xhttp.link, $lab.raw.link, $lab.subscriptionUrl)) {
        if ($s) { $script:Secrets.Add([string]$s) }
    }
    $script:Needles = @{
        uuid = [string]$lab.xhttp.uuid + "|" + [string]$lab.raw.uuid
        reality_public = [string]$lab.realityPublicKey
        reality_private = [string]$lab.realityPrivateKey
        short_id = [string]$lab.shortId
    }
    # uuid needle is checked per value, not as a joined string.
    $script:UuidValues = @([string]$lab.xhttp.uuid, [string]$lab.raw.uuid)
}

function Find-Secrets([string[]]$Roots) {
    $hits = @()
    foreach ($root in $Roots) {
        if (-not $root -or -not (Test-Path $root)) { continue }
        $files = @(Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
            $_.Length -lt 5MB -and $_.Extension -notin @(".exe", ".dll", ".sys", ".png", ".ico", ".dat", ".srs", ".mmdb")
        })
        foreach ($f in $files) {
            $text = ""
            try { $text = [System.IO.File]::ReadAllText($f.FullName) } catch { continue }
            if (-not $text) { continue }
            $kinds = @()
            foreach ($u in $script:UuidValues) { if ($u -and $text.Contains($u)) { $kinds += "uuid"; break } }
            if ($script:Needles.reality_public -and $text.Contains($script:Needles.reality_public)) { $kinds += "reality_public" }
            if ($script:Needles.reality_private -and $text.Contains($script:Needles.reality_private)) { $kinds += "reality_private" }
            if ($script:Needles.short_id -and $text.Contains($script:Needles.short_id) -and ($kinds -contains "uuid" -or $kinds -contains "reality_public")) {
                $kinds += "short_id"
            }
            if ($kinds.Count -gt 0) { $hits += @{ path = $f.FullName; kinds = @($kinds) } }
        }
    }
    return $hits
}

function Initialize-V2rayN {
    Write-Step "creating v2rayN application data"
    $dir = Split-Path $script:V2Exe -Parent
    $candidates = @(
        (Join-Path $dir "guiConfigs\guiNDB.db"),
        (Join-Path $env:LOCALAPPDATA "v2rayN\guiConfigs\guiNDB.db")
    )
    $proc = Start-Process -FilePath $script:V2Exe -WorkingDirectory $dir -PassThru
    $deadline = (Get-Date).AddSeconds(90)
    $db = $null
    $gui = $null
    while ((Get-Date) -lt $deadline) {
        foreach ($c in $candidates) {
            if (Test-Path $c) { $db = $c; break }
        }
        if ($db) {
            $candidateGui = Join-Path (Split-Path $db -Parent) "guiNConfig.json"
            if (Test-Path $candidateGui) { $gui = $candidateGui; break }
        }
        $alive = @(Get-Process -Name v2rayN -ErrorAction SilentlyContinue)
        if ($proc.HasExited -and $alive.Count -eq 0) { break }
        Start-Sleep -Seconds 1
    }
    $code = "running"
    if ($proc.HasExited) { $code = [string]$proc.ExitCode }
    if (-not $proc.HasExited) { & taskkill.exe /T /F /PID $proc.Id 2>&1 | Out-Null }
    Get-Process -Name v2rayN -ErrorAction SilentlyContinue | ForEach-Object { & taskkill.exe /T /F /PID $_.Id 2>&1 | Out-Null }
    Start-Sleep -Seconds 2
    if ($db -and -not $gui) {
        $gui = Join-Path (Split-Path $db -Parent) "guiNConfig.json"
        if (-not (Test-Path $gui)) { Set-Content -Encoding utf8 -Path $gui -Value "{}" }
    }
    $script:V2Db = $db
    $script:V2Gui = $gui
    $script:V2Ready = [bool]($db -and $gui -and (Test-Path $gui))
    $script:V2SetupNote = "exit=$code db=$db"
    if (-not $script:V2Ready) { Write-Step "v2rayN did not create its database ($($script:V2SetupNote))" }
}

function Stop-Lab {
    if ($script:LabProc -and -not $script:LabProc.HasExited) {
        & taskkill.exe /T /F /PID $script:LabProc.Id 2>&1 | Out-Null
    }
}

$fatal = $null
$doc = $null
try {
    $script:XrayPath = $Xray
    $script:ThroughputSeconds = $ThroughputSeconds
    $script:SoakMinutes = $SoakMinutes
    Write-Step "starting throwaway server"
    Start-Lab
    foreach ($transport in @("xhttp", "raw")) {
        Write-Step "server self-test $transport"
        & $script:Lab dial -xray $script:XrayPath -lab $script:LabJson -transport $transport
        if ($LASTEXITCODE -ne 0) { throw "server self-test failed for $transport" }
    }
    Initialize-V2rayN

    $cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    $cores = [int](Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    $pins = Get-Content -Raw (Join-Path $script:Compare "VERSIONS.json") | ConvertFrom-Json
    $sbPin = $pins.clients.'sing-box'
    $v2Pin = $pins.clients.v2rayn
    $ashVer = (Get-Content -Raw (Join-Path $script:Compare "..\version.json") | ConvertFrom-Json).version
    $ashPrint = ""
    try { $ashPrint = (& $script:AshgateExe version 2>&1 | Out-String).Trim() } catch { }
    $sbPrint = (& $script:SingBoxExe version 2>&1 | Out-String).Trim()

    $doc = @{
        runner = @{ cpu = [string]$cpu; os = [string]$os; logical_processors = $cores }
        scenario = @{
            rounds = $Rounds
            soak_minutes = $SoakMinutes
            throughput_seconds = $ThroughputSeconds
            latency_samples = 20
            bypass = "zones ru, su, рф and the listed Russian service domains; one workload executable is proxied"
            server = "local VLESS, generated keys, official xray $($pins.server.version)"
        }
        server = @{
            id = "xray-core"
            version = [string]$pins.server.version
            url = [string]$pins.server.url
            sha256 = [string]$pins.server.sha256
        }
        tools = @{
            ashgate = @{ version = [string]$ashVer; binary = $ashPrint; origin = "repository build of this pull request" }
            "sing-box" = @{ version = [string]$sbPin.version; binary = $sbPrint; url = [string]$sbPin.url; sha256 = [string]$sbPin.sha256 }
            v2rayn = @{ version = [string]$v2Pin.version; url = [string]$v2Pin.url; sha256 = [string]$v2Pin.sha256 }
        }
        rounds = @()
        once = @{}
    }
    $roundList = [System.Collections.Generic.List[object]]::new()

    for ($i = 1; $i -le $Rounds; $i++) {
        $order = @(Get-Shuffled $script:Tools)
        Write-Step ("round {0} order {1}" -f $i, ($order -join ","))
        $round = @{ index = $i; order = @($order); by_tool = @{} }
        foreach ($tool in $order) {
            $cap = Get-Cap $tool
            $torder = @(Get-Shuffled @("xhttp", "raw"))
            $by = $round["by_tool"]
            $by[$tool] = @{ transports = @{} }
            $transports = ($by[$tool])["transports"]
            foreach ($transport in $torder) {
                Write-Step "round $i $tool $transport"
                if (-not $cap[$transport]) {
                    $transports[$transport] = @{ status = "unsupported"; reason = "this build has no XHTTP transport" }
                    continue
                }
                $transports[$transport] = Measure-Steady $tool $transport
            }
        }
        $roundList.Add($round)
    }
    $doc.rounds = @($roundList)

    $onceOrder = @(Get-Shuffled $script:Tools)
    foreach ($tool in $onceOrder) {
        $cap = Get-Cap $tool
        $primary = $(if ($cap.xhttp) { "xhttp" } else { "raw" })
        Write-Step "failover $tool"
        $failover = Measure-Failover $tool
        Write-Step "kill-switch phase $tool"
        $kill = Measure-Crash $tool $primary ([bool]$cap.kill)
        Write-Step "soak $tool ($SoakMinutes min)"
        $soak = Measure-Soak $tool $primary
        # Copy first. A local named $side hides $script:Side on Windows PowerShell,
        # and a method call on that name then runs against null.
        $sideMap = $script:Side
        if ($null -eq $sideMap -or $sideMap -isnot [System.Collections.IDictionary]) {
            $sideMap = @{}
            $script:Side = $sideMap
        }
        $slot = $null
        if ($sideMap.ContainsKey($tool)) { $slot = $sideMap[$tool] }
        $secrets = @()
        $ports = @()
        $actions = @()
        if ($slot -and ($slot -is [System.Collections.IDictionary]) -and $slot.ContainsKey("secrets") -and $slot["secrets"]) {
            $table = $slot["secrets"]
            if ($table -is [System.Collections.IDictionary]) {
                foreach ($entry in @($table.GetEnumerator())) {
                    if (-not $entry.Key) { continue }
                    $secrets += @{ path = [string]$entry.Key; kinds = @($entry.Value) }
                }
            }
            if ($slot.ContainsKey("ports") -and $slot["ports"]) { $ports = @($slot["ports"]) }
            if ($slot.ContainsKey("actions") -and $slot["actions"]) { $actions = @($slot["actions"]) }
        }
        $once = $doc["once"]
        if ($null -eq $once) { $once = @{}; $doc["once"] = $once }
        $once[$tool] = @{
            failover = $failover
            kill_switch = $kill
            soak = $soak
            secrets = $secrets
            ports = $ports
            actions = $actions
        }
    }

    $missing = @()
    foreach ($tool in $script:Tools) {
        $cap = Get-Cap $tool
        $supported = @()
        if ($cap.xhttp) { $supported += "xhttp" }
        if ($cap.raw) { $supported += "raw" }
        $any = $false
        foreach ($round in @($doc.rounds)) {
            if ($round -isnot [System.Collections.IDictionary]) { continue }
            $by = $round["by_tool"]
            if ($by -isnot [System.Collections.IDictionary]) { continue }
            $block = $by[$tool]
            if ($block -isnot [System.Collections.IDictionary]) { continue }
            $transports = $block["transports"]
            if ($transports -isnot [System.Collections.IDictionary]) { continue }
            foreach ($transport in $supported) {
                $one = $transports[$transport]
                if ($one -and $one["status"] -eq "measured") { $any = $true }
            }
        }
        if (-not $any) { $missing += $tool }
    }
    $doc.clients_without_measurement = @($missing)
    if ($missing.Count -gt 0) {
        Write-Step ("recorded, not measured: " + ($missing -join ", "))
    }
} catch {
    $info = $_.InvocationInfo
    $fatal = $_.Exception.Message
    if ($info -and $info.PositionMessage) { $fatal = $fatal + "`n" + $info.PositionMessage }
    if ($_.ScriptStackTrace) { $fatal = $fatal + "`n" + $_.ScriptStackTrace }
    Write-Step "FAILED $fatal"
} finally {
    Stop-NamedClients
    Stop-Lab
    if ($doc) {
        $meas = Join-Path $script:Out "measurements.json"
        $doc | ConvertTo-Json -Depth 40 | Set-Content -Encoding utf8 $meas
        $publish = Join-Path $script:Out "publish"
        New-Item -ItemType Directory -Force (Join-Path $publish "raw") | Out-Null
        & $script:Python (Join-Path $script:Compare "assemble.py") $meas --results (Join-Path $publish "results.json") --mapping (Join-Path $publish "mapping.json")
        $script:AssembleCode = $LASTEXITCODE
        Copy-Item $meas (Join-Path $publish "raw\measurements.json") -Force
        $capPub = Join-Path $publish "raw\captures"
        New-Item -ItemType Directory -Force $capPub | Out-Null
        Copy-Item (Join-Path $script:CapDir "*.json") $capPub -Force -ErrorAction SilentlyContinue
        if (Test-Path $script:LabJson) {
            $public = Get-Content -Raw $script:LabJson | ConvertFrom-Json
            $public.realityPrivateKey = "***"
            $public | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $publish "raw\lab-public.json")
        }
        Remove-Item (Join-Path $script:Out "lab\xray-server.json") -Force -ErrorAction SilentlyContinue
    }
}

if ($fatal) { throw $fatal }
if ($null -ne $script:AssembleCode -and $script:AssembleCode -ne 0) { throw "could not write the blind results" }
Write-Step "comparison finished"
