# Windows Update Toolkit Friend - PowerShell Script
# Copyright (c) 2025 CygnusTech Ltd
# Licensed under the Apache License, Version 2.0.
# https://www.cygnustech.co.uk
# Last updated: 2025-10-14  (ISE-safe / PS5.1-compatible)

# ==========================================================
# LAUNCH GUARDRAILS: elevation + execution policy bypass
# ==========================================================
# Auto-elevate and bypass ExecutionPolicy without changing system-wide policy.
# This keeps the script portable and avoids interactive warnings.

try {
    $isAdmin = (
        [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        $elevArgs = @(
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy","Bypass",
            "-File","`"$PSCommandPath`""
        )
        Start-Process -FilePath "powershell.exe" -ArgumentList $elevArgs -Verb RunAs
        return
    }
} catch {
    Write-Host "Failed to self-elevate: $($_.Exception.Message)" -ForegroundColor Red
    throw
}

# ==========================================================
# TOOLKIT CONFIG (edit for your environment)
# ==========================================================

$ToolkitConfig = [ordered]@{
    # Verbose logging flag used by this script's own logging.
    # This no longer affects PowerShell's global $VerbosePreference, to keep
    # cmdlet verbose output off the console.
    VerboseLogging = $true

    # Optional WSUS details. If WsusServerName is non-empty, Enable-WSUS
    # can stamp WUServer/WUStatusServer using this value.
    WsusServerName  = 'my.wsus.server.contoso.com'
    WsusTargetGroup = ''
    WsusUseSsl      = $false   # http vs https when used

    # Maintenance window / reboot behaviour.
    # DefaultRebootTime is the HH:mm used for "schedule reboot in window".
    Maintenance = [ordered]@{
        WindowStart        = '03:30'   # HH:mm 24h
        WindowEnd          = '04:30'
        DefaultRebootTime  = '04:00'   # main configurable time for scheduled reboot
        JitterMinutes      = 0         # 0 = off; otherwise ±N mins
        OnlyIfRebootNeeded = $true     # schedule only if reboot is actually pending
        TaskPath           = '\WindowsUpdateToolkitFriend\Reboots\'
        TaskPrefix         = 'WindowsUpdateToolkitFriend-Reboot'
    }
}

# Convenience aliases to keep existing code readable
$VerboseLogging = $ToolkitConfig.VerboseLogging
$Maintenance    = $ToolkitConfig.Maintenance

# Keep PowerShell verbose output quiet globally; the script uses its own logging.
$VerbosePreference = 'SilentlyContinue'

# ==========================================================
# LOGGING (immediate write-to-disk)
# ==========================================================

try {
    $desktop = [Environment]::GetFolderPath('Desktop')  # handles OneDrive/KFM
    if (-not (Test-Path $desktop)) {
        $desktop = "$env:USERPROFILE\Desktop"           # fallback
    }
    $global:LogPath = Join-Path $desktop ("WindowsUpdateToolkit_Log_{0}.txt" -f (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
    New-Item -ItemType File -Path $global:LogPath -Force | Out-Null
} catch {
    $global:LogPath = Join-Path $env:TEMP ("WindowsUpdateToolkit_Log_{0}.txt" -f (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
    New-Item -ItemType File -Path $global:LogPath -Force | Out-Null
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp - $Message"
    Write-Output $entry
    try {
        Add-Content -Path $global:LogPath -Value $entry
    } catch {}
}

function Write-VerboseLog {
    param([string[]]$Lines)
    if ($VerboseLogging -and $Lines) {
        foreach ($l in $Lines) { Write-Log $l }
    }
}

# Capture PS streams and log
function Invoke-LoggedScript {
    param(
        [Parameter(Mandatory)][scriptblock]$Script
    )

    # Leave $VerbosePreference alone; script does not rely on cmdlet verbose output.
    & $Script 3>&1 4>&1 5>&1 6>&1 2>&1 | Tee-Object -Variable tee | Out-Null
    $tee | Write-Output

    if ($VerboseLogging -and $tee) {
        $tee | ForEach-Object { Write-Log ($_.ToString()) }
    }
}

# Run native tool with optional progress suppression
function Invoke-LoggedCommand {
    param(
        [Parameter(Mandatory)][string]$Command,
        [string[]]$SuppressPattern,
        [switch]$NormalizeForSuppression
    )

    Write-Log "Executing: $Command"

    $rawLines = Invoke-Expression "$Command 2>&1" | ForEach-Object { $_.ToString() }
    $lines = @()

    foreach ($line in $rawLines) {
        $comp = $line
        if ($NormalizeForSuppression) {
            # Strip console backspace/carriage-return noise when normalising
            $comp = $comp -replace '[\u0008\r]', ''
            $comp = $comp -replace '\s+', ''
        }

        $suppress = $false
        if ($SuppressPattern) {
            foreach ($pat in $SuppressPattern) {
                if ($comp -match $pat) { $suppress = $true; break }
            }
        }

        if (-not $suppress) { $lines += $line }
    }

    $lines | Write-Output
    if ($VerboseLogging -and $lines) {
        foreach ($l in $lines) { Write-Log $l }
    }
}

# ==========================================================
# CROSS-HOST PAUSE
# ==========================================================

function Wait-MenuReturn {
    if ($Host.Name -like '*ISE*') {
        $null = Read-Host "Press Enter to return to the menu..."
    } else {
        Write-Host "Press Enter to return to the menu..."
        [void][System.Console]::ReadLine()
    }
}

# Small helper for PS 5.1 to show defaults (no '??' available)
function Show-Value {
    param(
        [Parameter(Mandatory=$false)]$Value,
        [string]$Default = "(unknown)"
    )

    if ($null -ne $Value -and $Value -ne '') { return $Value }
    else { return $Default }
}

# ==========================================================
# OS Info and Update Source
# ==========================================================

function Get-OSInfo {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -Verbose:$false
    $cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    return @{
        ComputerName = $env:COMPUTERNAME
        Version      = $os.Version
        BuildNumber  = $os.BuildNumber
        Edition      = $cv.EditionID
    }
}

function Get-UpdateSource {
    $key   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $value = 'UseWUServer'

    if (Test-Path $key) {
        $useWUServer = (Get-ItemProperty -Path $key -Name $value -ErrorAction SilentlyContinue).$value
        if ($useWUServer -eq 1) { 'WSUS' } else { 'Microsoft Update' }
    } else {
        'Microsoft Update'
    }
}

# Helpers for last detect/install times
function Get-LastDetectTime {
    $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect'
    $t = (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).LastSuccessTime
    if ($t) { return $t }
    return $null
}

function Get-LastInstallTime {
    $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install'
    $t = (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).LastSuccessTime
    if ($t) { return $t }
    return $null
}

function Test-RebootPending {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    )

    $sessionMgr = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $pendingRen = (Get-ItemProperty -Path $sessionMgr -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pendingRen) { return $true }

    foreach ($p in $paths) {
        if (Test-Path $p) { return $true }
    }

    return $false
}

function Wait-ServiceRunning {
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$TimeoutSeconds = 30
    )

    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $st = (Get-Service -Name $Name -ErrorAction SilentlyContinue).Status
        if ($st -eq 'Running') { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Restart-ServicesLogged {
    param(
        [Parameter(Mandatory)][string[]]$Names,
        [int]$TimeoutSeconds = 30
    )

    foreach ($name in $Names) {
        try {
            $svc = Get-Service -Name $name -ErrorAction Stop
            $before = $svc.Status
            Write-Log "[$name] Current status: $before"

            $vb = Restart-Service -Name $name -ErrorAction Stop -Verbose 4>&1
            $vb | Write-Output
            Write-VerboseLog -Lines ($vb | ForEach-Object { "[$name] $_" })

            if (Wait-ServiceRunning -Name $name -TimeoutSeconds $TimeoutSeconds) {
                $after = (Get-Service -Name $name -ErrorAction SilentlyContinue).Status
                Write-Log "[$name] Status after restart: $after"
            } else {
                $curr = (Get-Service -Name $name -ErrorAction SilentlyContinue).Status
                Write-Log "[$name] Did not reach 'Running' within ${TimeoutSeconds}s (current: $curr)."
            }
        } catch {
            Write-Log "[$name] Restart failed: $_"
        }
    }
}

# ==========================================================
# CU/SSU/UBR INTELLIGENCE (read-only panel + export)
# ==========================================================

function Get-CUSSUInfo {
    Write-Log "Collecting CU/SSU/UBR info..."

    $cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
    $regUBR = $cv.UBR

    $start = Get-Date
    $lines = Invoke-LoggedCommand -Command 'DISM /Online /Get-Packages /English'
    $dur   = (Get-Date) - $start
    Write-Log ("Parsed DISM /Get-Packages in {0:N1}s" -f $dur.TotalSeconds)

    # Parse packages: identity + state
    $pkgs = @()
    $curr = [ordered]@{ Identity=$null; State=$null }

    foreach ($l in $lines) {
        if ($l -match '^\s*Package Identity\s*:\s*(.+)$') {
            if ($curr.Identity -or $curr.State) {
                $pkgs += [pscustomobject]$curr
                $curr = [ordered]@{ Identity=$null; State=$null }
            }
            $curr.Identity = $Matches[1].Trim()
        } elseif ($l -match '^\s*State\s*:\s*(.+)$') {
            $curr.State = $Matches[1].Trim()
        }
    }
    if ($curr.Identity -or $curr.State) { $pkgs += [pscustomobject]$curr }

    # Helpers to extract Build/UBR
    function Get-UbrFromRollup([string]$identity) {
        if ($identity -match '~~(\d+)\.(\d+)\.(\d+)\.(\d+)$') { return [int]$Matches[2] } # 20348.(3692).1.19
        return $null
    }
    function Get-BuildFromRollup([string]$identity) {
        if ($identity -match '~~(\d+)\.(\d+)\.(\d+)\.(\d+)$') { return [int]$Matches[1] }
        return $null
    }
    function Get-UbrFromSSU([string]$identity) {
        if ($identity -match 'Package_for_ServicingStack_(\d+)') { return [int]$Matches[1] }
        return $null
    }

    $rollups = $pkgs | Where-Object { $_.Identity -like '*Package_for_RollupFix*' -and $_.State -eq 'Installed' }
    $ssus    = $pkgs | Where-Object { $_.Identity -like '*Package_for_ServicingStack*' -and $_.State -eq 'Installed' }

    # Choose highest RollupFix by semantic version at the end
    $bestRollup = $rollups | Sort-Object -Property @{
        Expression = {
            if ($_.Identity -match '~~(\d+)\.(\d+)\.(\d+)\.(\d+)$') {
                [int64]("{0:D5}{1:D5}{2:D5}{3:D5}" -f $Matches[1],$Matches[2],$Matches[3],$Matches[4])
            } else { 0 }
        }
    } -Descending | Select-Object -First 1

    $bestSSU = $ssus | Sort-Object -Property @{
        Expression = {
            $u = Get-UbrFromSSU $_.Identity
            if ($null -ne $u) { [int64]$u } else { 0 }
        }
    } -Descending | Select-Object -First 1

    $lcuBuild = if ($bestRollup) { Get-BuildFromRollup $bestRollup.Identity } else { $null }
    $lcuUBR   = if ($bestRollup) { Get-UbrFromRollup   $bestRollup.Identity } else { $null }
    $ssuUBR   = if ($bestSSU)    { Get-UbrFromSSU      $bestSSU.Identity }    else { $null }

    $pending  = Test-RebootPending
    $detectT  = Get-LastDetectTime
    $installT = Get-LastInstallTime
    $osObj    = Get-CimInstance Win32_OperatingSystem -Verbose:$false

    [pscustomobject]@{
        ComputerName          = $env:COMPUTERNAME
        OSVersion             = $osObj.Version
        RegistryUBR           = $regUBR
        LCU_PackageIdentity   = if ($bestRollup) { $bestRollup.Identity } else { $null }
        LCU_EffectiveBuild    = if ($null -ne $lcuBuild -and $null -ne $lcuUBR) { "{0}.{1}" -f $lcuBuild,$lcuUBR } else { $null }
        LCU_State             = if ($bestRollup) { $bestRollup.State } else { $null }
        SSU_PackageIdentity   = if ($bestSSU) { $bestSSU.Identity } else { $null }
        SSU_Level             = $ssuUBR
        RebootPending         = [bool]$pending
        LastDetectTime        = $detectT
        LastInstallTime       = $installT
        UpdateSource          = Get-UpdateSource
        DismParseSeconds      = [math]::Round($dur.TotalSeconds,1)
    }
}

function Show-CUSSUPanel {
    $info = Get-CUSSUInfo

    Write-Host ""
    Write-Host "================ CU / SSU / UBR Status ================" -ForegroundColor Cyan
    Write-Host ("Computer Name        : {0}" -f (Show-Value $info.ComputerName))
    Write-Host ("OS Version           : {0}" -f (Show-Value $info.OSVersion))
    Write-Host ("Registry UBR         : {0}" -f (Show-Value $info.RegistryUBR '(unknown)'))
    Write-Host ("LCU Package          : {0}" -f (Show-Value $info.LCU_PackageIdentity '(not found)'))
    Write-Host ("LCU Effective Build  : {0}" -f (Show-Value $info.LCU_EffectiveBuild '(unknown)'))
    Write-Host ("SSU Package          : {0}" -f (Show-Value $info.SSU_PackageIdentity '(not found)'))
    Write-Host ("SSU Level (UBR-ish)  : {0}" -f (Show-Value $info.SSU_Level '(unknown)'))
    Write-Host ("Update Source        : {0}" -f (Show-Value $info.UpdateSource))
    Write-Host ("Last Detect Time     : {0}" -f (Show-Value $info.LastDetectTime 'none recorded'))
    Write-Host ("Last Install Time    : {0}" -f (Show-Value $info.LastInstallTime 'none recorded'))
    Write-Host ("Reboot Pending       : {0}" -f (Show-Value $info.RebootPending))
    Write-Host ("DISM Parse (sec)     : {0}" -f (Show-Value $info.DismParseSeconds))
    Write-Host "======================================================="

    # UBR comparison advisory
    $regU = $info.RegistryUBR
    $effU = $null
    if ($info.LCU_EffectiveBuild -and ($info.LCU_EffectiveBuild -match '^\d+\.(\d+)$')) {
        $effU = [int]$Matches[1]
    }

    if ($null -ne $regU -and $null -ne $effU -and $regU -ne $effU) {
        Write-Host ("Advisory: Registry UBR ({0}) differs from LCU-derived UBR ({1}) — staged/pending or sensor stale." -f $regU,$effU) -ForegroundColor Yellow
    }

    # SSU missing advisory
    if (-not $info.SSU_PackageIdentity) {
        Write-Host "Advisory: No Servicing Stack package was found in DISM output. On some builds this can be expected, but if servicing issues persist, confirm the latest SSU is installed." -ForegroundColor Yellow
    } elseif ($null -ne $info.SSU_Level -and $null -ne $effU -and $info.SSU_Level -lt ($effU - 1)) {
        Write-Host ("Advisory: SSU level ({0}) lags significantly behind LCU UBR ({1}); servicing stack may be outdated." -f $info.SSU_Level,$effU) -ForegroundColor Yellow
    }

    # Detect/install times advisory
    if (-not $info.LastDetectTime) {
        Write-Host "Advisory: Last detect time is not recorded in the Windows Update results key. This can happen if the machine has never completed a successful scan on this OS image." -ForegroundColor Yellow
    }
    if (-not $info.LastInstallTime) {
        Write-Host "Advisory: Last install time is not recorded. If this machine is known to have installed updates, check whether the Windows Update results registry keys are being maintained correctly." -ForegroundColor Yellow
    }
}

function Export-CUSSUCsv {
    param([string]$Path)

    if (-not $Path) {
        $Path = Join-Path ([Environment]::GetFolderPath('Desktop')) ("CUSSU_{0}.csv" -f (Get-Date -Format 'yyyy-MM-dd_HHmmss'))
    }

    $o = Get-CUSSUInfo
    $o | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    Write-Log "Exported CU/SSU CSV to $Path"
    Write-Output "Exported to: $Path"
}

# ==========================================================
# SERVICING SNAPSHOT (SSU + staged packages)
# ==========================================================

function Get-ServicingStackSummary {
    # Shows the latest Servicing Stack entry from DISM /Get-Packages.
    try {
        $cmd = 'DISM /Online /Get-Packages /English | findstr /i ServicingStack'
        Write-Log "Querying servicing stack via: $cmd"
        $output = cmd.exe /c $cmd 2>&1 | ForEach-Object { $_.ToString() }

        if (-not $output -or $output.Count -eq 0) {
            return '(no ServicingStack packages found)'
        }

        $last = $output[-1].Trim()
        return $last
    } catch {
        Write-Log "Get-ServicingStackSummary failed: $_"
        return '(error reading servicing stack – see log)'
    }
}

function Get-StagedPackageList {
    # Returns staged packages if the DISM PowerShell cmdlet is available.
    if (-not (Get-Command Get-WindowsPackage -ErrorAction SilentlyContinue)) {
        Write-Log "Get-WindowsPackage not available on this OS/session."
        return @()
    }

    try {
        $pkgs = Get-WindowsPackage -Online |
            Where-Object { $_.PackageState -eq 'Staged' }

        return $pkgs
    } catch {
        Write-Log "Get-StagedPackageList failed: $_"
        return @()
    }
}

function Show-ServicingSnapshot {
    # Compact view: servicing stack line + staged package summary.
    Write-Log "Showing servicing snapshot (ServicingStack + staged packages)."

    $ssLine = Get-ServicingStackSummary
    $staged = Get-StagedPackageList
    $count  = $staged.Count

    Write-Host ""
    Write-Host "================ Servicing Snapshot ====================" -ForegroundColor Cyan
    Write-Host ("Servicing Stack (DISM) : {0}" -f $ssLine)
    if ($count -gt 0) {
        Write-Host ("Staged packages        : {0}" -f $count)
        Write-Host "Use 'Remove staged packages' in the advanced menu with care."
    } else {
        Write-Host "Staged packages        : none reported."
    }
    Write-Host "======================================================="
}

# ==========================================================
# HEALTH SUMMARY (light)
# ==========================================================

function Show-HealthSummary {
    Write-Log "Generating health summary..."

    $updateSource = Get-UpdateSource
    $winhttpProxy = (netsh winhttp show proxy) 2>&1
    $svcs = @('wuauserv','bits','dosvc','waasmedicsvc','cryptsvc','trustedinstaller') | ForEach-Object {
        $s = Get-Service -Name $_ -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Name   = $_
            Status = if ($s) { $s.Status } else { 'NotFound' }
        }
    }
    $sysDrive = Get-PSDrive -Name C -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "================ Health Summary =======================" -ForegroundColor Cyan
    Write-Host ("Update Source   : {0}" -f $updateSource)
    Write-Host "Services:"
    $svcs | Format-Table Name,Status -AutoSize | Out-String | Write-Host
    Write-Host ("WinHTTP Proxy   :")
    $winhttpProxy | ForEach-Object { "  $_" } | Write-Host
    if ($sysDrive) {
        Write-Host ("System Drive C: : {0:N2} GB free" -f ($sysDrive.Free/1GB))
    }
    Write-Host ("Reboot Pending  : {0}" -f (Test-RebootPending))
    Write-Host "======================================================="
}

# ==========================================================
# ACTIONS (core tools)
# ==========================================================

function Clear-WindowsUpdateCache {
    Write-Log "Stopping Windows Update services..."
    Invoke-LoggedScript { Stop-Service -Name wuauserv,bits -Force -Verbose }

    $dir = Join-Path $env:SystemRoot 'SoftwareDistribution'
    $toDelete = @(Get-ChildItem $dir -Recurse -Force -ErrorAction SilentlyContinue)
    Write-Log "SoftwareDistribution items queued for delete: $($toDelete.Count)"

    Write-Log "Deleting SoftwareDistribution contents..."
    Invoke-LoggedScript {
        Remove-Item (Join-Path $dir '*') -Recurse -Force -Verbose -ErrorAction SilentlyContinue
    }

    Write-Log "Starting Windows Update services..."
    Invoke-LoggedScript { Start-Service -Name wuauserv,bits -Verbose }

    (Get-Service wuauserv,bits | Select-Object Name,Status) | ForEach-Object {
        Write-Log ("{0} status: {1}" -f $_.Name,$_.Status)
    }

    Write-Log "Windows Update cache cleared."
}

function Disable-WSUS {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    Write-Log "Disabling WSUS (switching to Microsoft Update)..."

    $prev = $null
    if (Test-Path $key) {
        $prev = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).UseWUServer
    }
    Write-Log "Previous UseWUServer: $prev"

    if (Test-Path $key) {
        Invoke-LoggedScript { Set-ItemProperty -Path $key -Name UseWUServer -Value 0 -Verbose }
        Invoke-LoggedScript { Restart-Service -Name wuauserv -Verbose }
    } else {
        Write-Log "WSUS registry key not found; likely already on Microsoft Update."
    }

    $src = Get-UpdateSource
    Write-Log "Effective update source after change: $src"
}

function Enable-WSUS {
    $keyWU = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $keyAU = "$keyWU\AU"
    Write-Log "Enabling WSUS..."

    Invoke-LoggedScript {
        if (-not (Test-Path $keyWU)) { New-Item -Path $keyWU -Verbose | Out-Null }
    }
    Invoke-LoggedScript {
        if (-not (Test-Path $keyAU)) { New-Item -Path $keyAU -Verbose | Out-Null }
    }

    $prev = (Get-ItemProperty -Path $keyAU -ErrorAction SilentlyContinue).UseWUServer
    Write-Log "Previous UseWUServer: $prev"

    # If a WSUS server name is configured, stamp WUServer/WUStatusServer
    if ($ToolkitConfig.WsusServerName) {
        $scheme = if ($ToolkitConfig.WsusUseSsl) { 'https' } else { 'http' }
        $url    = '{0}://{1}' -f $scheme, $ToolkitConfig.WsusServerName

        Invoke-LoggedScript {
            Set-ItemProperty -Path $keyWU -Name WUServer       -Value $url   -Verbose
        }
        Invoke-LoggedScript {
            Set-ItemProperty -Path $keyWU -Name WUStatusServer -Value $url   -Verbose
        }

        if ($ToolkitConfig.WsusTargetGroup) {
            Invoke-LoggedScript {
                Set-ItemProperty -Path $keyWU -Name TargetGroup -Value $ToolkitConfig.WsusTargetGroup -Verbose
            }
        }
    }

    Invoke-LoggedScript { Set-ItemProperty -Path $keyAU -Name UseWUServer -Value 1 -Verbose }
    Invoke-LoggedScript { Restart-Service -Name wuauserv -Verbose }

    $src = Get-UpdateSource
    Write-Log "Effective update source after change: $src"
}

function Invoke-SFCScan {
    Write-Output "Heads up: SFC can take 10–30 minutes. The console may look idle at times—don't close it."
    Write-Log    "SFC started (may take 10–30 minutes)."

    $sfcVerificationMultiNorm = '(?i)^(verification[0-9]{1,3}%complete\.)+$'
    $blankNorm                = '^$'

    Invoke-LoggedCommand -Command "sfc /scannow" `
        -SuppressPattern @($sfcVerificationMultiNorm,$blankNorm) `
        -NormalizeForSuppression

    Write-Log "SFC scan complete."
}

$dismProgressPattern = '^\s*\[[=\s]+[0-9]{1,3}(\.[0-9])?%[=\s]+\]\s*$'
$blankLinePattern    = '^\s*$'

function Invoke-DISMScanHealth {
    Write-Output "Heads up: DISM /ScanHealth may take 5–20 minutes. It can appear to pause—don't close it."
    Write-Log    "DISM /ScanHealth started (may take 5–20 minutes)."

    Invoke-LoggedCommand -Command "DISM /Online /Cleanup-Image /ScanHealth" `
        -SuppressPattern @($dismProgressPattern,$blankLinePattern)

    Write-Log "DISM /ScanHealth complete."
}

function Invoke-DISMRestoreHealth {
    Write-Output "Heads up: DISM /RestoreHealth may take 10–30 minutes. It can appear to pause—don't close it."
    Write-Log    "DISM /RestoreHealth started (may take 10–30 minutes)."

    Invoke-LoggedCommand -Command "DISM /Online /Cleanup-Image /RestoreHealth" `
        -SuppressPattern @($dismProgressPattern,$blankLinePattern)

    Write-Log "DISM /RestoreHealth complete."
}

function Invoke-WindowsUpdateScan {
    $before = Get-LastDetectTime
    Write-Log "Triggering Windows Update scan... (previous LastSuccessTime: $before)"

    Invoke-LoggedCommand -Command "UsoClient StartScan"
    Start-Sleep -Seconds 3

    $after = Get-LastDetectTime
    Write-Log "LastSuccessTime after trigger: $after"
}

function Restart-WUService {
    Write-Log "Restarting Windows Update related services..."
    Restart-ServicesLogged -Names @('wuauserv','bits')
    Write-Log "Requested services processed."
}

function Show-UpdateSource {
    $src = Get-UpdateSource
    Write-Log "Update source: $src"
    Write-Output "`nUpdate Source: $src`n"
}

function Open-CBSLog {
    $cbs = Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'
    if (Test-Path $cbs) {
        Write-Log "Opening CBS.log at $cbs"
        Start-Process notepad.exe $cbs
    } else {
        Write-Log "CBS.log not found at expected path: $cbs"
    }
}

function Open-DISMLog {
    $dismLog = Join-Path $env:SystemRoot 'Logs\DISM\dism.log'
    if (Test-Path $dismLog) {
        Write-Log "Opening DISM.log at $dismLog"
        Start-Process notepad.exe $dismLog
    } else {
        Write-Log "DISM.log not found at expected path: $dismLog"
    }
}

function Export-WindowsUpdateLog {
    Write-Output "Heads up: Exporting WindowsUpdate.log can take several minutes."
    $dest = Join-Path ([Environment]::GetFolderPath('Desktop')) 'WindowsUpdate.log'

    Write-Log "Exporting WindowsUpdate.log to $dest ..."
    Invoke-LoggedScript { Get-WindowsUpdateLog -LogPath $dest -Verbose }

    if (Test-Path $dest) {
        $sz = (Get-Item $dest).Length
        Write-Log ("WindowsUpdate.log exported ({0:N0} bytes)." -f $sz)
    } else {
        Write-Log "Export failed: file not found at $dest"
    }
}

function Open-WindowsUpdateLog {
    $dest = Join-Path ([Environment]::GetFolderPath('Desktop')) 'WindowsUpdate.log'
    if (Test-Path $dest) {
        Write-Log "Opening WindowsUpdate.log at $dest"
        Start-Process notepad.exe $dest
    } else {
        Write-Log "WindowsUpdate.log not found at $dest. Use 'Export WindowsUpdate.log' first."
    }
}

function Remove-PendingUpdates {
    Write-Output "Heads up: Removing pending updates can take several minutes."
    Write-Log    "Removing pending updates (may take several minutes)..."

    Invoke-LoggedScript {
        Stop-Service wuauserv,bits,trustedinstaller -Force -Verbose -ErrorAction SilentlyContinue
    }

    $pendingXml = "$env:SystemRoot\WinSxS\pending.xml"
    if (Test-Path $pendingXml) {
        $sz = (Get-Item $pendingXml).Length
        Invoke-LoggedScript {
            Remove-Item $pendingXml -Force -Verbose -ErrorAction SilentlyContinue
        }
        Write-Log ("Removed pending.xml ({0:N0} bytes)" -f $sz)
    } else {
        Write-Log "No pending.xml found"
    }

    $downloadDir = "$env:SystemRoot\SoftwareDistribution\Download"
    if (Test-Path $downloadDir) {
        $files = @(Get-ChildItem "$downloadDir" -Recurse -Force -ErrorAction SilentlyContinue)
        Write-Log "Files queued for delete in Download: $($files.Count)"
        Invoke-LoggedScript {
            Remove-Item "$downloadDir\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue
        }
    } else {
        Write-Log "Download folder not found"
    }

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    if (Test-Path $regPath) {
        Invoke-LoggedScript {
            Remove-Item -Path $regPath -Recurse -Force -Verbose -ErrorAction SilentlyContinue
        }
        Write-Log "Removed RebootPending registry key"
    } else {
        Write-Log "No RebootPending registry key found"
    }

    Invoke-LoggedScript {
        Start-Service wuauserv,bits,trustedinstaller -Verbose -ErrorAction SilentlyContinue
    }

    (Get-Service wuauserv,bits,trustedinstaller -ErrorAction SilentlyContinue) | ForEach-Object {
        Write-Log ("{0} status: {1}" -f $_.Name,$_.Status)
    }

    Write-Log "Pending update cleanup done."
}

# ==========================================================
# ADVANCED: staged package removal
# ==========================================================

function Remove-StagedPackages {
    # Attempts to remove all staged packages using Remove-WindowsPackage.
    if (-not (Get-Command Get-WindowsPackage -ErrorAction SilentlyContinue)) {
        Write-Host "Get-WindowsPackage is not available on this system." -ForegroundColor Yellow
        Write-Log "Remove-StagedPackages aborted – Get-WindowsPackage missing."
        return
    }

    Write-Host ""
    Write-Host "WARNING: this will attempt to remove *all* staged packages." -ForegroundColor Yellow
    Write-Host "Only use this if you understand the impact on the servicing stack." -ForegroundColor Yellow
    Write-Host ""
    $confirm = Read-Host "Type REMOVE in uppercase to continue"

    if ($confirm -ne 'REMOVE') {
        Write-Host "Aborted by user."
        Write-Log "Remove-StagedPackages aborted by user."
        return
    }

    $staged = Get-StagedPackageList
    if (-not $staged -or $staged.Count -eq 0) {
        Write-Host "No staged packages found."
        Write-Log "Remove-StagedPackages: nothing to remove."
        return
    }

    Write-Log ("Remove-StagedPackages: found {0} staged package(s)." -f $staged.Count)

    foreach ($pkg in $staged) {
        $name = $pkg.PackageName
        Write-Host ("Removing {0}" -f $name)
        Write-Log  ("Attempting Remove-WindowsPackage for {0}" -f $name)

        try {
            Remove-WindowsPackage -Online -PackageName $name -NoRestart -ErrorAction Stop | Out-Null
            Write-Log ("Remove-WindowsPackage succeeded for {0}" -f $name)
        } catch {
            Write-Log ("Remove-WindowsPackage FAILED for {0}: {1}" -f $name, $_)
            Write-Host ("Failed removing {0} – see log." -f $name) -ForegroundColor Yellow
        }
    }

    Write-Log "Remove-StagedPackages completed."
}

# ==========================================================
# ADVANCED: CBS\Packages ACL helper
# ==========================================================

function Backup-And-Relax-CbsPackagesAcl {
    # Backs up HKLM:\...\CBS\Packages then grants Everyone:FullControl on it + children.
    $regPath       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
    $regNativePath = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'

    Write-Host ""
    Write-Host "ADVANCED: CBS\Packages ACL change" -ForegroundColor Yellow
    Write-Host "This exports the key to a .reg file then sets owner + ACL to Everyone (local)." -ForegroundColor Yellow
    Write-Host "If in doubt, cancel and do it manually in regedit with a VM snapshot." -ForegroundColor Yellow
    Write-Host ""

    if (-not (Test-Path $regPath)) {
        Write-Host "Registry path not found: $regPath" -ForegroundColor Red
        Write-Log  "Backup-And-Relax-CbsPackagesAcl aborted – path not found."
        return
    }

    $confirm = Read-Host "Type ACLFIX in uppercase to continue"
    if ($confirm -ne 'ACLFIX') {
        Write-Host "Aborted by user."
        Write-Log "Backup-And-Relax-CbsPackagesAcl aborted by user."
        return
    }

    # Backup destination
    try {
        $desktop    = [Environment]::GetFolderPath('Desktop')
        $backupRoot = Join-Path $desktop 'WindowsUpdateToolkit_RegistryBackups'
        if (-not (Test-Path $backupRoot)) { New-Item -ItemType Directory -Path $backupRoot | Out-Null }
        $backupFile = Join-Path $backupRoot ("CBS_Packages_{0}.reg" -f (Get-Date -Format 'yyyy-MM-dd_HHmmss'))

        Write-Log ("Exporting CBS\Packages registry branch to {0}" -f $backupFile)
        & reg.exe export $regNativePath $backupFile /y | Out-Null
        Write-Log "Registry export completed."
    } catch {
        Write-Log "Registry export failed: $_"
        Write-Host "Registry export failed – see log. Aborting ACL change." -ForegroundColor Red
        return
    }

    # ACL change
    try {
        $sidEveryone = New-Object System.Security.Principal.SecurityIdentifier 'S-1-1-0'
        $regRights   = [System.Security.AccessControl.RegistryRights]::FullControl
        $inherit     = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
        $propFlags   = [System.Security.AccessControl.PropagationFlags]::None
        $accessType  = [System.Security.AccessControl.AccessControlType]::Allow

        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $sidEveryone, $regRights, $inherit, $propFlags, $accessType
        )

        Write-Log "Applying Everyone:FullControl ACL to CBS\Packages and subkeys."

        Get-ChildItem -Path $regPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $keyPath = $_.PsPath
            try {
                $acl = Get-Acl -Path $keyPath
                $acl.SetOwner($sidEveryone)
                $acl.SetAccessRule($rule)
                Set-Acl -Path $keyPath -AclObject $acl
            } catch {
                Write-Log ("ACL update failed for {0}: {1}" -f $keyPath, $_)
            }
        }

        # Also apply to the root key itself
        try {
            $rootAcl = Get-Acl -Path $regPath
            $rootAcl.SetOwner($sidEveryone)
            $rootAcl.SetAccessRule($rule)
            Set-Acl -Path $regPath -AclObject $rootAcl
        } catch {
            Write-Log ("ACL update failed for root {0}: {1}" -f $regPath, $_)
        }

        Write-Log "Backup-And-Relax-CbsPackagesAcl completed."
        Write-Host "CBS\Packages ACL updated. If anything misbehaves, import the .reg backup or revert snapshot." -ForegroundColor Green
    } catch {
        Write-Log "Backup-And-Relax-CbsPackagesAcl overall failure: $_"
        Write-Host "ACL change hit an error – see log for details." -ForegroundColor Red
    }
}

# ==========================================================
# ADVANCED: CurrentState reset
# ==========================================================

function Reset-CbsPackageCurrentState {
    # Resets specific CBS\Packages CurrentState values to 0.
    $regRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
    $name    = 'CurrentState'

    Write-Host ""
    Write-Host "EXTREME CAUTION: CBS CurrentState mass edit" -ForegroundColor Red
    Write-Host "This walks CBS\Packages and forces certain CurrentState values to 0." -ForegroundColor Red
    Write-Host "Only run this with a tested rollback path (snapshot/backup) and clear guidance." -ForegroundColor Red
    Write-Host ""

    if (-not (Test-Path $regRoot)) {
        Write-Host "Registry path not found: $regRoot" -ForegroundColor Red
        Write-Log  "Reset-CbsPackageCurrentState aborted – path not found."
        return
    }

    $confirm = Read-Host "Type CURRENTSTATE in uppercase to continue"
    if ($confirm -ne 'CURRENTSTATE') {
        Write-Host "Aborted by user."
        Write-Log "Reset-CbsPackageCurrentState aborted by user."
        return
    }

    Write-Log "Reset-CbsPackageCurrentState starting."

    $targets = Get-ChildItem -Path $regRoot -Recurse -ErrorAction SilentlyContinue

    foreach ($item in $targets) {
        try {
            $keyPath = $item.Name.Replace('HKEY_LOCAL_MACHINE', 'HKLM:')
            $props   = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
            if (-not $props) { continue }

            $state = $props.$name
            if ($null -eq $state) { continue }

            if ($state -eq 0x50 -or
                $state -eq 0x40 -or
                $state -eq 0x60 -or
                $state -eq 0x5  -or
                $state -eq 0x65) {

                Write-Host ("Fixing: {0}  State={1}" -f $keyPath, $state)
                Write-Log  ("Resetting {0} CurrentState from {1} to 0" -f $keyPath, $state)
                Set-ItemProperty -Path $keyPath -Name $name -Value 0 -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Log ("Reset-CbsPackageCurrentState error on {0}: {1}" -f $item.Name, $_)
        }
    }

    Write-Log "Reset-CbsPackageCurrentState completed."
}

# ==========================================================
# REBOOT SCHEDULING (maintenance-window friendly)
# ==========================================================

function Get-MaintenanceDateTime {
    param(
        [string]$HHmm
    )
    # Returns next occurrence of HH:mm (today if in the future, otherwise tomorrow)
    $today = Get-Date
    $parts = $HHmm.Split(':')
    $h = [int]$parts[0]
    $m = [int]$parts[1]
    $targetToday = Get-Date -Hour $h -Minute $m -Second 0

    if ($targetToday -gt $today) { return $targetToday }
    else { return $targetToday.AddDays(1) }
}

function New-WindowsUpdateToolkitFriendRebootTask {
    param(
        [datetime]$When,
        [string]$Reason = "Windows Update Toolkit Friend scheduled reboot",
        [switch]$Force
    )

    # Guard: OnlyIfRebootNeeded
    if ($Maintenance.OnlyIfRebootNeeded -and -not $Force.IsPresent) {
        if (-not (Test-RebootPending)) {
            Write-Host "No reboot required. Use -Force to override." -ForegroundColor Yellow
            Write-Log  "Reboot not scheduled: no reboot pending (policy OnlyIfRebootNeeded=true)."
            return
        }
    }

    # Jitter (±N mins)
    if ($Maintenance.JitterMinutes -gt 0) {
        $delta = Get-Random -Minimum (-$Maintenance.JitterMinutes) -Maximum ($Maintenance.JitterMinutes+1)
        $When = $When.AddMinutes($delta)
    }

    # Validate window (warn if outside)
    $ws    = [TimeSpan]::Parse($Maintenance.WindowStart)
    $we    = [TimeSpan]::Parse($Maintenance.WindowEnd)
    $wtime = $When.TimeOfDay
    if (($wtime -lt $ws) -or ($wtime -gt $we)) {
        Write-Host ("WARNING: {0:HH:mm} is outside the configured window {1}-{2}." -f $When,$ws,$we) -ForegroundColor Yellow
    }

    $taskName  = "{0}-{1}-{2:yyyyMMdd-HHmm}" -f $Maintenance.TaskPrefix,$env:COMPUTERNAME,$When
    $action    = New-ScheduledTaskAction -Execute "shutdown.exe" -Argument "/r /t 120 /c `"$Reason`""
    $trigger   = New-ScheduledTaskTrigger -Once -At $When

    # LogonType must be one of: None, Password, S4U, Interactive, Group, ServiceAccount, InteractiveOrPassword
    $principal = New-ScheduledTaskPrincipal `
        -UserId   ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
        -LogonType Interactive `
        -RunLevel Highest

    try {
        Register-ScheduledTask `
            -TaskName    $taskName `
            -TaskPath    $Maintenance.TaskPath `
            -Action      $action `
            -Trigger     $trigger `
            -Principal   $principal `
            -Description $Reason `
            -Force | Out-Null

        Write-Log  ("Reboot scheduled: {0} at {1:yyyy-MM-dd HH:mm} (task {2}{3})" -f $env:COMPUTERNAME,$When,$Maintenance.TaskPath,$taskName)
        Write-Host ("Reboot scheduled for {0:yyyy-MM-dd HH:mm}. Task: {1}{2}" -f $When,$Maintenance.TaskPath,$taskName) -ForegroundColor Green
    } catch {
        Write-Log ("Failed to schedule reboot: $_")
        Write-Host "Failed to schedule reboot: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-WindowsUpdateToolkitFriendRebootTasks {
    try {
        $tasks = Get-ScheduledTask -TaskPath $Maintenance.TaskPath -ErrorAction Stop
        if (-not $tasks) {
            Write-Host "No Windows Update Toolkit Friend reboot tasks found."
            return
        }
        $tasks | Select-Object TaskName, State, LastRunTime, NextRunTime | Format-Table -AutoSize
    } catch {
        Write-Host "No Windows Update Toolkit Friend reboot tasks found."
    }
}

function Stop-WindowsUpdateToolkitFriendRebootTask {
    param([string]$TaskName)

    if (-not $TaskName) {
        Write-Host "Provide a task name shown by 'List Windows Update Toolkit Friend reboot tasks'." -ForegroundColor Yellow
        return
    }

    try {
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $Maintenance.TaskPath -Confirm:$false
        Write-Log "Cancelled Windows Update Toolkit Friend reboot task: $TaskName"
        Write-Host "Cancelled: $TaskName"
    } catch {
        Write-Host "Failed to cancel: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ==========================================================
# HELP / USAGE
# ==========================================================

function Show-ToolkitHelp {
    # Opens USAGE.md from the script directory if present.
    try {
        $usagePath = Join-Path $PSScriptRoot 'USAGE.md'
    } catch {
        $usagePath = '.\USAGE.md'
    }

    if (Test-Path $usagePath) {
        Write-Log ("Opening USAGE at {0}" -f $usagePath)
        Start-Process notepad.exe $usagePath | Out-Null
    } else {
        Write-Host "USAGE.md not found next to the script." -ForegroundColor Yellow
        Write-Log  "Show-ToolkitHelp: USAGE.md not found."
    }
}

# ==========================================================
# MAIN MENU LOOP
# ==========================================================

$running = $true
Write-Log "Logging to: $global:LogPath"

do {
    Clear-Host
    $osInfo       = Get-OSInfo
    $updateSource = Get-UpdateSource

    Write-Output "================ Windows Update Toolkit Friend ================"
    Write-Output "Computer Name     : $($osInfo.ComputerName)"
    Write-Output "OS Version        : $($osInfo.Version) (Build $($osInfo.BuildNumber))"
    Write-Output "Edition           : $($osInfo.Edition)"
    Write-Output "Update Source     : $updateSource"
    Write-Output "Log File          : $global:LogPath"
    Write-Output "Maintenance Time  : $($Maintenance.DefaultRebootTime) (local)"
    Write-Output "==============================================================="
    Write-Output " Core tools"
    Write-Output "==============================================================="
    Write-Output "  1.  Clear Windows Update cache"
    Write-Output "  2.  Disable WSUS (switch to Microsoft Update)"
    Write-Output "  3.  Enable WSUS"
    Write-Output "  4.  Run SFC scan               (may take 10–30 min)"
    Write-Output "  5.  Run DISM /ScanHealth       (may take 5–20 min)"
    Write-Output "  6.  Run DISM /RestoreHealth    (may take 10–30 min)"
    Write-Output "  7.  Trigger Windows Update scan"
    Write-Output "  8.  Restart Windows Update services"
    Write-Output "  9.  Show current update source"
    Write-Output " 10.  Open CBS.log"
    Write-Output " 11.  Open DISM.log"
    Write-Output " 12.  Export WindowsUpdate.log    (may take several minutes)"
    Write-Output " 13.  Open WindowsUpdate.log"
    Write-Output " 14.  Remove pending updates      (may take several minutes)"
    Write-Output "----- Diagnostics ------------------------------------------------"
    Write-Output " 15.  Show CU/SSU/UBR status (read-only panel)"
    Write-Output " 16.  Export CU/SSU CSV (this device)"
    Write-Output " 17.  Show Health Summary (read-only)"
    Write-Output " 18.  Show Servicing Snapshot (ServicingStack + staged pkgs)"
    Write-Output "----- Reboot scheduling -----------------------------------------"
    Write-Output " 19.  Schedule reboot for maintenance window (~$($Maintenance.DefaultRebootTime))"
    Write-Output " 20.  List Windows Update Toolkit Friend reboot tasks"
    Write-Output " 21.  Cancel a Windows Update Toolkit Friend reboot task"
    Write-Output "----- Advanced tools (handle with care) -------------------------"
    Write-Output " 22.  Remove all staged packages (DISM)"
    Write-Output " 23.  Backup + relax CBS\Packages ACL (Everyone:FullControl)"
    Write-Output " 24.  Reset CBS\Packages CurrentState flags"
    Write-Output " 25.  Open README / Help"
    Write-Output " 26.  Exit Toolkit Friend"
    Write-Output "=================================================================="

    $choiceRaw = Read-Host "Select an option (1-26)"
    [int]$choice = 0
    $valid = [int]::TryParse($choiceRaw, [ref]$choice)
    if (-not $valid) {
        Write-Output "`nInvalid input. Please enter a number from 1 to 26."
        Start-Sleep -Seconds 2
        continue
    }

    try {
        switch ($choice) {
            1  { Clear-WindowsUpdateCache }
            2  { Disable-WSUS }
            3  { Enable-WSUS }
            4  { Invoke-SFCScan }
            5  { Invoke-DISMScanHealth }
            6  { Invoke-DISMRestoreHealth }
            7  { Invoke-WindowsUpdateScan }
            8  { Restart-WUService }
            9  { Show-UpdateSource }
            10 { Open-CBSLog }
            11 { Open-DISMLog }
            12 { Export-WindowsUpdateLog }
            13 { Open-WindowsUpdateLog }
            14 { Remove-PendingUpdates }
            15 { Show-CUSSUPanel }
            16 { Export-CUSSUCsv }
            17 { Show-HealthSummary }
            18 { Show-ServicingSnapshot }
            19 {
                $when = Get-MaintenanceDateTime -HHmm $Maintenance.DefaultRebootTime
                New-WindowsUpdateToolkitFriendRebootTask -When $when
            }
            20 { Get-WindowsUpdateToolkitFriendRebootTasks }
            21 {
                $t = Read-Host "Enter exact task name to cancel (see option 20)"
                if ($t) { Stop-WindowsUpdateToolkitFriendRebootTask -TaskName $t }
            }
            22 { Remove-StagedPackages }
            23 { Backup-And-Relax-CbsPackagesAcl }
            24 { Reset-CbsPackageCurrentState }
            25 { Show-ToolkitHelp }
            26 {
                Write-Log "Exit selected. Stopping menu loop."
                $running = $false
            }
            default {
                Write-Output "`nInvalid selection. Please choose a number between 1 and 26."
                Start-Sleep -Seconds 2
            }
        }

        if ($running -and $choice -ne 26) {
            Wait-MenuReturn
        }

    } catch {
        Write-Log "Error occurred during selection ${choice}: $_"
        Write-Host "An error occurred while running option $choice. See the log for details." -ForegroundColor Red
    }

} while ($running)

Write-Output "`nLog saved to: $global:LogPath"
Write-Log "Toolkit finished."
