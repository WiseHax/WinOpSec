#!/usr/bin/env pwsh
[CmdletBinding()]
param (
    [switch]$Audit,
    [switch]$Recon,
    [switch]$Sentry,
    [switch]$AutoPanic,
    [switch]$SinglePass,
    [switch]$Mullvad,
    [switch]$Browser,
    [switch]$LaunchBrowser,
    [switch]$HardenAll,
    [switch]$WipeTraces,
    [switch]$PcaWipe,
    [switch]$ShellBags,
    [switch]$Srum,
    [switch]$ScrubWifi,
    [switch]$RandomizeHwId,
    [switch]$DeadMan,
    [string]$DeadManDrive,
    [switch]$WipeTokens,
    [switch]$WipeScreenshots,
    [switch]$WipeRegLogs,
    [switch]$Chameleon,
    [switch]$PurgeChameleon,
    [string]$Scrub,
    [switch]$SpoofMac,
    [switch]$ScanSecrets,
    [switch]$Panic,
    [switch]$Restore,
    [switch]$Hud,
    [switch]$NonInteractive,
    [switch]$WipeRam,
    [string]$Jitter,
    [switch]$Vanish,
    [switch]$Intro,
    [switch]$TestVoice,
    [switch]$VmShield,
    [switch]$AuditVm,
    [switch]$Help
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulePath = Join-Path $PSScriptRoot "modules"
foreach ($mod in @("Common.psm1", "BackupRestore.psm1", "Telemetry.psm1", "Anonymity.psm1", "NetworkOpSec.psm1", "EgressRecon.psm1", "BrowserOpSec.psm1", "AntiForensics.psm1", "SecretsScanner.psm1", "HwIdOpSec.psm1", "DeadManSwitch.psm1", "Chameleon.psm1", "SentryMonitor.psm1", "CanaryTrap.psm1", "UsbOpSec.psm1", "IntroTour.psm1", "VmShield.psm1")) {
    Import-Module (Join-Path $modulePath $mod) -DisableNameChecking -Force
}

function Test-RootOrAdmin {
    if ($PSVersionTable.Platform -eq 'Unix' -or $IsLinux -or $IsMacOS) {
        try { return ((id -u 2>$null) -eq 0) } catch { return $false }
    }
    try {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

$IsElevated = Test-RootOrAdmin
$HostOS     = Get-OSLabel
$Arch       = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture

function Write-Header {
    $privTag = if ($IsElevated) { "elevated (root/admin)" } else { "unprivileged (user)" }
    $privColor = if ($IsElevated) { "Green" } else { "Yellow" }

    $drvCtx = if (Get-Command Get-RunningDriveContext -ErrorAction SilentlyContinue) { Get-RunningDriveContext } else { $null }
    $drvTag = if ($drvCtx) { $drvCtx.Label } else { "HOST" }
    $drvColor = if ($drvCtx -and $drvCtx.IsUsb) { "Green" } else { "DarkGray" }

    Write-Host ""
    Write-Host "  WinOpSec" -ForegroundColor Cyan
    Write-Host "  os   : " -ForegroundColor DarkGray -NoNewline
    Write-Host "$HostOS [$Arch]" -ForegroundColor Gray
    Write-Host "  priv : " -ForegroundColor DarkGray -NoNewline
    Write-Host "$privTag" -ForegroundColor $privColor
    Write-Host "  drive: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$drvTag" -ForegroundColor $drvColor
    Write-Host ""
}

function Write-StatusRow {
    param (
        [string]$State,
        [string]$Label,
        [string]$Detail
    )
    $badgeColor = switch ($State) {
        "HARDENED"     { "Green" }
        "CLEAN"        { "Green" }
        "ENCRYPTED"    { "Green" }
        "CONFIGURABLE" { "Yellow" }
        default        { "Red" }
    }
    $tag = switch ($State) {
        "HARDENED"     { "PASS" }
        "CLEAN"        { "PASS" }
        "ENCRYPTED"    { "PASS" }
        "CONFIGURABLE" { "INFO" }
        default        { "FAIL" }
    }
    Write-Host ("  [{0}] " -f $tag) -ForegroundColor $badgeColor -NoNewline
    Write-Host ("{0,-32} " -f $Label) -ForegroundColor Gray -NoNewline
    Write-Host $Detail -ForegroundColor DarkGray
}

function Invoke-Audit {
    Write-Host "  telemetry, lsass & host shield" -ForegroundColor DarkGray
    $telemetryResults = Audit-Telemetry
    foreach ($r in $telemetryResults) {
        Write-StatusRow -State $r.Status -Label $r.Check -Detail $r.Details
    }

    Write-Host "`n  anonymity & sensors (vpn-safe)" -ForegroundColor DarkGray
    $anonymityResults = Audit-Anonymity
    foreach ($r in $anonymityResults) {
        Write-StatusRow -State $r.Status -Label $r.Check -Detail $r.Details
    }

    Write-Host "`n  network & protocol leaks" -ForegroundColor DarkGray
    $networkResults = Audit-NetworkOpSec
    foreach ($r in $networkResults) {
        Write-StatusRow -State $r.Status -Label "$($r.Protocol): $($r.Check)" -Detail "$($r.Details) [risk:$($r.Risk)]"
    }

    Write-Host "`n  mullvad / vpn tunnel & egress firewall" -ForegroundColor DarkGray
    $egressResults = Audit-VpnAndEgress
    foreach ($r in $egressResults) {
        Write-StatusRow -State $r.Status -Label $r.Check -Detail $r.Details
    }

    Write-Host "`n  browser opsec (webrtc, doh & vault shield)" -ForegroundColor DarkGray
    $browserResults = Audit-BrowserOpSec
    foreach ($r in $browserResults) {
        Write-StatusRow -State $r.Status -Label $r.Check -Detail $r.Details
    }

    Write-Host "`n  runtime traces & forensic artifacts" -ForegroundColor DarkGray
    $traceResults = Audit-Traces
    foreach ($r in $traceResults) {
        Write-StatusRow -State $r.Status -Label $r.Artifact -Detail $r.Count
    }

    Write-Host "`n  hardware identity & cryptographic anchors" -ForegroundColor DarkGray
    $hwResults = Audit-HardwareIdentity
    foreach ($r in $hwResults) {
        Write-StatusRow -State $(if ($r.Status -eq "CLEAN") { "CLEAN" } else { "CONFIGURABLE" }) -Label $r.Artifact -Detail "$($r.Value) [risk:$($r.Risk)]"
    }

    Write-Host "`n  camouflage & plausible deniability" -ForegroundColor DarkGray
    $chamResults = Audit-ChameleonState
    foreach ($r in $chamResults) {
        Write-StatusRow -State $(if ($r.Posture -eq "CIVILIAN_CAMOUFLAGE") { "HARDENED" } else { "CONFIGURABLE" }) -Label $r.Profile -Detail "$($r.Posture) ($($r.Decoys))"
    }

    Write-Host "`n  public sentry & defensive tripwire posture" -ForegroundColor DarkGray
    $sentryResults = Audit-SentryPosture
    foreach ($r in $sentryResults) {
        Write-StatusRow -State $r.Status -Label $r.Check -Detail $r.Details
    }

    Write-Host "`n  breach traps & canary honeytokens" -ForegroundColor DarkGray
    $canaryTraps = Audit-CanaryTraps
    foreach ($ct in $canaryTraps) {
        $st = if ($ct.State -eq "ARMED") { "HARDENED" } elseif ($ct.State -eq "TRIPPED") { "EXPOSED" } else { "CONFIGURABLE" }
        Write-StatusRow -State $st -Label "Canary: $($ct.Trap)" -Detail $ct.Details
    }

    Write-Host "`n  disk encryption" -ForegroundColor DarkGray
    $diskResult = Audit-DiskEncryption
    Write-StatusRow -State $diskResult.Status -Label $diskResult.Target -Detail $diskResult.Details

    Write-Host "`n  vm shield, host stealth & leak sentry" -ForegroundColor DarkGray
    $vmShieldResults = Audit-VmShieldPosture
    foreach ($r in $vmShieldResults) {
        Write-StatusRow -State $r.Status -Label $r.Check -Detail $r.Details
    }

    $scoredEgress = @($egressResults | Where-Object { $_.Status -ne "CONFIGURABLE" } | ForEach-Object { $_.Status })
    $scoredBrowser = @($browserResults | Where-Object { $_.Status -ne "CONFIGURABLE" } | ForEach-Object { $_.Status })
    $scoredSentry = @($sentryResults | Where-Object { $_.Status -ne "CONFIGURABLE" } | ForEach-Object { $_.Status })
    $scoredCanaries = @($canaryTraps | Where-Object { $_.State -ne "MISSING" } | ForEach-Object { if ($_.State -eq "ARMED") { "HARDENED" } else { "EXPOSED" } })
    $scoredVm = @($vmShieldResults | Where-Object { $_.Status -ne "CONFIGURABLE" } | ForEach-Object { $_.Status })
    $allChecks = @($telemetryResults.Status) + @($anonymityResults.Status) + @($networkResults.Status) + $scoredEgress + $scoredBrowser + @($traceResults.Status) + $scoredSentry + $scoredCanaries + $scoredVm
    $passed = ($allChecks | Where-Object { $_ -eq "HARDENED" -or $_ -eq "CLEAN" }).Count
    $total  = $allChecks.Count
    $score  = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 1) } else { 100 }
    $scoreColor = if ($score -ge 85) { "Green" } elseif ($score -ge 50) { "Yellow" } else { "Red" }

    Write-Host ""
    Write-Host "  score: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$score% ($passed/$total passed)" -ForegroundColor $scoreColor
    Write-Host ""
}

function Invoke-HardenAll {
    $snap = Save-OpSecState -Description "full"
    Write-Host "  snapshot -> $snap`n" -ForegroundColor DarkGray
    Harden-Telemetry
    Harden-Anonymity
    Harden-NetworkOpSec
    Harden-FirewallEgress
    Harden-Browsers
    Invoke-MullvadPartner -Action "harden"
    Enable-VmHostStealthFirewall | Out-Null
    Harden-VirtualAdapters
    Write-Host "`n  done." -ForegroundColor Green
}

function Invoke-TraceWipe {
    Shred-PowerShellHistory
    Clear-ExplorerTraces
    Clear-BrowserTraces
    Invoke-RamSanitize
    Write-Host "`n  traces, caches & volatile ram memory purged." -ForegroundColor Green
}

function Invoke-SecretsScan {
    $findings = Scan-ExposedSecrets
    Write-Host ""
    if ($findings.Count -eq 0) {
        Write-Host "  [PASS] 0 exposed secrets found." -ForegroundColor Green
    } else {
        Write-Host "  [WARN] $($findings.Count) potential exposures:" -ForegroundColor Red
        foreach ($f in $findings) {
            Write-Host ("    [{0,-4}] {1,-22} {2}" -f $f.Risk.ToUpper(), $f.Type, $f.File) -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

function Show-Usage {
    Write-Header
    Write-Host "  usage: ./WinOpSec.ps1 [flags]" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  flags:" -ForegroundColor DarkGray
    Write-Host "    -Audit            run full posture, Mullvad/VPN, browser & trace audit"
    Write-Host "    -Recon            inspect active VPN tunnels, listening ports & external connections"
    Write-Host "    -Sentry           launch real-time public sentry & defensive intrusion tripwire"
    Write-Host "    -AutoPanic        arm automated network severance & screen lock on intrusion"
    Write-Host "    -Mullvad          verify Mullvad VPN partner state, killswitch, PQ tunnel & exit IP"
    Write-Host "    -Browser          harden Chrome/Brave/Edge/Firefox (block WebRTC leak, vault & enforce Mullvad DoH)"
    Write-Host "    -LaunchBrowser    launch preferred browser in isolated ephemeral OpSec mode"
    Write-Host "    -HardenAll        apply host, VPN, Mullvad, browser, network & firewall hardening"
    Write-Host "    -WipeTraces       shred shell histories, UserAssist, MRU, ADS, browser caches & crash dumps"
    Write-Host "    -Scrub <path>     strip EXIF/ADS metadata and normalize timestamps on file/folder"
    Write-Host "    -SpoofMac         randomize active physical adapter MAC address"
    Write-Host "    -ScanSecrets      scan user dirs for private keys, .env & API tokens"
    Write-Host "    -Panic            emergency shred all traces, flush ARP/DNS & lock screen"
    Write-Host "    -VmShield         launch real-time VM sentry, memory watchdog & host stealth firewall"
    Write-Host "    -AuditVm          audit VirtualBox VMs for clipboard, shared folder & RAM leak risks"
    Write-Host "    -Restore          revert system state from latest snapshot"
    Write-Host ""
}

function Show-TacticalHud {
    [CmdletBinding()]
    param(
        [switch]$NonInteractive
    )

    # Render helpers: badges and values are driven by live audit data, not hardcoded.
    $StatusToBadge = {
        param($status)
        if ($status -eq 'HARDENED' -or $status -eq 'CLEAN' -or $status -eq 'ENCRYPTED') { return @{ Tag = 'PASS'; Color = 'Green' } }
        elseif ($status -eq 'CONFIGURABLE') { return @{ Tag = 'INFO'; Color = 'Yellow' } }
        else { return @{ Tag = 'FAIL'; Color = 'Red' } }
    }
    $FindCheck = {
        param($arr, $name)
        return ($arr | Where-Object { $_.Check -eq $name } | Select-Object -First 1)
    }
    $GuardVal = {
        param($chk, $fallbackText)
        if (-not $chk) { return @{ Val = $fallbackText; Color = 'DarkGray' } }
        $c = if ($chk.Status -eq 'HARDENED' -or $chk.Status -eq 'CLEAN') { 'Green' } elseif ($chk.Status -eq 'CONFIGURABLE') { 'Yellow' } else { 'Red' }
        return @{ Val = $chk.Details; Color = $c }
    }
    $Row = {
        param($tag, $tagColor, $label, $rightCap, $rightVal, $rightColor)
        Write-Host ("  [{0,-4}] " -f $tag) -ForegroundColor $tagColor -NoNewline
        Write-Host ("{0,-34}" -f $label) -ForegroundColor Gray -NoNewline
        Write-Host ("{0,-10} : " -f $rightCap) -ForegroundColor DarkGray -NoNewline
        Write-Host $rightVal -ForegroundColor $rightColor
    }

    $hudLoop = $true
    while ($hudLoop) {
        Clear-Host
        $privTag = if ($IsElevated) { "ELEVATED (ROOT/ADMIN)" } else { "UNPRIVILEGED (USER)" }
        $privColor = if ($IsElevated) { "Green" } else { "Yellow" }
        
        $mullvadRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq "10.64.0.1" }
        $vpnStatus = if ($mullvadRoute) { "LOCKED (MULLVAD ENCRYPTED)" } else { "EXPOSED (RAW/UNENCRYPTED)" }
        $vpnColor = if ($mullvadRoute) { "Green" } else { "Red" }

        $canaryArmed = 0
        $canaryTripped = 0
        if (Get-Command Audit-CanaryTraps -ErrorAction SilentlyContinue) {
            $cTraps = Audit-CanaryTraps
            $canaryArmed = @($cTraps | Where-Object { $_.State -eq "ARMED" }).Count
            $canaryTripped = @($cTraps | Where-Object { $_.State -eq "TRIPPED" }).Count
        }

        $osInfo = try { Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { $null }
        if (-not $osInfo) {
            $osInfo = try { Get-WmiObject Win32_OperatingSystem -ErrorAction Stop } catch { $null }
        }
        $freeRamMb = if ($osInfo) { [math]::Round($osInfo.FreePhysicalMemory / 1024, 0) } else { 0 }
        $totalRamMb = if ($osInfo) { [math]::Round($osInfo.TotalVisibleMemorySize / 1024, 0) } else { 0 }

        $drvCtx = if (Get-Command Get-RunningDriveContext -ErrorAction SilentlyContinue) { Get-RunningDriveContext } else { $null }
        $drvTag = if ($drvCtx) { $drvCtx.Label } else { "HOST" }
        $drvColor = if ($drvCtx -and $drvCtx.IsUsb) { "Green" } else { "DarkGray" }

        Write-Host ""
        Write-Host "  WinOpSec Tactical HUD" -ForegroundColor Cyan
        Write-Host "  host : " -ForegroundColor DarkGray -NoNewline
        Write-Host "$HostOS [$Arch]  " -ForegroundColor Gray -NoNewline
        Write-Host "priv : " -ForegroundColor DarkGray -NoNewline
        Write-Host "$privTag  " -ForegroundColor $privColor -NoNewline
        if ($totalRamMb -gt 0) {
            Write-Host "ram : " -ForegroundColor DarkGray -NoNewline
            Write-Host "$freeRamMb MB free / $totalRamMb MB" -ForegroundColor Gray
        } else {
            Write-Host ""
        }
        Write-Host "  drive: " -ForegroundColor DarkGray -NoNewline
        Write-Host "$drvTag" -ForegroundColor $drvColor

        Write-Host "  ------------------------------------------------------------------------" -ForegroundColor DarkGray

        # --- real posture snapshot (drives every badge below) ---
        $telPosture = @(); $egrPosture = @(); $senPosture = @()
        try { $telPosture = @(Audit-Telemetry) } catch {}
        try { $egrPosture = @(Audit-VpnAndEgress) } catch {}
        try { $senPosture = @(Audit-SentryPosture) } catch {}
        $posture = $telPosture + $egrPosture + $senPosture

        $scored = @($posture | Where-Object { $_.Status -ne 'CONFIGURABLE' })
        $passCount = @($scored | Where-Object { $_.Status -eq 'HARDENED' -or $_.Status -eq 'CLEAN' -or $_.Status -eq 'ENCRYPTED' }).Count
        $scoreTotal = $scored.Count
        $scorePct = if ($scoreTotal -gt 0) { [math]::Round(($passCount / $scoreTotal) * 100, 1) } else { 0 }
        $scoreColor = if ($scorePct -ge 85) { 'Green' } elseif ($scorePct -ge 50) { 'Yellow' } else { 'Red' }
        $barWidth = 35
        $filled = [int][math]::Round(($scorePct / 100) * $barWidth)
        if ($filled -gt $barWidth) { $filled = $barWidth }
        $bar = ('=' * $filled) + ('.' * ($barWidth - $filled))

        # left column (perimeter) badges from live sentry posture
        $arpBase = & $FindCheck $senPosture 'Gateway ARP Baseline'
        $arpColl = & $FindCheck $senPosture 'ARP Table Collision Check'
        $arpStatus = if ($arpColl -and $arpColl.Status -eq 'FAIL') { 'FAIL' } elseif ($arpBase) { $arpBase.Status } else { 'CONFIGURABLE' }
        $arpB = & $StatusToBadge $arpStatus
        $usbChk = & $FindCheck $senPosture 'USB Perimeter Tripwire'
        $usbB = & $StatusToBadge $(if ($usbChk) { $usbChk.Status } else { 'CONFIGURABLE' })
        $sensorChk = & $FindCheck $senPosture 'Sensor Hardware Lockdown'
        $eavesChk  = & $FindCheck $senPosture 'Live Eavesdropping Sentinel'
        $sensorStatus = if ($eavesChk -and $eavesChk.Status -eq 'FAIL') { 'FAIL' } elseif ($sensorChk) { $sensorChk.Status } else { 'CONFIGURABLE' }
        $sensorB = & $StatusToBadge $sensorStatus
        $canTag = if ($canaryTripped -gt 0) { 'FAIL' } elseif ($canaryArmed -gt 0) { 'PASS' } else { 'IDLE' }
        $canColor = if ($canaryTripped -gt 0) { 'Red' } elseif ($canaryArmed -gt 0) { 'Green' } else { 'DarkGray' }

        # right column (guards) values from live telemetry/vpn posture
        $gKill = & $GuardVal (& $FindCheck $egrPosture 'Mullvad Partner Lockdown') 'n/a (mullvad cli absent)'
        $pqChk = & $FindCheck $egrPosture 'Mullvad Post-Quantum & DAITA'
        $pqText = if ($pqChk) { (($pqChk.Details -split '\|')[0]).Trim() } else { 'n/a (mullvad cli absent)' }
        $daText = if ($pqChk -and ($pqChk.Details -split '\|').Count -ge 2) { (($pqChk.Details -split '\|')[1]).Trim() } else { 'n/a (mullvad cli absent)' }
        $pqColor = if ($pqChk -and $pqText -match '(?i)on') { 'Green' } elseif ($pqChk) { 'Yellow' } else { 'DarkGray' }
        $daColor = if ($pqChk -and $daText -match '(?i)on') { 'Green' } elseif ($pqChk) { 'Yellow' } else { 'DarkGray' }
        $gLsass = & $GuardVal (& $FindCheck $telPosture 'LSASS Memory Guard (RunAsPPL)') 'unknown (needs admin)'
        $gKern  = & $GuardVal (& $FindCheck $telPosture 'Kernel Memory Paging Guard') 'unknown (needs admin)'
        $gDma   = & $GuardVal (& $FindCheck $telPosture 'External DMA Guard (Anti-PCILeech)') 'unknown (needs admin)'
        $gWpbt  = & $GuardVal (& $FindCheck $telPosture 'UEFI WPBT Firmware Execution') 'unknown (needs admin)'

        Write-Host "  [SENTRY PERIMETER]                        [TUNNEL & KERNEL GUARDS]" -ForegroundColor White
        & $Row $arpB.Tag $arpB.Color 'Gateway ARP Integrity' 'Tunnel' $vpnStatus $vpnColor
        & $Row 'IDLE' 'DarkGray' 'SYN Port Scan Guard (live)' 'Killswitch' $gKill.Val $gKill.Color
        & $Row $usbB.Tag $usbB.Color 'Hardware USB Tripwire' 'Crypt-PQC' $pqText $pqColor
        & $Row 'IDLE' 'DarkGray' 'Rogue DNS Watch (live)' 'Traffic-AI' $daText $daColor
        & $Row $sensorB.Tag $sensorB.Color 'Microphone & Cam Sensor Trap' 'LSASS Mode' $gLsass.Val $gLsass.Color
        & $Row 'IDLE' 'DarkGray' 'Evil Twin AP Guard (live)' 'Kernel RAM' $gKern.Val $gKern.Color
        & $Row 'IDLE' 'DarkGray' 'Reverse Shell Trap (live)' 'DMA Guard' $gDma.Val $gDma.Color
        & $Row $canTag $canColor 'Honeytoken Canary Traps' 'UEFI WPBT' $gWpbt.Val $gWpbt.Color

        Write-Host "  ------------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  SECURITY POSTURE : " -ForegroundColor DarkGray -NoNewline
        Write-Host ("[{0}] {1}% ({2}/{3} PASS)" -f $bar, $scorePct, $passCount, $scoreTotal) -ForegroundColor $scoreColor
        Write-Host "  SENTRY VECTORS   : " -ForegroundColor DarkGray -NoNewline
        Write-Host "live vectors (IDLE) arm only while 'sentry' runs" -ForegroundColor DarkGray
        Write-Host "  COUNTERMEASURES  : " -ForegroundColor DarkGray -NoNewline
        Write-Host "Manual (arm auto-sever with 'sentry -autopanic')" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [1] Cafe   [2] Lockdown   [3] Canary   [4] Wipe RAM   [5] USB Deploy   [R] Refresh   [0] Exit HUD" -ForegroundColor Gray
        Write-Host ""

        if ($NonInteractive) {
            break
        }

        Write-Host "hud > " -ForegroundColor Cyan -NoNewline
        $hudInput = (Read-Host)
        if ($null -eq $hudInput) { break }
        $hudCmd = $hudInput.Trim().ToLower()

        switch -Regex ($hudCmd) {
            "^(1|cafe)$" {
                Write-Host "`n  [*] executing cafe mode..." -ForegroundColor DarkGray
                Invoke-MacSpoof
                Invoke-MullvadPartner -Action "harden"
                Invoke-SentryMonitor -AutoPanic:$true -SinglePass:$true
                Write-Host "`n  [+] press Enter to return to HUD..." -ForegroundColor DarkGray
                [void](Read-Host)
            }
            "^(2|lockdown)$" {
                Write-Host "`n  [*] applying complete host lockdown..." -ForegroundColor DarkGray
                Save-OpSecState -Description "pre-lockdown" | Out-Null
                Harden-All
                Write-Host "`n  [+] press Enter to return to HUD..." -ForegroundColor DarkGray
                [void](Read-Host)
            }
            "^(3|canary)$" {
                Write-Host ""
                Deploy-CanaryTraps
                Write-Host "`n  [+] press Enter to return to HUD..." -ForegroundColor DarkGray
                [void](Read-Host)
            }
            "^(4|ram|wipe|wipe-ram)$" {
                Write-Host ""
                Invoke-RamSanitize
                Write-Host "`n  [+] press Enter to return to HUD..." -ForegroundColor DarkGray
                [void](Read-Host)
            }
            "^(5|usb|deploy)$" {
                Write-Host ""
                Deploy-UsbOpSec
                Write-Host "`n  [+] press Enter to return to HUD..." -ForegroundColor DarkGray
                [void](Read-Host)
            }
            "^(r|refresh)$" {
                continue
            }
            "^(0|q|quit|exit|back)$" {
                $hudLoop = $false
                break
            }
            default {
                Write-Host "  unknown HUD action '$hudCmd'. (type 1-4, 'r' to refresh, '0' to exit)" -ForegroundColor DarkGray
                Start-Sleep -Milliseconds 800
            }
        }
    }

    Clear-Host
    Write-Header
    Show-Menu
}

function Show-Menu {
    Write-Host "  WinOpSec Console" -ForegroundColor Cyan
    Write-Host "  select an option below or type 'quick' for the 1-click scenario menu.`n" -ForegroundColor DarkGray

    Write-Host "  [1] audit & recon" -ForegroundColor White
    Write-Host "      hud / dash      - live real-time tactical security HUD" -ForegroundColor White
    Write-Host "      1 / audit       - full posture check and security score" -ForegroundColor Gray
    Write-Host "      8 / recon       - listening ports, active sockets & vpn tunnel" -ForegroundColor DarkGray
    Write-Host "      canary          - honeytoken breach traps (desktop, docs, downloads)" -ForegroundColor DarkGray
    Write-Host "      7 / secrets     - scan disk for exposed private keys & .env files" -ForegroundColor DarkGray
    Write-Host "      hwid            - inspect hardware machine guids (machineguid, sqm id)" -ForegroundColor DarkGray

    Write-Host "`n  [2] public wi-fi & sentry (defense)" -ForegroundColor White
    Write-Host "      sentry          - 8-vector defensive tripwire (arp, port scans, canary, mic)" -ForegroundColor Gray
    Write-Host "      sentry -autopanic - auto-sever wi-fi & lock workstation on threat" -ForegroundColor Green
    Write-Host "      deadman         - usb buskill lanyard trigger (panic on physical pull)" -ForegroundColor DarkGray
    Write-Host "      9 / mac         - spoof physical network mac ('mac reset' to restore)" -ForegroundColor DarkGray

    Write-Host "`n  [3] system hardening & shields" -ForegroundColor White
    Write-Host "      5 / harden-all  - apply all host, network, mullvad and browser shields" -ForegroundColor Gray
    Write-Host "      mullvad harden  - post-quantum tunnel, daita & wfp killswitch" -ForegroundColor DarkGray
    Write-Host "      browser         - block webrtc leaks and lock password vaults" -ForegroundColor DarkGray
    Write-Host "      browser launch  - open private ephemeral browser instance" -ForegroundColor DarkGray

    Write-Host "`n  [4] anti-forensics & cleanup" -ForegroundColor White
    Write-Host "      6 / wipe        - shred histories, runmru, crash dumps, caches & ram" -ForegroundColor Gray
    Write-Host "      wipe-ram        - flush process working sets & trim volatile memory" -ForegroundColor DarkGray
    Write-Host "      wipe-pca        - purge windows 11 app compatibility execution logs" -ForegroundColor DarkGray
    Write-Host "      wipe-shellbags  - purge explorer folder navigation histories" -ForegroundColor DarkGray
    Write-Host "      wipe-reglogs    - flush registry transaction journals (.log1/.log2)" -ForegroundColor DarkGray
    Write-Host "      wipe-deleted    - purge vss shadow copies & re-trim ssd" -ForegroundColor DarkGray
    Write-Host "      scrub <path>    - strip metadata and normalize file timestamps" -ForegroundColor DarkGray
    Write-Host "      jitter <path>   - apply natural gaussian jitter (anti-timestomp)" -ForegroundColor DarkGray

    Write-Host "`n  [5] civilian camouflage" -ForegroundColor White
    Write-Host "      chameleon       - plant benign civilian decoys (defeats 'too clean machine')" -ForegroundColor Gray
    Write-Host "      chameleon -purge - remove synthetic decoy files" -ForegroundColor DarkGray

    Write-Host "`n  [6] usb hardware & stealth deployment" -ForegroundColor White
    Write-Host "      usb / usb list  - list connected removable drives & bitlocker status" -ForegroundColor Gray
    Write-Host "      usb deploy      - clone portable winopsec to usb with autorun immunization" -ForegroundColor DarkGray
    Write-Host "      usb shield on   - lock all usb ports to read-only (anti-data-exfiltration)" -ForegroundColor DarkGray
    Write-Host "      usb shield off  - restore normal read/write to usb ports" -ForegroundColor DarkGray
    Write-Host "      deadman         - usb buskill lanyard trigger (panic on physical pull)" -ForegroundColor DarkGray
    Write-Host "      vanish / burn   - emergency self-destruct (DoD shred winopsec, TRIM & poweroff)" -ForegroundColor Red

    Write-Host "`n  [7] vm shield & hypervisor leak guard" -ForegroundColor White
    Write-Host "      vm / vm watch   - real-time vm sentry, memory watchdog & stealth isolation" -ForegroundColor Cyan
    Write-Host "      vm audit        - scan virtualbox configs for clipboard, folder & ram leaks" -ForegroundColor Gray
    Write-Host "      vm stealth on   - block guest vms from probing host windows listening ports" -ForegroundColor DarkGray
    Write-Host "      vm stealth off  - disable vm host stealth firewall rules" -ForegroundColor DarkGray

    Write-Host "`n  [!] shortcuts & navigation" -ForegroundColor White
    Write-Host "      quick           - 1-click scenario wizard (cafe, lockdown, clean)" -ForegroundColor Green
    Write-Host "      intro           - play animated audio briefing & walkthrough" -ForegroundColor Gray
    Write-Host "      test-voice      - test laptop speaker voice output" -ForegroundColor DarkGray
    Write-Host "      guide <cmd>     - explain how any feature works" -ForegroundColor DarkGray
    Write-Host "      panic           - emergency route severance, trace wipe & screen lock" -ForegroundColor Red
    Write-Host "      panic -poweroff - emergency hard shutdown with zero disk traces" -ForegroundColor DarkRed
    Write-Host "      restore         - rollback system settings from saved snapshot" -ForegroundColor Gray
    Write-Host "      q / quit        - exit console" -ForegroundColor DarkGray
    Write-Host ""
}

function Invoke-GuidedWizard {
    Write-Host "`n  1-Click Scenario Wizard" -ForegroundColor Cyan
    Write-Host "  choose your current operational scenario:`n" -ForegroundColor Gray

    Write-Host "  [1] Cafe / Public Wi-Fi Mode" -ForegroundColor White
    Write-Host "      -> Spoof MAC, lock Mullvad VPN, and activate Sentry with Auto-Panic." -ForegroundColor DarkGray

    Write-Host "  [2] Complete Host Lockdown" -ForegroundColor White
    Write-Host "      -> Lock LSASS memory, disable telemetry, and block network leaks." -ForegroundColor DarkGray

    Write-Host "  [3] Secure Ephemeral Browsing" -ForegroundColor White
    Write-Host "      -> Block WebRTC leaks and launch private isolated browser." -ForegroundColor DarkGray

    Write-Host "  [4] Post-Session Forensics Scrub & Camouflage" -ForegroundColor White
    Write-Host "      -> Purge execution logs (PCA, ShellBags) and plant civilian decoy files." -ForegroundColor DarkGray

    Write-Host "  [5] Full Security Posture Audit" -ForegroundColor White
    Write-Host "      -> Scan all 53 defensive benchmarks and calculate score." -ForegroundColor DarkGray

    Write-Host "  [0] Back / Cancel" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "select [0-5]: " -ForegroundColor Green -NoNewline
    $sel = (Read-Host).Trim()

    switch ($sel) {
        "1" {
            Write-Host "`n  [+] Cafe Mode: spoofing MAC & locking Mullvad..." -ForegroundColor Gray
            Invoke-MacSpoof
            Invoke-MullvadPartner -Action "harden"
            Write-Host "  [+] Sentry armed with Auto-Panic active...`n" -ForegroundColor Green
            Invoke-SentryMonitor -AutoPanic
        }
        "2" {
            Write-Host "`n  [+] Applying complete host lockdown..." -ForegroundColor Gray
            Invoke-HardenAll
        }
        "3" {
            Write-Host "`n  [+] Launching hardened ephemeral browser..." -ForegroundColor Gray
            Harden-Browsers
            Start-HardenedBrowser
        }
        "4" {
            Write-Host "`n  [+] Scrubbing execution traces & deploying chameleon decoys..." -ForegroundColor Gray
            Invoke-TraceWipe
            Invoke-PcaWipe
            Invoke-ShellBagsSanitize
            Invoke-RegistryLogSanitize
            Invoke-ChameleonNoise
            Write-Host "  [+] Traces sanitized and civilian noise active." -ForegroundColor Green
        }
        "5" {
            Write-Host ""
            Invoke-Audit
        }
        default {
            Write-Host "  Cancelled." -ForegroundColor DarkGray
        }
    }
}

function Show-CommandGuide {
    param([string]$Topic)

    $t = if ($Topic) { $Topic.ToLower().Trim() } else { "" }

    Write-Host ""
    switch -Regex ($t) {
        "^(canary|honeytoken|trap)$" {
            Write-Host "  Canary Honeytoken Breach Trap Guide" -ForegroundColor Cyan
            Write-Host "  Purpose: Early-warning tripwire that detects malware and unauthorized intruders." -ForegroundColor White
            Write-Host "  How it works:" -ForegroundColor Gray
            Write-Host "    Plants realistic bait files (AWS keys, crypto seed, password database)" -ForegroundColor DarkGray
            Write-Host "    in Desktop, Documents, and Downloads. If any infostealer or intruder" -ForegroundColor DarkGray
            Write-Host "    touches the bait, Sentry triggers an immediate alert and auto-panic." -ForegroundColor DarkGray
            Write-Host "`n  Usage:" -ForegroundColor White
            Write-Host "    canary drop   -> Deploy bait files with realistic historical timestamps" -ForegroundColor Yellow
            Write-Host "    canary status -> Check if traps are armed or tripped" -ForegroundColor Gray
            Write-Host "    canary purge  -> Shred and remove all bait files" -ForegroundColor Gray
        }
        "^(sentry|monitor|tripwire)$" {
            Write-Host "  Sentry & Defensive Tripwire Guide" -ForegroundColor Cyan
            Write-Host "  Purpose: Real-time defense against attackers on the same public Wi-Fi or LAN." -ForegroundColor White
            Write-Host "  Monitors 8 attack vectors:" -ForegroundColor Gray
            Write-Host "    - ARP Poisoning / MITM (Bettercap/Ettercap gateway spoofing)" -ForegroundColor DarkGray
            Write-Host "    - Inbound Port Scans (Nmap SYN half-open probes on ports 445, 135, 3389)" -ForegroundColor DarkGray
            Write-Host "    - Eavesdropping (Processes actively recording microphone or camera)" -ForegroundColor DarkGray
            Write-Host "    - Unauthorized USB (BadUSB / Rubber Ducky keystroke injectors)" -ForegroundColor DarkGray
            Write-Host "    - Rogue DNS (Untrusted local resolvers or hosts tampering)" -ForegroundColor DarkGray
            Write-Host "    - Evil Twin Wi-Fi (BSSID access point mutation)" -ForegroundColor DarkGray
            Write-Host "    - Active Reverse Shells (Outbound sockets from cmd/powershell)" -ForegroundColor DarkGray
            Write-Host "    - Canary Honeytoken Traps (Unauthorized file read/touch on decoy secrets)" -ForegroundColor DarkGray
            Write-Host "`n  Usage:" -ForegroundColor White
            Write-Host "    sentry            -> Continuous monitoring with audible alerts" -ForegroundColor Yellow
            Write-Host "    sentry -autopanic -> Auto-disables Wi-Fi and locks PC if attacked" -ForegroundColor Red
        }
        "^(chameleon|camouflage|noise)$" {
            Write-Host "  Forensic Chameleon Guide" -ForegroundColor Cyan
            Write-Host "  Purpose: Defeats the SANS FOR500 'Evidence of Absence / Too Clean Machine' trap." -ForegroundColor White
            Write-Host "  Why it matters:" -ForegroundColor Gray
            Write-Host "    Digital forensics experts look for machines that have 0 logs and 0 recent files." -ForegroundColor DarkGray
            Write-Host "    A wiped laptop is suspicious. Chameleon injects benign student/civilian" -ForegroundColor DarkGray
            Write-Host "    documents, recent links, and realistic activity so you blend in." -ForegroundColor DarkGray
            Write-Host "`n  Usage:" -ForegroundColor White
            Write-Host "    chameleon        -> Deploy civilian noise documents & Recent links" -ForegroundColor Yellow
            Write-Host "    chameleon -purge -> Clean up all decoy files" -ForegroundColor Gray
        }
        "^(deadman|buskill|usb)$" {
            Write-Host "  USB Dead Man's Switch Guide" -ForegroundColor Cyan
            Write-Host "  Purpose: Anti-snatch physical defense (like the Silk Road Glen Park arrest)." -ForegroundColor White
            Write-Host "  How it works:" -ForegroundColor Gray
            Write-Host "    Attach a USB flash drive with a wrist lanyard to your laptop." -ForegroundColor DarkGray
            Write-Host "    If someone snatches your laptop and the USB pulls out, WinOpSec triggers" -ForegroundColor DarkGray
            Write-Host "    an immediate panic wipe, route kill, and workstation lock or poweroff." -ForegroundColor DarkGray
            Write-Host "`n  Usage:" -ForegroundColor White
            Write-Host "    deadman          -> Select USB drive and arm monitor (200ms poll)" -ForegroundColor Yellow
        }
        "^(pca|wipe-pca)$" {
            Write-Host "  Program Compatibility Assistant (PCA) Guide" -ForegroundColor Cyan
            Write-Host "  Purpose: Neutralizes Windows 11 hidden program execution tracking." -ForegroundColor White
            Write-Host "  Why it matters:" -ForegroundColor Gray
            Write-Host "    Windows 11 silently logs every executable you run into PcaAppLaunchDic.txt." -ForegroundColor DarkGray
            Write-Host "    Even if you delete Prefetch, PCA still has the full history." -ForegroundColor DarkGray
            Write-Host "`n  Usage:" -ForegroundColor White
            Write-Host "    wipe-pca         -> Purges dictionary and locks file with read-only ACL" -ForegroundColor Yellow
        }
        "^(shellbags|wipe-shellbags)$" {
            Write-Host "  ShellBags Sanitizer Guide" -ForegroundColor Cyan
            Write-Host "  Purpose: Wipes Explorer folder browsing and USB folder access history." -ForegroundColor White
            Write-Host "  Why it matters:" -ForegroundColor Gray
            Write-Host "    Windows stores every folder, flash drive, and network share you ever opened" -ForegroundColor DarkGray
            Write-Host "    in the registry BagMRU keys. This reveals what directories you explored." -ForegroundColor DarkGray
            Write-Host "`n  Usage:" -ForegroundColor White
            Write-Host "    wipe-shellbags   -> Removes all BagMRU and Bags keys" -ForegroundColor Yellow
        }
        "^(mullvad)$" {
            Write-Host "  Mullvad Partner Lockdown Guide" -ForegroundColor Cyan
            Write-Host "  Features:" -ForegroundColor Gray
            Write-Host "    - WFP strict killswitch (blocks all non-tunnel traffic)" -ForegroundColor DarkGray
            Write-Host "    - Post-Quantum Kyber-1024 encryption (quantum-resistant)" -ForegroundColor DarkGray
            Write-Host "    - DAITA (Maybenot AI traffic analysis padding)" -ForegroundColor DarkGray
            Write-Host "    - Multihop routing (dual-country relay bounce)" -ForegroundColor DarkGray
            Write-Host "`n  Usage:" -ForegroundColor White
            Write-Host "    mullvad harden   -> Turn on all maximum security protections" -ForegroundColor Yellow
            Write-Host "    mullvad rotate   -> Generate fresh WireGuard keys" -ForegroundColor Gray
        }
        "^(panic)$" {
            Write-Host "  Emergency Panic Protocol Guide" -ForegroundColor Red
            Write-Host "  Purpose: Instant duress countermeasure under active raid or compromise." -ForegroundColor White
            Write-Host "  Actions taken:" -ForegroundColor Gray
            Write-Host "    - Terminates browsers, messengers, and shell processes" -ForegroundColor DarkGray
            Write-Host "    - Drops all Wi-Fi / Ethernet adapters and deletes routes" -ForegroundColor DarkGray
            Write-Host "    - Flushes ARP, DNS, and NetBIOS caches" -ForegroundColor DarkGray
            Write-Host "    - Shreds recent histories and locks Windows workstation" -ForegroundColor DarkGray
            Write-Host "`n  Usage:" -ForegroundColor White
            Write-Host "    panic            -> Execute immediate screen lock and network severance" -ForegroundColor Yellow
            Write-Host "    panic -poweroff  -> Emergency hard shutdown with zero disk traces" -ForegroundColor Red
        }
        "^(vanish|burn)$" {
            Write-Host "  Ghost Self-Destruct (Vanish Protocol) Guide" -ForegroundColor Red
            Write-Host "  Purpose: Irreversible elimination of WinOpSec, traces, and forensic anchors." -ForegroundColor White
            Write-Host "  Actions taken:" -ForegroundColor Gray
            Write-Host "    - Terminates browsers, messengers, and password vaults" -ForegroundColor DarkGray
            Write-Host "    - Cryptographically shreds all WinOpSec modules, scripts, backups, and audio" -ForegroundColor DarkGray
            Write-Host "    - Deletes the WinOpSec directory via detached process" -ForegroundColor DarkGray
            Write-Host "    - Wipes USN Deletion Journal and executes SSD TRIM" -ForegroundColor DarkGray
            Write-Host "    - Triggers immediate emergency hard power-off" -ForegroundColor DarkGray
            Write-Host "`n  Usage:" -ForegroundColor White
            Write-Host "    vanish           -> Prompts for 'NUKE' confirmation before executing" -ForegroundColor Red
        }
        "^(usb|usb-shield|usb-deploy)$" {
            Write-Host "  USB Tactical Operations Guide" -ForegroundColor Cyan
            Write-Host "  Purpose: Run WinOpSec completely air-gapped from USB with zero host footprint." -ForegroundColor White
            Write-Host "  Key Capabilities:" -ForegroundColor Gray
            Write-Host "    - 'usb list'       -> Displays connected USB flash drives and BitLocker status" -ForegroundColor DarkGray
            Write-Host "    - 'usb deploy'     -> Clones WinOpSec to USB with root autorun.inf immunization" -ForegroundColor DarkGray
            Write-Host "    - 'usb shield on'  -> Locks USB ports to read-only (prevents data exfiltration)" -ForegroundColor DarkGray
            Write-Host "    - 'deadman'        -> USB buskill lanyard (emergency panic on physical snatch)" -ForegroundColor DarkGray
            Write-Host "`n  Operational Advantage:" -ForegroundColor White
            Write-Host "    Running from USB leaves ZERO WinOpSec source code or tools on the host SSD." -ForegroundColor Yellow
        }
        "^(vm|vmshield|vbox|virtualbox)$" {
            Write-Host "  VM Shield & Hypervisor Leak Sentry Guide" -ForegroundColor Cyan
            Write-Host "  Purpose: Isolates host Windows identity and guards against VM leaks and host crashes." -ForegroundColor White
            Write-Host "  Key Defenses:" -ForegroundColor Gray
            Write-Host "    - Host Stealth Firewall -> Blocks guest VMs from probing host SMB (445), RPC, NetBIOS, MySQL" -ForegroundColor DarkGray
            Write-Host "    - Memory Watchdog      -> Alerts if VirtualBox starts leaking memory towards 8 GB limit" -ForegroundColor DarkGray
            Write-Host "    - TCP Port Sentry      -> Monitors ephemeral port allocations to prevent Wi-Fi/Taskbar freeze" -ForegroundColor DarkGray
            Write-Host "    - VM Config Audit      -> Flags bidirectional clipboard, shared folders and dangerous RAM limits" -ForegroundColor DarkGray
            Write-Host "`n  Usage:" -ForegroundColor White
            Write-Host "    vm watch         -> Continuous VM monitoring and real-time host leak guard" -ForegroundColor Yellow
            Write-Host "    vm audit         -> Inspect VirtualBox VM files for configuration leaks" -ForegroundColor Gray
            Write-Host "    vm stealth on    -> Arm WFP host-stealth firewall rules" -ForegroundColor Green
            Write-Host "    vm stealth off   -> Remove host-stealth firewall rules" -ForegroundColor DarkGray
        }
        default {
            Write-Host "  WinOpSec Operational Guide" -ForegroundColor Cyan
            Write-Host "  Type 'guide <topic>' for in-depth details on any module:`n" -ForegroundColor DarkGray
            Write-Host "    guide sentry     -> Real-time Public Wi-Fi tripwire & BadUSB monitor" -ForegroundColor White
            Write-Host "    guide chameleon  -> Synthetic civilian camouflage & SANS anti-absence" -ForegroundColor White
            Write-Host "    guide deadman    -> USB BusKill lanyard anti-snatch hardware trigger" -ForegroundColor White
            Write-Host "    guide usb        -> USB-driven portable deployment & hardware shield" -ForegroundColor White
            Write-Host "    guide pca        -> Windows 11 hidden program execution logs" -ForegroundColor White
            Write-Host "    guide shellbags  -> Explorer folder navigation histories" -ForegroundColor White
            Write-Host "    guide mullvad    -> Post-quantum, DAITA & WFP killswitch setup" -ForegroundColor White
            Write-Host "    guide panic      -> Emergency duress protocol" -ForegroundColor White
            Write-Host "    guide vanish     -> Irreversible ghost self-destruct" -ForegroundColor Red
            Write-Host "`n  Tip: You can also type 'quick' for the guided 1-click scenario wizard!" -ForegroundColor Green
        }
    }
    Write-Host ""
}

if ($Help)          { Show-Usage; exit }
if ($Audit)         { Write-Header; Invoke-Audit; exit }
if ($Recon)         { Write-Header; Invoke-NetworkRecon; exit }
if ($Sentry)        { Write-Header; Invoke-SentryMonitor -AutoPanic:$AutoPanic -SinglePass:$SinglePass; exit }
if ($Mullvad)       { Write-Header; Invoke-MullvadPartner -Action "status"; exit }
if ($Browser)       { Write-Header; Harden-Browsers; exit }
if ($LaunchBrowser) { Write-Header; Start-HardenedBrowser; exit }
if ($HardenAll)     { Write-Header; Invoke-HardenAll; exit }
if ($WipeTraces)    { Write-Header; Invoke-TraceWipe; exit }
if ($PcaWipe)       { Write-Header; Invoke-PcaWipe; exit }
if ($ShellBags)     { Write-Header; Invoke-ShellBagsSanitize; exit }
if ($Srum)          { Write-Header; Invoke-SrumNeutralize; exit }
if ($ScrubWifi)        { Write-Header; Invoke-NetworkListScrub; exit }
if ($RandomizeHwId)    { Write-Header; Invoke-HwIdRandomize; exit }
if ($DeadMan)          { Write-Header; Invoke-DeadManSwitch -DriveLetter $DeadManDrive; exit }
if ($WipeTokens)       { Write-Header; Invoke-TokenSanitize; exit }
if ($WipeScreenshots)  { Write-Header; Invoke-ScreenshotCacheWipe; exit }
if ($WipeRegLogs)      { Write-Header; Invoke-RegistryLogSanitize; exit }
if ($Chameleon)        { Write-Header; Invoke-ChameleonNoise; exit }
if ($PurgeChameleon)   { Write-Header; Invoke-ChameleonNoise -Purge; exit }
if ($Scrub)            { Write-Header; Invoke-MetadataScrub -TargetPath $Scrub; exit }
if ($SpoofMac)      { Write-Header; Invoke-MacSpoof; exit }
if ($ScanSecrets)   { Write-Header; Invoke-SecretsScan; exit }
if ($Panic)         { Write-Header; Invoke-PanicProtocol; exit }
if ($Vanish)        { Write-Header; Invoke-SelfDestruct; exit }
if ($Restore)       { Write-Header; Restore-OpSecState | Out-Null; exit }
if ($Hud)           { Show-TacticalHud -NonInteractive:$NonInteractive; exit }
if ($WipeRam)       { Write-Header; Invoke-RamSanitize; exit }
if ($Jitter)        { Write-Header; Invoke-TimestampJitter -TargetPath $Jitter; exit }
if ($TestVoice)     { Test-VoiceOutput; exit }
if ($Intro)         { Invoke-CyberIntro; exit }
if ($VmShield)      { Write-Header; Start-VmShieldSentinel -SinglePass:$SinglePass; exit }
if ($AuditVm)       { Write-Header; Write-Host "`n  === VIRTUAL MACHINE LEAK & ISOLATION AUDIT ===" -ForegroundColor Cyan; Audit-VirtualBoxConfigurations | Format-Table -AutoSize; exit }

Clear-Host
Write-Header
Show-Menu

$sessionActive = $true
while ($sessionActive) {
    $privTag = if ($IsElevated) { "admin" } else { "user" }
    $vpnTag  = if (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq "10.64.0.1" }) { "vpn:mullvad" } else { "vpn:off" }
    Write-Host "winopsec " -ForegroundColor DarkGray -NoNewline
    Write-Host "[$privTag | $vpnTag] " -ForegroundColor Cyan -NoNewline
    Write-Host "> " -ForegroundColor White -NoNewline
    $rawInput = Read-Host
    if ($null -eq $rawInput) {
        $sessionActive = $false
        break
    }
    $rawInput = $rawInput.Trim()
    $inputCmd = $rawInput.ToLower()
    if ($inputCmd -eq "") {
        continue
    }

    if ($inputCmd -match "^scrub\s+(.+)$") {
        $target = $rawInput.Substring(5).Trim().Trim('"').Trim("'")
        Write-Host ""
        Invoke-MetadataScrub -TargetPath $target
        Write-Host ""
        continue
    }

    if ($inputCmd -match "^jitter\s+(.+)$") {
        $target = $rawInput.Substring(6).Trim().Trim('"').Trim("'")
        Write-Host ""
        Invoke-TimestampJitter -TargetPath $target
        Write-Host ""
        continue
    }

    switch -Regex ($inputCmd) {
        "^(1|audit|status)$" {
            Write-Host ""
            Invoke-Audit
        }
        "^(2|telemetry|shield)$" {
            Write-Host ""
            Save-OpSecState -Description "telemetry" | Out-Null
            Harden-Telemetry
            Write-Host ""
        }
        "^(3|anon|anonymity)$" {
            Write-Host ""
            Save-OpSecState -Description "anon" | Out-Null
            Harden-Anonymity
            Write-Host ""
        }
        "^(4|net|network)$" {
            Write-Host ""
            Save-OpSecState -Description "net" | Out-Null
            Harden-NetworkOpSec
            Harden-FirewallEgress
            Write-Host ""
        }
        "^(5|harden|harden-all|all)$" {
            Write-Host ""
            Invoke-HardenAll
            Write-Host ""
        }
        "^(6|wipe|shred|clean)$" {
            Write-Host ""
            Invoke-TraceWipe
            Write-Host ""
        }
        "^(7|secrets|scan)$" {
            Write-Host ""
            Invoke-SecretsScan
        }
        "^(8|recon|ports|egress)$" {
            Write-Host ""
            Invoke-NetworkRecon
            Write-Host ""
        }
        "^(9|mac|spoof)$" {
            Write-Host ""
            Invoke-MacSpoof
            Write-Host ""
        }
        "^(9|mac|spoof)\s+reset$" {
            Write-Host ""
            Invoke-MacSpoof -Reset
            Write-Host ""
        }
        "^hwid(\s+(status|audit|check))?$" {
            Write-Host ""
            Audit-HardwareIdentity | Format-Table -AutoSize
            Write-Host ""
        }
        "^hwid\s+(randomize|spoof|new)$" {
            Write-Host ""
            Invoke-HwIdRandomize
            Write-Host ""
        }
        "^mullvad(\s+status)?$" {
            Write-Host ""
            Invoke-MullvadPartner -Action "status"
            Write-Host ""
        }
        "^mullvad\s+(harden|lockdown)$" {
            Write-Host ""
            Invoke-MullvadPartner -Action "harden"
            Write-Host ""
        }
        "^mullvad\s+(rotate|rotate-key)$" {
            Write-Host ""
            Invoke-MullvadPartner -Action "rotate"
            Write-Host ""
        }
        "^mullvad\s+daita(\s+(on|off))?$" {
            $act = if ($Matches[2]) { "daita " + $Matches[2] } else { "daita on" }
            Write-Host ""
            Invoke-MullvadPartner -Action $act
            Write-Host ""
        }
        "^mullvad\s+multihop(\s+(on|off))?$" {
            $act = if ($Matches[2]) { "multihop " + $Matches[2] } else { "multihop on" }
            Write-Host ""
            Invoke-MullvadPartner -Action $act
            Write-Host ""
        }
        "^browser\s+(list|profiles|accounts|detect)$" {
            Write-Host ""
            Show-BrowserInventory
            Write-Host ""
        }
        "^browser\s+(clean|wipe|nuke)(\s+(.+))?$" {
            $filter = $Matches[3]
            Write-Host ""
            Clear-BrowserHistoryAndTraces -Filter $filter
            Write-Host ""
        }
        "^browser\s+(autofill|clean-autofill)(\s+(.+))?$" {
            $filter = $Matches[3]
            Write-Host ""
            Clear-BrowserAutofill -Filter $filter
            Write-Host ""
        }
        "^browser\s+(remove|purge|delete)\s+(.+)$" {
            $target = $Matches[2].Trim().Trim('"').Trim("'")
            Write-Host ""
            Remove-BrowserAccountTraces -Target $target
            Write-Host ""
        }
        "^(browser\s+(launch|mullvad|open)(\s+(.+))?|mullvad\s+browser)$" {
            $target = if ($Matches[4]) { $Matches[4].Trim() } elseif ($Matches[0] -match "mullvad") { "Mullvad Browser" } else { "" }
            Write-Host ""
            Start-HardenedBrowser -TargetBrowser $target
            Write-Host ""
        }
        "^browser(\s+harden)?$" {
            Write-Host ""
            Save-OpSecState -Description "browser" | Out-Null
            Harden-Browsers
            Write-Host ""
        }
        "^scrub$" {
            Write-Host "  usage: scrub <file_or_directory_path>" -ForegroundColor Yellow
        }
        "^forensic(-check|s)?$" {
            Write-Host ""
            Audit-DeletedFootprint
            Write-Host ""
        }
        "^(wipe-pca|pca)$" {
            Write-Host ""
            Invoke-PcaWipe
            Write-Host ""
        }
        "^(wipe-shellbags|shellbags)$" {
            Write-Host ""
            Invoke-ShellBagsSanitize
            Write-Host ""
        }
        "^(wipe-srum|srum)$" {
            Write-Host ""
            Invoke-SrumNeutralize
            Write-Host ""
        }
        "^(scrub-wifi|wifi-scrub|wipe-wifi)$" {
            Write-Host ""
            Invoke-NetworkListScrub
            Write-Host ""
        }
        "^(wipe-tokens|tokens|clean-tokens)$" {
            Write-Host ""
            Invoke-TokenSanitize
            Write-Host ""
        }
        "^(wipe-screenshots|screenshots|scrub-screenshots)$" {
            Write-Host ""
            Invoke-ScreenshotCacheWipe
            Write-Host ""
        }
        "^(wipe-reglogs|reglogs|flush-registry)$" {
            Write-Host ""
            Invoke-RegistryLogSanitize
            Write-Host ""
        }
        "^sentry(\s+(-autopanic|autopanic))?$" {
            Write-Host ""
            Invoke-SentryMonitor -AutoPanic:($Matches[2] -ne $null)
            Write-Host ""
        }
        "^sentry\s+(status|posture|audit)$" {
            Write-Host ""
            Audit-SentryPosture | Format-Table -AutoSize
            Write-Host ""
        }
        "^chameleon(\s+(-purge|purge))?$" {
            Write-Host ""
            Invoke-ChameleonNoise -Purge:($Matches[2] -ne $null)
            Write-Host ""
        }
        "^deadman(\s+(-drive\s+(\S+)|(\S+:)))?$" {
            $drv = if ($Matches[3]) { $Matches[3] } elseif ($Matches[4]) { $Matches[4] } else { $null }
            Write-Host ""
            Invoke-DeadManSwitch -DriveLetter $drv
            Write-Host ""
        }
        "^wipe-deleted(\s+(-cipher|cipher))?$" {
            Write-Host ""
            Invoke-DeepSanitize -FullCipher:($Matches[1] -ne $null)
            Write-Host ""
        }
        "^(wipe-logs|wipe\s+logs|clear-logs)$" {
            Write-Host ""
            Clear-WindowsEventLogs
            Write-Host ""
        }
        "^panic(\s+(-poweroff|poweroff|shutdown))?$" {
            Write-Host ""
            Invoke-PanicProtocol -PowerOff:($Matches[1] -ne $null)
            Write-Host ""
        }
        "^(10|restore|rollback)$" {
            Write-Host ""
            Restore-OpSecState | Out-Null
            Write-Host ""
        }
        "^(intro|tour|hello|onboarding)(\s+(-mute|-quiet))?$" {
            $mute = ($Matches[2] -ne $null)
            Invoke-CyberIntro -VoiceMute:$mute
            Clear-Host
            Write-Header
            Show-Menu
        }
        "^(test-voice|testvoice|voice-test)$" {
            Test-VoiceOutput
        }
        "^(hud|dash|dashboard|soc)$" {
            Show-TacticalHud
        }
        "^canary(\s+(status|audit|check))?$" {
            Write-Host ""
            Audit-CanaryTraps | Format-Table -AutoSize
            Write-Host ""
        }
        "^canary\s+(drop|deploy|plant|arm)$" {
            Write-Host ""
            Deploy-CanaryTraps
            Write-Host ""
        }
        "^canary\s+(purge|clean|wipe|remove)$" {
            Write-Host ""
            Purge-CanaryTraps
            Write-Host ""
        }
        "^(wipe-ram|ram)$" {
            Write-Host ""
            Invoke-RamSanitize
            Write-Host ""
        }
        "^(vanish|burn|nuke-self)$" {
            Write-Host ""
            Invoke-SelfDestruct
            Write-Host ""
        }
        "^usb(\s+list)?$" {
            Write-Host ""
            Show-UsbInventory
            Write-Host ""
        }
        "^usb\s+deploy(\s+(\S+))?$" {
            $tDrv = $Matches[2]
            Write-Host ""
            Deploy-UsbOpSec -TargetDrive $tDrv
            Write-Host ""
        }
        "^usb\s+shield(\s+(on|off|status|enable|disable))?$" {
            $act = if ($Matches[2]) { $Matches[2] } else { "status" }
            Write-Host ""
            Set-UsbWriteProtect -Action $act
            Write-Host ""
        }
        "^(vm|vms|vm-hub|vmfortress)$" {
            Show-VmHub
        }
        "^vm\s+(watch|sentry|monitor)$" {
            Start-VmShieldSentinel
        }
        "^vm\s+(list|inventory|ls|status)$" {
            Show-VmInventory
        }
        "^vm\s+(fix|harden|harden-all)(\s+(\S+))?$" {
            $t = if ($Matches[3]) { $Matches[3] } else { "ALL" }
            Harden-VirtualBoxVMs -TargetVM $t
        }
        "^vm\s+ram\s+(\S+)\s+(\d+)$" {
            Set-VmRam -VmName $Matches[1] -RamMb ([int]$Matches[2])
        }
        "^vm\s+clip\s+(\S+)\s+(\S+)$" {
            Set-VmClipboard -VmName $Matches[1] -Mode $Matches[2]
        }
        "^vm\s+(audit|check|scan)$" {
            Write-Host "`n  === VIRTUAL MACHINE CONFIG AUDIT ===" -ForegroundColor Cyan
            $findings = Audit-VirtualBoxConfigurations
            if ($findings.Count -eq 0) {
                Write-Host "  [PASS] No high-risk VM leak configurations found.`n" -ForegroundColor Green
            } else {
                $findings | Format-Table -AutoSize
                Write-Host ""
            }
        }
        "^vm\s+stealth(\s+(on|enable|arm))?$" {
            Write-Host ""
            Enable-VmHostStealthFirewall | Out-Null
            Harden-VirtualAdapters
            Write-Host "  [+] VM Host Stealth firewall armed: Host listening ports hidden from guests.`n" -ForegroundColor Green
        }
        "^vm\s+stealth\s+(off|disable|disarm)$" {
            Write-Host ""
            Disable-VmHostStealthFirewall
            Write-Host "  [-] VM Host Stealth firewall rules removed.`n" -ForegroundColor Yellow
        }
        "^(quick|wizard|mode|modes)$" {
            Invoke-GuidedWizard
        }
        "^(guide|howto)(\s+(.+))?$" {
            Show-CommandGuide -Topic $Matches[3]
        }
        "^(help|\?)\s+(.+)$" {
            Show-CommandGuide -Topic $Matches[2]
        }
        "^(\?|help|menu|0)$" {
            Write-Host ""
            Show-Menu
        }
        "^(clear|cls)$" {
            Clear-Host
            Write-Header
            Show-Menu
        }
        "^(q|quit|exit)$" {
            Write-Host "`n  [+] operational session terminated. stay secure.`n" -ForegroundColor DarkGray
            $sessionActive = $false
            break
        }
        default {
            Write-Host "  unknown command '$inputCmd' (type 'help' for list, 'q' to quit)" -ForegroundColor DarkGray
        }
    }
}

return
