#!/usr/bin/env pwsh
[CmdletBinding()]
param (
    [switch]$Audit,
    [switch]$Recon,
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
    [string]$Scrub,
    [switch]$SpoofMac,
    [switch]$ScanSecrets,
    [switch]$Panic,
    [switch]$Restore,
    [switch]$Help
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulePath = Join-Path $PSScriptRoot "modules"
foreach ($mod in @("BackupRestore.psm1", "Telemetry.psm1", "Anonymity.psm1", "NetworkOpSec.psm1", "EgressRecon.psm1", "BrowserOpSec.psm1", "AntiForensics.psm1", "SecretsScanner.psm1", "HwIdOpSec.psm1")) {
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

    Write-Host ""
    Write-Host "  winopsec " -ForegroundColor White -NoNewline
    Write-Host "v3.2  //  cross-platform opsec, mullvad partner & browser shield" -ForegroundColor DarkGray
    Write-Host "  os   : " -ForegroundColor DarkGray -NoNewline
    Write-Host "$HostOS [$Arch]" -ForegroundColor Gray
    Write-Host "  priv : " -ForegroundColor DarkGray -NoNewline
    Write-Host "$privTag" -ForegroundColor $privColor
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
    Write-Host "  -- telemetry, lsass & host shield" -ForegroundColor Cyan
    $telemetryResults = Audit-Telemetry
    foreach ($r in $telemetryResults) {
        Write-StatusRow -State $r.Status -Label $r.Check -Detail $r.Details
    }

    Write-Host "`n  -- anonymity & sensors (vpn-safe)" -ForegroundColor Cyan
    $anonymityResults = Audit-Anonymity
    foreach ($r in $anonymityResults) {
        Write-StatusRow -State $r.Status -Label $r.Check -Detail $r.Details
    }

    Write-Host "`n  -- network & protocol leaks" -ForegroundColor Cyan
    $networkResults = Audit-NetworkOpSec
    foreach ($r in $networkResults) {
        Write-StatusRow -State $r.Status -Label "$($r.Protocol): $($r.Check)" -Detail "$($r.Details) [risk:$($r.Risk)]"
    }

    Write-Host "`n  -- mullvad / vpn tunnel & egress firewall" -ForegroundColor Cyan
    $egressResults = Audit-VpnAndEgress
    foreach ($r in $egressResults) {
        Write-StatusRow -State $r.Status -Label $r.Check -Detail $r.Details
    }

    Write-Host "`n  -- browser opsec (webrtc, doh & vault shield)" -ForegroundColor Cyan
    $browserResults = Audit-BrowserOpSec
    foreach ($r in $browserResults) {
        Write-StatusRow -State $r.Status -Label $r.Check -Detail $r.Details
    }

    Write-Host "`n  -- runtime traces & forensic artifacts" -ForegroundColor Cyan
    $traceResults = Audit-Traces
    foreach ($r in $traceResults) {
        Write-StatusRow -State $r.Status -Label $r.Artifact -Detail $r.Count
    }

    Write-Host "`n  -- hardware identity & cryptographic anchors" -ForegroundColor Cyan
    $hwResults = Audit-HardwareIdentity
    foreach ($r in $hwResults) {
        Write-StatusRow -State $(if ($r.Status -eq "CLEAN") { "CLEAN" } else { "CONFIGURABLE" }) -Label $r.Artifact -Detail "$($r.Value) [risk:$($r.Risk)]"
    }

    Write-Host "`n  -- disk encryption" -ForegroundColor Cyan
    $diskResult = Audit-DiskEncryption
    Write-StatusRow -State $diskResult.Status -Label $diskResult.Target -Detail $diskResult.Details

    $scoredEgress = @($egressResults | Where-Object { $_.Status -ne "CONFIGURABLE" } | ForEach-Object { $_.Status })
    $scoredBrowser = @($browserResults | Where-Object { $_.Status -ne "CONFIGURABLE" } | ForEach-Object { $_.Status })
    $allChecks = @($telemetryResults.Status) + @($anonymityResults.Status) + @($networkResults.Status) + $scoredEgress + $scoredBrowser + @($traceResults.Status)
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
    Write-Host "`n  done." -ForegroundColor Green
}

function Invoke-TraceWipe {
    Shred-PowerShellHistory
    Clear-ExplorerTraces
    Clear-BrowserTraces
    Write-Host "`n  traces & browser caches purged." -ForegroundColor Green
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
    Write-Host "    -Mullvad          verify Mullvad VPN partner state, killswitch, PQ tunnel & exit IP"
    Write-Host "    -Browser          harden Chrome/Brave/Edge/Firefox (block WebRTC leak, vault & enforce Mullvad DoH)"
    Write-Host "    -LaunchBrowser    launch preferred browser in isolated ephemeral OpSec mode"
    Write-Host "    -HardenAll        apply host, VPN, Mullvad, browser, network & firewall hardening"
    Write-Host "    -WipeTraces       shred shell histories, UserAssist, MRU, ADS, browser caches & crash dumps"
    Write-Host "    -Scrub <path>     strip EXIF/ADS metadata and normalize timestamps on file/folder"
    Write-Host "    -SpoofMac         randomize active physical adapter MAC address"
    Write-Host "    -ScanSecrets      scan user dirs for private keys, .env & API tokens"
    Write-Host "    -Panic            emergency shred all traces, flush ARP/DNS & lock screen"
    Write-Host "    -Restore          revert system state from latest snapshot"
    Write-Host ""
}

function Show-Menu {
    Write-Host "  commands:" -ForegroundColor DarkGray
    Write-Host "    1  audit          posture, memory shield, VPN/Mullvad, browser & trace check"
    Write-Host "    2  telemetry      disable telemetry, WDigest, SAM enum + enable LSASS PPL & NTLMv2"
    Write-Host "    3  anon           VPN-safe geolocation kill (no popup), AI/Recall & cam/mic lock"
    Write-Host "    4  net            block LLMNR, mDNS, NetBIOS, Teredo, WPAD + enforce SMB signing"
    Write-Host "    5  harden-all     apply all host, network, Mullvad & browser hardening (with snapshot)"
    Write-Host "    6  wipe           shred histories, UserAssist, ComDlg32, ADS, WER & browser caches"
    Write-Host "    7  secrets        scan user paths for keys, .env & infostealer token targets"
    Write-Host "    8  recon          live VPN tunnel check, exposed listening ports & active sockets"
    Write-Host "    9  mac            spoof physical network adapter hardware MAC ('mac reset' to restore)"
    Write-Host "    hwid              inspect cryptographic machine anchors (MachineGuid, SQM)"
    Write-Host "    hwid randomize    generate fresh cryptographically random hardware GUIDs"
    Write-Host "    mullvad           status & exit (or 'mullvad harden' | 'rotate' | 'daita on' | 'multihop on')"
    Write-Host "    browser           harden browsers | 'browser list' | 'browser clean' | 'browser autofill' | 'browser remove <acct>'"
    Write-Host "    browser launch    launch preferred browser (Mullvad Browser / hardened ephemeral mode)"
    Write-Host "    forensic-check    inspect VSS snapshots, USN deletion journal, timeline & slack space"
    Write-Host "    wipe-pca          purge Windows 11 PCA launch dictionaries (PcaAppLaunchDic.txt)"
    Write-Host "    wipe-shellbags    purge Explorer ShellBags (BagMRU & Bags folder navigation histories)"
    Write-Host "    wipe-srum         purge SRUM ESE database (SRUDB.dat) & lock DPS telemetry service"
    Write-Host "    scrub-wifi        purge NetworkList Wi-Fi profiles & BSSIDs (anti-WiGLE triangulation)"
    Write-Host "    wipe-deleted      purge VSS shadows, reset USN deletion logs & re-trim SSD ('wipe-deleted -cipher')"
    Write-Host "    wipe-logs         purge all 400+ Windows event logs (Security, System, PowerShell, WLAN)"
    Write-Host "    scrub <path>      strip EXIF/NTFS Zone.Identifier & normalize file timestamps"
    Write-Host "    panic             apex duress protocol: terminate apps, sever routes, wipe traces & lock"
    Write-Host "    panic -poweroff   emergency hard shutdown with zero-trace power severance"
    Write-Host "    restore           rollback system config from latest snapshot"
    Write-Host "    q  quit"
    Write-Host ""
}

if ($Help)          { Show-Usage; exit }
if ($Audit)         { Write-Header; Invoke-Audit; exit }
if ($Recon)         { Write-Header; Invoke-NetworkRecon; exit }
if ($Mullvad)       { Write-Header; Invoke-MullvadPartner -Action "status"; exit }
if ($Browser)       { Write-Header; Harden-Browsers; exit }
if ($LaunchBrowser) { Write-Header; Start-HardenedBrowser; exit }
if ($HardenAll)     { Write-Header; Invoke-HardenAll; exit }
if ($WipeTraces)    { Write-Header; Invoke-TraceWipe; exit }
if ($PcaWipe)       { Write-Header; Invoke-PcaWipe; exit }
if ($ShellBags)     { Write-Header; Invoke-ShellBagsSanitize; exit }
if ($Srum)          { Write-Header; Invoke-SrumNeutralize; exit }
if ($ScrubWifi)     { Write-Header; Invoke-NetworkListScrub; exit }
if ($RandomizeHwId) { Write-Header; Invoke-HwIdRandomize; exit }
if ($Scrub)         { Write-Header; Invoke-MetadataScrub -TargetPath $Scrub; exit }
if ($SpoofMac)      { Write-Header; Invoke-MacSpoof; exit }
if ($ScanSecrets)   { Write-Header; Invoke-SecretsScan; exit }
if ($Panic)         { Write-Header; Invoke-PanicProtocol; exit }
if ($Restore)       { Write-Header; Restore-OpSecState | Out-Null; exit }

Clear-Host
Write-Header
Show-Menu

while ($true) {
    Write-Host "opsec> " -ForegroundColor Cyan -NoNewline
    $rawInput = (Read-Host).Trim()
    $inputCmd = $rawInput.ToLower()

    if ($inputCmd -match "^scrub\s+(.+)$") {
        $target = $rawInput.Substring(5).Trim().Trim('"').Trim("'")
        Write-Host ""
        Invoke-MetadataScrub -TargetPath $target
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
        "^(\?|help|menu)$" {
            Write-Host ""
            Show-Menu
        }
        "^(clear|cls)$" {
            Clear-Host
            Write-Header
            Show-Menu
        }
        "^(0|q|quit|exit)$" {
            break
        }
        "^$" {
            continue
        }
        default {
            Write-Host "  unknown command '$inputCmd' (type 'help' for list, 'q' to quit)" -ForegroundColor DarkGray
        }
    }
}
