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
    [switch]$Intro,
    [switch]$Help
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulePath = Join-Path $PSScriptRoot "modules"
foreach ($mod in @("BackupRestore.psm1", "Telemetry.psm1", "Anonymity.psm1", "NetworkOpSec.psm1", "EgressRecon.psm1", "BrowserOpSec.psm1", "AntiForensics.psm1", "SecretsScanner.psm1", "HwIdOpSec.psm1", "DeadManSwitch.psm1", "Chameleon.psm1", "SentryMonitor.psm1", "IntroTour.psm1")) {
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
    Write-Host "v4.0  //  cross-platform opsec, defensive sentry & forensic camouflage" -ForegroundColor DarkGray
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

    Write-Host "`n  -- camouflage & plausible deniability" -ForegroundColor Cyan
    $chamResults = Audit-ChameleonState
    foreach ($r in $chamResults) {
        Write-StatusRow -State $(if ($r.Posture -eq "CIVILIAN_CAMOUFLAGE") { "HARDENED" } else { "CONFIGURABLE" }) -Label $r.Profile -Detail "$($r.Posture) ($($r.Decoys))"
    }

    Write-Host "`n  -- public sentry & defensive tripwire posture" -ForegroundColor Cyan
    $sentryResults = Audit-SentryPosture
    foreach ($r in $sentryResults) {
        Write-StatusRow -State $r.Status -Label $r.Check -Detail $r.Details
    }

    Write-Host "`n  -- disk encryption" -ForegroundColor Cyan
    $diskResult = Audit-DiskEncryption
    Write-StatusRow -State $diskResult.Status -Label $diskResult.Target -Detail $diskResult.Details

    $scoredEgress = @($egressResults | Where-Object { $_.Status -ne "CONFIGURABLE" } | ForEach-Object { $_.Status })
    $scoredBrowser = @($browserResults | Where-Object { $_.Status -ne "CONFIGURABLE" } | ForEach-Object { $_.Status })
    $scoredSentry = @($sentryResults | Where-Object { $_.Status -ne "CONFIGURABLE" } | ForEach-Object { $_.Status })
    $allChecks = @($telemetryResults.Status) + @($anonymityResults.Status) + @($networkResults.Status) + $scoredEgress + $scoredBrowser + @($traceResults.Status) + $scoredSentry
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
    Write-Host "    -Restore          revert system state from latest snapshot"
    Write-Host ""
}

function Show-Menu {
    Write-Host "  -- winopsec v4.0 -------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  pili ka sa options sa ibaba o i-type ang 'quick' para sa 1-click menu.`n" -ForegroundColor DarkGray

    Write-Host "  [1] audit & recon" -ForegroundColor White
    Write-Host "      1 / audit       - buong posture check at security score" -ForegroundColor Gray
    Write-Host "      8 / recon       - open listening ports, active sockets at VPN tunnel" -ForegroundColor DarkGray
    Write-Host "      7 / secrets     - scan ng hard drive para sa exposed keys at .env" -ForegroundColor DarkGray
    Write-Host "      hwid            - machine GUIDs (MachineGuid, SQM ID)" -ForegroundColor DarkGray

    Write-Host "`n  [2] public wi-fi & sentry (defense)" -ForegroundColor White
    Write-Host "      sentry          - real-time tripwire (ARP poison, port scan, mic tap)" -ForegroundColor Gray
    Write-Host "      sentry -autopanic - auto-cut ng Wi-Fi at lock screen kapag may umatake" -ForegroundColor Green
    Write-Host "      deadman         - USB lanyard trigger (panic kapag hinablot ang laptop)" -ForegroundColor DarkGray
    Write-Host "      9 / mac         - spoof ng MAC address ('mac reset' para ibalik)" -ForegroundColor DarkGray

    Write-Host "`n  [3] system hardening & shields" -ForegroundColor White
    Write-Host "      5 / harden-all  - i-apply lahat ng host, network, Mullvad at browser shields" -ForegroundColor Gray
    Write-Host "      mullvad harden  - post-quantum tunnel, DAITA at WFP killswitch" -ForegroundColor DarkGray
    Write-Host "      browser         - block WebRTC leak at password vault lock" -ForegroundColor DarkGray
    Write-Host "      browser launch  - buksan ang private ephemeral browser" -ForegroundColor DarkGray

    Write-Host "`n  [4] anti-forensics & linis" -ForegroundColor White
    Write-Host "      6 / wipe        - burahin ang history, runMRU, crash dumps at caches" -ForegroundColor Gray
    Write-Host "      wipe-pca        - burahin ang Windows 11 app execution history" -ForegroundColor DarkGray
    Write-Host "      wipe-shellbags  - burahin ang folder navigation tracking" -ForegroundColor DarkGray
    Write-Host "      wipe-reglogs    - i-flush ang registry transaction logs (.LOG1/.LOG2)" -ForegroundColor DarkGray
    Write-Host "      wipe-deleted    - burahin ang shadow copies at i-trim ang SSD" -ForegroundColor DarkGray
    Write-Host "      scrub <path>    - tanggalin ang metadata at baguhin ang timestamps" -ForegroundColor DarkGray

    Write-Host "`n  [5] civilian camouflage" -ForegroundColor White
    Write-Host "      chameleon       - magtanim ng normal na civilian files (para hindi suspicious)" -ForegroundColor Gray
    Write-Host "      chameleon -purge - tanggalin ang decoy files" -ForegroundColor DarkGray

    Write-Host "`n  [!] shortcuts & navigation" -ForegroundColor White
    Write-Host "      quick           - 1-click wizard para sa mga tinatamad mag-isip" -ForegroundColor Green
    Write-Host "      intro           - pakinggan ang boses at animated tutorial" -ForegroundColor Gray
    Write-Host "      guide <cmd>     - basahin kung para saan ang command" -ForegroundColor DarkGray
    Write-Host "      panic           - emergency cut ng Wi-Fi, wipe traces at lock screen" -ForegroundColor Red
    Write-Host "      panic -poweroff - emergency hard poweroff agad" -ForegroundColor DarkRed
    Write-Host "      restore         - ibalik ang dating settings galing sa snapshot" -ForegroundColor DarkGray
    Write-Host "      q / quit        - exit" -ForegroundColor DarkGray
    Write-Host "  ------------------------------------------------------------------------------`n" -ForegroundColor DarkGray
}

function Invoke-GuidedWizard {
    Write-Host "`n  -- 1-click scenario menu -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Piliin ang sitwasyon mo ngayon:`n" -ForegroundColor Gray

    Write-Host "  [1] Cafe / Public Wi-Fi Mode" -ForegroundColor White
    Write-Host "      -> Spoof MAC, lock Mullvad VPN, at bantay Sentry with Auto-Panic." -ForegroundColor DarkGray

    Write-Host "  [2] Complete Host Lockdown" -ForegroundColor White
    Write-Host "      -> I-lock ang LSASS memory, patayin ang telemetry, at i-block ang leaks." -ForegroundColor DarkGray

    Write-Host "  [3] Secure Ephemeral Browsing" -ForegroundColor White
    Write-Host "      -> Block WebRTC leaks at buksan ang private browser session." -ForegroundColor DarkGray

    Write-Host "  [4] Post-Session Forensics Scrub & Camouflage" -ForegroundColor White
    Write-Host "      -> Burahin ang PCA/ShellBags at magtanim ng civilian decoy files." -ForegroundColor DarkGray

    Write-Host "  [5] Full Security Posture Audit" -ForegroundColor White
    Write-Host "      -> I-scan lahat ng 47 checks para makita ang score mo." -ForegroundColor DarkGray

    Write-Host "  [0] Back / Cancel" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "pili [0-5]: " -ForegroundColor Green -NoNewline
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
            Write-Host "`n  [+] Inilalapat ang complete host lockdown..." -ForegroundColor Gray
            Invoke-HardenAll
        }
        "3" {
            Write-Host "`n  [+] Binubuksan ang hardened ephemeral browser..." -ForegroundColor Gray
            Harden-Browsers
            Start-HardenedBrowser
        }
        "4" {
            Write-Host "`n  [+] Nililinis ang execution logs at nagtatanim ng chameleon decoys..." -ForegroundColor Gray
            Invoke-TraceWipe
            Invoke-PcaWipe
            Invoke-ShellBagsSanitize
            Invoke-RegistryLogSanitize
            Invoke-ChameleonNoise
            Write-Host "  [+] Malinis na at may disguise noise na active." -ForegroundColor Green
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
        "^(sentry|monitor|tripwire)$" {
            Write-Host "  === SENTRY & DEFENSIVE TRIPWIRE GUIDE ===" -ForegroundColor Cyan
            Write-Host "  Purpose: Real-time defense against attackers on the same public Wi-Fi or LAN." -ForegroundColor White
            Write-Host "  Monitors 7 attack vectors:" -ForegroundColor Gray
            Write-Host "    - ARP Poisoning / MITM (Bettercap/Ettercap gateway spoofing)" -ForegroundColor DarkGray
            Write-Host "    - Inbound Port Scans (Nmap SYN half-open probes on ports 445, 135, 3389)" -ForegroundColor DarkGray
            Write-Host "    - Eavesdropping (Processes actively recording microphone or camera)" -ForegroundColor DarkGray
            Write-Host "    - Unauthorized USB (BadUSB / Rubber Ducky keystroke injectors)" -ForegroundColor DarkGray
            Write-Host "    - Rogue DNS (Untrusted local resolvers or hosts tampering)" -ForegroundColor DarkGray
            Write-Host "    - Evil Twin Wi-Fi (BSSID access point mutation)" -ForegroundColor DarkGray
            Write-Host "    - Active Reverse Shells (Outbound sockets from cmd/powershell)" -ForegroundColor DarkGray
            Write-Host "`n  Usage:" -ForegroundColor White
            Write-Host "    sentry            -> Continuous monitoring with audible alerts" -ForegroundColor Yellow
            Write-Host "    sentry -autopanic -> Auto-disables Wi-Fi and locks PC if attacked" -ForegroundColor Red
        }
        "^(chameleon|camouflage|noise)$" {
            Write-Host "  === FORENSIC CHAMELEON GUIDE ===" -ForegroundColor Cyan
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
            Write-Host "  === USB DEAD MAN'S SWITCH GUIDE ===" -ForegroundColor Cyan
            Write-Host "  Purpose: Anti-snatch physical defense (like the Silk Road Glen Park arrest)." -ForegroundColor White
            Write-Host "  How it works:" -ForegroundColor Gray
            Write-Host "    Attach a USB flash drive with a wrist lanyard to your laptop." -ForegroundColor DarkGray
            Write-Host "    If someone snatches your laptop and the USB pulls out, WinOpSec triggers" -ForegroundColor DarkGray
            Write-Host "    an immediate panic wipe, route kill, and workstation lock or poweroff." -ForegroundColor DarkGray
            Write-Host "`n  Usage:" -ForegroundColor White
            Write-Host "    deadman          -> Select USB drive and arm monitor (200ms poll)" -ForegroundColor Yellow
        }
        "^(pca|wipe-pca)$" {
            Write-Host "  === PROGRAM COMPATIBILITY ASSISTANT (PCA) GUIDE ===" -ForegroundColor Cyan
            Write-Host "  Purpose: Neutralizes Windows 11 hidden program execution tracking." -ForegroundColor White
            Write-Host "  Why it matters:" -ForegroundColor Gray
            Write-Host "    Windows 11 silently logs every executable you run into PcaAppLaunchDic.txt." -ForegroundColor DarkGray
            Write-Host "    Even if you delete Prefetch, PCA still has the full history." -ForegroundColor DarkGray
            Write-Host "`n  Usage:" -ForegroundColor White
            Write-Host "    wipe-pca         -> Purges dictionary and locks file with read-only ACL" -ForegroundColor Yellow
        }
        "^(shellbags|wipe-shellbags)$" {
            Write-Host "  === SHELLBAGS SANITIZER GUIDE ===" -ForegroundColor Cyan
            Write-Host "  Purpose: Wipes Explorer folder browsing and USB folder access history." -ForegroundColor White
            Write-Host "  Why it matters:" -ForegroundColor Gray
            Write-Host "    Windows stores every folder, flash drive, and network share you ever opened" -ForegroundColor DarkGray
            Write-Host "    in the registry BagMRU keys. This reveals what directories you explored." -ForegroundColor DarkGray
            Write-Host "`n  Usage:" -ForegroundColor White
            Write-Host "    wipe-shellbags   -> Removes all BagMRU and Bags keys" -ForegroundColor Yellow
        }
        "^(mullvad)$" {
            Write-Host "  === MULLVAD PARTNER LOCKDOWN GUIDE ===" -ForegroundColor Cyan
            Write-Host "  Purpose: Enforces state-level cryptographic VPN protections." -ForegroundColor White
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
            Write-Host "  === EMERGENCY PANIC PROTOCOL GUIDE ===" -ForegroundColor Red
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
        default {
            Write-Host "  === WINOPSEC OPERATIONAL GUIDE ===" -ForegroundColor Cyan
            Write-Host "  Type 'guide <topic>' for in-depth details on any module:`n" -ForegroundColor DarkGray
            Write-Host "    guide sentry     -> Real-time Public Wi-Fi tripwire & BadUSB monitor" -ForegroundColor White
            Write-Host "    guide chameleon  -> Synthetic civilian camouflage & SANS anti-absence" -ForegroundColor White
            Write-Host "    guide deadman    -> USB BusKill lanyard anti-snatch hardware trigger" -ForegroundColor White
            Write-Host "    guide pca        -> Windows 11 hidden program execution logs" -ForegroundColor White
            Write-Host "    guide shellbags  -> Explorer folder navigation histories" -ForegroundColor White
            Write-Host "    guide mullvad    -> Post-quantum, DAITA & WFP killswitch setup" -ForegroundColor White
            Write-Host "    guide panic      -> Emergency duress protocol" -ForegroundColor White
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
if ($Restore)       { Write-Header; Restore-OpSecState | Out-Null; exit }
if ($Intro)         { Invoke-CyberIntro; exit }

Clear-Host
Write-Header
Show-Menu

while ($true) {
    $privTag = if ($IsElevated) { "admin" } else { "user" }
    $vpnTag  = if (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq "10.64.0.1" }) { "vpn:mullvad" } else { "vpn:off" }
    Write-Host "winopsec " -ForegroundColor DarkGray -NoNewline
    Write-Host "[$privTag | $vpnTag] " -ForegroundColor Cyan -NoNewline
    Write-Host "> " -ForegroundColor White -NoNewline
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
        "^(intro|tour|hello|onboarding)$" {
            Invoke-CyberIntro
            Clear-Host
            Write-Header
            Show-Menu
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
