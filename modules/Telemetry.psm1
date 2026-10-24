function Test-AdminPrivilege {
    if ($PSVersionTable.Platform -eq 'Unix' -or $IsLinux -or $IsMacOS) {
        try { return ((id -u 2>$null) -eq 0) } catch { return $false }
    }
    try {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Test-IsWindowsOS {
    return ($env:OS -eq "Windows_NT") -and (-not $IsLinux) -and (-not $IsMacOS)
}

function Audit-Telemetry {
    $results = @()

    if (Test-IsWindowsOS) {
        $telemetryVal = $null
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection") {
            $item = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
            if ($item) { $telemetryVal = $item.AllowTelemetry }
        }
        $results += [PSCustomObject]@{
            Category = "Telemetry"
            Check    = "AllowTelemetry Policy"
            Status   = if ($telemetryVal -eq 0 -or $telemetryVal -eq 1) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($telemetryVal -eq 0) { "0 (off/security)" } elseif ($telemetryVal -eq 1) { "1 (basic)" } else { "default (full)" }
        }

        $advVal = $null
        if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo") {
            $item = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -ErrorAction SilentlyContinue
            if ($item) { $advVal = $item.Enabled }
        }
        $results += [PSCustomObject]@{
            Category = "Privacy"
            Check    = "Advertising ID"
            Status   = if ($advVal -eq 0) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($advVal -eq 0) { "disabled" } else { "active" }
        }

        $pubAct = $null
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System") {
            $item = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -ErrorAction SilentlyContinue
            if ($item) { $pubAct = $item.PublishUserActivities }
        }
        $results += [PSCustomObject]@{
            Category = "Privacy"
            Check    = "Activity Timeline"
            Status   = if ($pubAct -eq 0) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($pubAct -eq 0) { "disabled" } else { "enabled" }
        }

        $clipSync = $null
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System") {
            $item = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -ErrorAction SilentlyContinue
            if ($item) { $clipSync = $item.AllowCrossDeviceClipboard }
        }
        $results += [PSCustomObject]@{
            Category = "Privacy"
            Check    = "Cloud Clipboard Sync"
            Status   = if ($clipSync -eq 0) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($clipSync -eq 0) { "disabled" } else { "enabled" }
        }

        $diagSvc = Get-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
        $diagStart = if ($diagSvc -and $diagSvc.StartType) { $diagSvc.StartType } else { "restricted" }
        $results += [PSCustomObject]@{
            Category = "Services"
            Check    = "DiagTrack Service"
            Status   = if (-not $diagSvc -or ($diagSvc.Status -eq "Stopped" -and ($diagSvc.StartType -eq "Disabled" -or -not $diagSvc.StartType))) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($diagSvc) { "$($diagSvc.Status.ToString().ToLower()) ($($diagStart.ToString().ToLower()))" } else { "absent" }
        }

        $dmwSvc = Get-Service -Name "dmwappushservice" -ErrorAction SilentlyContinue
        $dmwStart = if ($dmwSvc -and $dmwSvc.StartType) { $dmwSvc.StartType } else { "restricted" }
        $results += [PSCustomObject]@{
            Category = "Services"
            Check    = "dmwappushservice"
            Status   = if (-not $dmwSvc -or ($dmwSvc.Status -eq "Stopped" -and ($dmwSvc.StartType -eq "Disabled" -or -not $dmwSvc.StartType))) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($dmwSvc) { "$($dmwSvc.Status.ToString().ToLower()) ($($dmwStart.ToString().ToLower()))" } else { "absent" }
        }

        $bingVal = $null
        if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search") {
            $item = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -ErrorAction SilentlyContinue
            if ($item) { $bingVal = $item.BingSearchEnabled }
        }
        if ($bingVal -ne 0 -and (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
            $item = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -ErrorAction SilentlyContinue
            if ($item -and $item.DisableWebSearch -eq 1) { $bingVal = 0 }
        }
        $results += [PSCustomObject]@{
            Category = "Privacy"
            Check    = "Start Menu Web Search"
            Status   = if ($bingVal -eq 0) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($bingVal -eq 0) { "disabled" } else { "enabled" }
        }

        # Credential & Host Memory Shield Checks
        $wdigest = $null
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest") {
            $item = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
            if ($item) { $wdigest = $item.UseLogonCredential }
        }
        $results += [PSCustomObject]@{
            Category = "HostOpSec"
            Check    = "WDigest Cleartext Caching"
            Status   = if ($wdigest -eq 0 -or $null -eq $wdigest) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($wdigest -eq 0 -or $null -eq $wdigest) { "disabled (no plaintext LSASS)" } else { "enabled (cleartext risk)" }
        }

        $lsaPpl = $null
        $lmLevel = $null
        $anonSam = $null
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa") {
            $lsaProps = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
            if ($lsaProps) {
                $lsaPpl  = $lsaProps.RunAsPPL
                $lmLevel = $lsaProps.LmCompatibilityLevel
                $anonSam = $lsaProps.RestrictAnonymousSAM
            }
        }
        $results += [PSCustomObject]@{
            Category = "HostOpSec"
            Check    = "LSASS Memory Guard (RunAsPPL)"
            Status   = if ($lsaPpl -eq 1 -or $lsaPpl -eq 2) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($lsaPpl -eq 1 -or $lsaPpl -eq 2) { "protected process light (PPL)" } else { "unprotected" }
        }

        $results += [PSCustomObject]@{
            Category = "HostOpSec"
            Check    = "NTLMv2-Only & SAM Lockdown"
            Status   = if ($lmLevel -ge 5 -and $anonSam -eq 1) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($lmLevel -ge 5 -and $anonSam -eq 1) { "LM/NTLMv1 refused, SAM restricted" } else { "legacy NTLM or SAM allowed" }
        }

        # Kernel Memory Paging Guard (DisablePagingExecutive)
        $pExec = $null
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management") {
            $mProps = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -ErrorAction SilentlyContinue
            if ($mProps) { $pExec = $mProps.DisablePagingExecutive }
        }
        $results += [PSCustomObject]@{
            Category = "HostOpSec"
            Check    = "Kernel Memory Paging Guard"
            Status   = if ($pExec -eq 1) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($pExec -eq 1) { "DisablePagingExecutive enforced (RAM-locked)" } else { "unprotected (kernel code paged to disk)" }
        }

        # Fast Startup & Hibernation Memory Bleed
        $hiberBoot = $null
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power") {
            $pwrProps = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -ErrorAction SilentlyContinue
            if ($pwrProps) { $hiberBoot = $pwrProps.HiberbootEnabled }
        }
        $hiberFileExists = Test-Path "C:\hiberfil.sys" -ErrorAction SilentlyContinue
        $hiberClean = ($hiberBoot -eq 0 -or $null -eq $hiberBoot) -and (-not $hiberFileExists)
        $results += [PSCustomObject]@{
            Category = "HostOpSec"
            Check    = "Fast Startup & Hibernation Dump"
            Status   = if ($hiberClean) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($hiberClean) { "disabled (zero RAM dump on shutdown)" } else { "active (hiberfil.sys memory bleed risk)" }
        }

        # External DMA Port Guard (Anti-PCILeech / Thunderbolt Hardware Raid Defense)
        $dmaUnderLock = $null
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE") {
            $fveProps = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "DisableExternalDMAUnderLock" -ErrorAction SilentlyContinue
            if ($fveProps) { $dmaUnderLock = $fveProps.DisableExternalDMAUnderLock }
        }
        $results += [PSCustomObject]@{
            Category = "HostOpSec"
            Check    = "External DMA Guard (Anti-PCILeech)"
            Status   = if ($dmaUnderLock -eq 1) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($dmaUnderLock -eq 1) { "locked (external Thunderbolt/PCIe DMA blocked)" } else { "unprotected (DMA hardware raid risk) [risk:high]" }
        }

        # UEFI WPBT Firmware Binary Injection Guard
        $wpbt = $null
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager") {
            $smProps = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "DisableWpbtExecution" -ErrorAction SilentlyContinue
            if ($smProps) { $wpbt = $smProps.DisableWpbtExecution }
        }
        $results += [PSCustomObject]@{
            Category = "HostOpSec"
            Check    = "UEFI WPBT Firmware Execution"
            Status   = if ($wpbt -eq 1) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($wpbt -eq 1) { "disabled (OEM firmware backdoor blocked)" } else { "unrestricted (motherboard ROM injection allowed) [risk:med]" }
        }
    } elseif ($IsMacOS) {
        $diagAuto = (defaults read "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" AutoSubmit 2>$null)
        $results += [PSCustomObject]@{
            Category = "Telemetry"
            Check    = "CrashReporter AutoSubmit"
            Status   = if ($diagAuto -eq "0") { "HARDENED" } else { "EXPOSED" }
            Details  = if ($diagAuto -eq "0") { "disabled" } else { "active/default" }
        }
        $adTrack = (defaults read com.apple.AdLib allowApplePersonalizedAdvertising 2>$null)
        $results += [PSCustomObject]@{
            Category = "Privacy"
            Check    = "Apple Personalized Ads"
            Status   = if ($adTrack -eq "0") { "HARDENED" } else { "EXPOSED" }
            Details  = if ($adTrack -eq "0") { "disabled" } else { "enabled" }
        }
    } else {
        $apportActive = $false
        if (Test-Path "/etc/default/apport") {
            $content = Get-Content "/etc/default/apport" -Raw -ErrorAction SilentlyContinue
            if ($content -match "enabled=1") { $apportActive = $true }
        }
        $results += [PSCustomObject]@{
            Category = "Telemetry"
            Check    = "Apport Crash Reporting"
            Status   = if (-not $apportActive) { "HARDENED" } else { "EXPOSED" }
            Details  = if (-not $apportActive) { "disabled/absent" } else { "enabled (/etc/default/apport)" }
        }

        $whoopsie = (systemctl is-active whoopsie 2>$null)
        $results += [PSCustomObject]@{
            Category = "Services"
            Check    = "Whoopsie / Error Daemon"
            Status   = if ($whoopsie -ne "active") { "HARDENED" } else { "EXPOSED" }
            Details  = if ($whoopsie -eq "active") { "running" } else { "inactive" }
        }

        $corePattern = if (Test-Path "/proc/sys/kernel/core_pattern") { (Get-Content "/proc/sys/kernel/core_pattern" -Raw).Trim() } else { "none" }
        $results += [PSCustomObject]@{
            Category = "Telemetry"
            Check    = "Kernel Core Dumps"
            Status   = if ($corePattern -eq "|/bin/false" -or $corePattern -eq "none") { "HARDENED" } else { "EXPOSED" }
            Details  = $corePattern
        }

        $ptraceScope = if (Test-Path "/proc/sys/kernel/yama/ptrace_scope") { (Get-Content "/proc/sys/kernel/yama/ptrace_scope" -Raw).Trim() } else { "0" }
        $results += [PSCustomObject]@{
            Category = "HostOpSec"
            Check    = "Yama ptrace Memory Scope"
            Status   = if ([int]$ptraceScope -ge 1) { "HARDENED" } else { "EXPOSED" }
            Details  = "ptrace_scope=$ptraceScope"
        }
    }

    return $results
}

function Harden-Telemetry {
    $isAdmin = Test-AdminPrivilege

    if (Test-IsWindowsOS) {
        $advPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
        if (-not (Test-Path $advPath)) { New-Item -Path $advPath -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $advPath -Name "Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Host "  ok  advertising_id = 0" -ForegroundColor Green

        $cloudPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
        if (-not (Test-Path $cloudPath)) { New-Item -Path $cloudPath -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $cloudPath -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
        Write-Host "  ok  tailored_experiences = 0" -ForegroundColor Green

        $searchPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
        if (-not (Test-Path $searchPath)) { New-Item -Path $searchPath -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $searchPath -Name "BingSearchEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $searchPath -Name "CortanaConsent" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Host "  ok  start_menu_bing_search = 0" -ForegroundColor Green

        $expPolicy = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $expPolicy)) { New-Item -Path $expPolicy -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $expPolicy -Name "NoRecentDocsHistory" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $expPolicy -Name "ClearRecentDocsOnExit" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue

        $expAdv = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        if (-not (Test-Path $expAdv)) { New-Item -Path $expAdv -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $expAdv -Name "Start_TrackDocs" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $expAdv -Name "Start_TrackProgs" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Host "  ok  recent_docs_tracking & jumplists = 0" -ForegroundColor Green

        if ($isAdmin) {
            $dataColl = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            if (-not (Test-Path $dataColl)) { New-Item -Path $dataColl -Force | Out-Null }
            Set-ItemProperty -Path $dataColl -Name "AllowTelemetry" -Type DWord -Value 0 -Force
            Set-ItemProperty -Path $dataColl -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1 -Force
            Write-Host "  ok  allow_telemetry = 0" -ForegroundColor Green

            $sysPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
            if (-not (Test-Path $sysPolicy)) { New-Item -Path $sysPolicy -Force | Out-Null }
            Set-ItemProperty -Path $sysPolicy -Name "PublishUserActivities" -Type DWord -Value 0 -Force
            Set-ItemProperty -Path $sysPolicy -Name "UploadUserActivities" -Type DWord -Value 0 -Force
            Set-ItemProperty -Path $sysPolicy -Name "AllowClipboardHistory" -Type DWord -Value 0 -Force
            Set-ItemProperty -Path $sysPolicy -Name "AllowCrossDeviceClipboard" -Type DWord -Value 0 -Force

            $winSearchPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            if (-not (Test-Path $winSearchPolicy)) { New-Item -Path $winSearchPolicy -Force | Out-Null }
            Set-ItemProperty -Path $winSearchPolicy -Name "DisableWebSearch" -Type DWord -Value 1 -Force
            Set-ItemProperty -Path $winSearchPolicy -Name "ConnectedSearchUseWeb" -Type DWord -Value 0 -Force
            Write-Host "  ok  activity_timeline, cloud_clipboard & web_search = 0" -ForegroundColor Green

            # Memory & Credential Shield (WDigest, LSASS RunAsPPL, NTLMv2-only, CachedLogonsCount=0, AutoRun=0)
            $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
            if (-not (Test-Path $wdigestPath)) { New-Item -Path $wdigestPath -Force | Out-Null }
            Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Type DWord -Value 0 -Force

            $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            if (Test-Path $lsaPath) {
                Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -Type DWord -Value 1 -Force
                Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -Type DWord -Value 1 -Force
                Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Type DWord -Value 1 -Force
                Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Type DWord -Value 5 -Force
            }

            $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            if (Test-Path $winlogonPath) {
                Set-ItemProperty -Path $winlogonPath -Name "CachedLogonsCount" -Type String -Value "0" -Force
            }

            $werPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
            if (-not (Test-Path $werPolicy)) { New-Item -Path $werPolicy -Force | Out-Null }
            Set-ItemProperty -Path $werPolicy -Name "Disabled" -Type DWord -Value 1 -Force

            $autoRunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            if (-not (Test-Path $autoRunPath)) { New-Item -Path $autoRunPath -Force | Out-Null }
            Set-ItemProperty -Path $autoRunPath -Name "NoDriveTypeAutoRun" -Type DWord -Value 255 -Force
            Write-Host "  ok  lsass_ppl = 1, ntlmv2_only = 5, wdigest = 0, cached_logons = 0" -ForegroundColor Green

            # Anti-PCILeech & External DMA Physical Port Defense
            $fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
            if (-not (Test-Path $fvePath)) { New-Item -Path $fvePath -Force | Out-Null }
            Set-ItemProperty -Path $fvePath -Name "DisableExternalDMAUnderLock" -Type DWord -Value 1 -Force
            Write-Host "  ok  disable_external_dma_under_lock = 1 (anti-PCILeech physical DMA defense)" -ForegroundColor Green

            # Block UEFI WPBT (Windows Platform Binary Table) firmware-level code injection
            $sessionMgr = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
            if (Test-Path $sessionMgr) {
                Set-ItemProperty -Path $sessionMgr -Name "DisableWpbtExecution" -Type DWord -Value 1 -Force
                Write-Host "  ok  disable_wpbt_execution = 1 (motherboard firmware backdoor blocked)" -ForegroundColor Green
            }

            # Anti-Forensic Memory & Execution Tracing Shield (Prefetch, Superfetch, Hibernation, ClearPageFile)
            $memMgmt = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            if (Test-Path $memMgmt) {
                Set-ItemProperty -Path $memMgmt -Name "ClearPageFileAtShutdown" -Type DWord -Value 1 -Force
                Set-ItemProperty -Path $memMgmt -Name "DisablePagingExecutive" -Type DWord -Value 1 -Force
            }
            $pwrMgmt = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
            if (Test-Path $pwrMgmt) {
                Set-ItemProperty -Path $pwrMgmt -Name "HiberbootEnabled" -Type DWord -Value 0 -Force
            }
            $pfParams = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
            if (-not (Test-Path $pfParams)) { New-Item -Path $pfParams -Force | Out-Null }
            Set-ItemProperty -Path $pfParams -Name "EnablePrefetcher" -Type DWord -Value 0 -Force
            Set-ItemProperty -Path $pfParams -Name "EnableSuperfetch" -Type DWord -Value 0 -Force

            Get-Service -Name "SysMain" -ErrorAction SilentlyContinue | ForEach-Object {
                Stop-Service -Name "SysMain" -Force -ErrorAction SilentlyContinue
                Set-Service -Name "SysMain" -StartupType Disabled -ErrorAction SilentlyContinue
            }

            try {
                powercfg /h off 2>$null | Out-Null
            } catch {}
            Write-Host "  ok  prefetch = 0, pagefile_clear_on_shutdown = 1, hibernation (hiberfil.sys) = killed" -ForegroundColor Green

            foreach ($s in @("DiagTrack", "dmwappushservice", "WerSvc")) {
                $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
                if ($svc) {
                    Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue
                    Write-Host "  ok  service/$s -> disabled" -ForegroundColor Green
                }
            }

            $tasks = @(
                "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
                "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
                "\Microsoft\Windows\Autochk\Proxy",
                "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
                "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
                "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
            )
            foreach ($t in $tasks) {
                try {
                    Disable-ScheduledTask -TaskPath ($t.Substring(0, $t.LastIndexOf("\") + 1)) -TaskName ($t.Substring($t.LastIndexOf("\") + 1)) -ErrorAction SilentlyContinue | Out-Null
                } catch {}
            }
            Write-Host "  ok  ceip_scheduled_tasks -> disabled" -ForegroundColor Green
        } else {
            Write-Host "  --  skipped HKLM/services (requires admin)" -ForegroundColor DarkYellow
        }
    } elseif ($IsMacOS) {
        defaults write com.apple.AdLib allowApplePersonalizedAdvertising -bool false 2>$null
        Write-Host "  ok  com.apple.AdLib personalized_ads = false" -ForegroundColor Green
        if ($isAdmin) {
            defaults write "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" AutoSubmit -bool false 2>$null
            Write-Host "  ok  CrashReporter AutoSubmit = false" -ForegroundColor Green
        } else {
            Write-Host "  --  skipped system CrashReporter policy (requires root)" -ForegroundColor DarkYellow
        }
    } else {
        if ($isAdmin) {
            if (Test-Path "/etc/default/apport") {
                $c = (Get-Content "/etc/default/apport" -Raw) -replace "enabled=1", "enabled=0"
                Set-Content -Path "/etc/default/apport" -Value $c -Force
                Write-Host "  ok  /etc/default/apport -> enabled=0" -ForegroundColor Green
            }
            foreach ($svc in @("apport", "whoopsie")) {
                systemctl stop $svc 2>$null
                systemctl disable $svc 2>$null
            }
            sysctl -w kernel.core_pattern="|/bin/false" 2>$null | Out-Null
            sysctl -w kernel.yama.ptrace_scope=2 2>$null | Out-Null
            sysctl -w kernel.kptr_restrict=2 2>$null | Out-Null
            sysctl -w kernel.dmesg_restrict=1 2>$null | Out-Null
            Write-Host "  ok  crash daemons, core_pattern, ptrace_scope & kptr_restrict hardened" -ForegroundColor Green
        } else {
            Write-Host "  --  skipped daemon/sysctl telemetry checks (requires root)" -ForegroundColor DarkYellow
        }
    }
}

Export-ModuleMember -Function Audit-Telemetry, Harden-Telemetry
