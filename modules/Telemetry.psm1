# Shared helpers Test-AdminPrivilege / Test-IsWindowsOS live in Common.psm1

function Get-TelemetryPosture {
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
        $hiberEnabled = $null
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power") {
            $pwrCtl = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -ErrorAction SilentlyContinue
            if ($pwrCtl) { $hiberEnabled = $pwrCtl.HibernateEnabled }
        }
        $hiberFileExists = $false
        try { $hiberFileExists = Test-Path "C:\hiberfil.sys" -ErrorAction SilentlyContinue } catch {}
        $hiberClean = ($hiberBoot -eq 0 -or $null -eq $hiberBoot) -and ($hiberEnabled -eq 0 -or -not $hiberFileExists)
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

function Protect-Telemetry {
    $isAdmin = Test-AdminPrivilege

    if (Test-IsWindowsOS) {
        # user-scope privacy (no admin needed) — each write is verified by readback
        $userRes = @()
        $userRes += Set-HardenedValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Label "advertising_id"
        $userRes += Set-HardenedValue -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Label "tailored_experiences"
        $userRes += Set-HardenedValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Label "bing_search"
        $userRes += Set-HardenedValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Label "cortana_consent"
        $userRes += Set-HardenedValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Value 1 -Label "no_recent_docs"
        $userRes += Set-HardenedValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Value 1 -Label "clear_recent_docs_on_exit"
        $userRes += Set-HardenedValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 -Label "track_docs"
        $userRes += Set-HardenedValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Label "track_progs"
        Write-HardenGroup -Label "user privacy & recent-docs tracking" -Results $userRes

        if ($isAdmin) {
            $telRes = @()
            $telRes += Set-HardenedValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Label "allow_telemetry"
            $telRes += Set-HardenedValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Label "no_feedback_notifications"
            $telRes += Set-HardenedValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Label "publish_user_activities"
            $telRes += Set-HardenedValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Label "upload_user_activities"
            $telRes += Set-HardenedValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Value 0 -Label "clipboard_history"
            $telRes += Set-HardenedValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0 -Label "cross_device_clipboard"
            $telRes += Set-HardenedValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1 -Label "disable_web_search"
            $telRes += Set-HardenedValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0 -Label "connected_search_web"
            Write-HardenGroup -Label "telemetry & activity policy (machine)" -Results $telRes

            $credRes = @()
            $credRes += Set-HardenedValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Label "wdigest_cleartext"
            $credRes += Set-HardenedValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Label "restrict_anonymous"
            $credRes += Set-HardenedValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Label "restrict_anonymous_sam"
            $credRes += Set-HardenedValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Label "lsass_runasppl"
            $credRes += Set-HardenedValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Label "ntlmv2_only"
            $credRes += Set-HardenedValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "0" -Type String -Label "cached_logons"
            $credRes += Set-HardenedValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Label "wer_disabled"
            $credRes += Set-HardenedValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Label "autorun_all_drives"
            Write-HardenGroup -Label "credential & memory shield" -Results $credRes

            $fwRes = @()
            $fwRes += Set-HardenedValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "DisableExternalDMAUnderLock" -Value 1 -Label "anti_pcileech_dma"
            $fwRes += Set-HardenedValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "DisableWpbtExecution" -Value 1 -Label "disable_uefi_wpbt"
            Write-HardenGroup -Label "firmware & DMA guard" -Results $fwRes

            $memRes = @()
            $memRes += Set-HardenedValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1 -Label "clear_pagefile_on_shutdown"
            $memRes += Set-HardenedValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -Label "disable_paging_executive"
            $memRes += Set-HardenedValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -Label "fast_startup_off"
            $memRes += Set-HardenedValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -Value 0 -Label "hibernate_off"
            $memRes += Set-HardenedValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 0 -Label "prefetch_off"
            $memRes += Set-HardenedValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Value 0 -Label "superfetch_off"
            Write-HardenGroup -Label "anti-forensic memory & paging" -Results $memRes

            # SysMain + telemetry services — state verified by Set-ServiceDisabled
            $svcRes = @()
            foreach ($s in @("SysMain", "DiagTrack", "dmwappushservice", "WerSvc")) {
                $svcRes += Set-ServiceDisabled -Name $s
            }
            try { powercfg /h off 2>$null | Out-Null } catch {}
            Write-HardenGroup -Label "telemetry & prefetch services" -Results $svcRes

            $tasks = @(
                "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
                "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
                "\Microsoft\Windows\Autochk\Proxy",
                "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
                "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
                "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
            )
            $taskOk = 0
            foreach ($t in $tasks) {
                try {
                    Disable-ScheduledTask -TaskPath ($t.Substring(0, $t.LastIndexOf("\") + 1)) -TaskName ($t.Substring($t.LastIndexOf("\") + 1)) -ErrorAction Stop | Out-Null
                    $taskOk++
                } catch {}
            }
            Write-Host ("  ok   ceip scheduled tasks ({0}/{1} disabled)" -f $taskOk, $tasks.Count) -ForegroundColor $(if ($taskOk -eq $tasks.Count) { 'Green' } else { 'Yellow' })
        } else {
            Write-Host "  --   skipped HKLM/services (requires admin)" -ForegroundColor DarkYellow
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

Export-ModuleMember -Function Get-TelemetryPosture, Protect-Telemetry
