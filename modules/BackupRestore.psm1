function Get-OSLabel {
    if ($PSVersionTable.Platform -eq 'Unix' -or $IsLinux -or $IsMacOS) {
        if ($IsMacOS) {
            $ver = (sw_vers -productVersion 2>$null)
            return "macOS $ver".Trim()
        }
        if (Test-Path "/etc/os-release") {
            $osRel = Get-Content "/etc/os-release" -ErrorAction SilentlyContinue
            $pretty = ($osRel | Where-Object { $_ -match '^PRETTY_NAME=' }) -replace '^PRETTY_NAME=', '' -replace '"', ''
            if ($pretty) { return $pretty }
        }
        $uname = (uname -sr 2>$null)
        if ($uname) { return $uname }
        return [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    }
    try {
        $cim = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        return "$($cim.Caption) ($($cim.Version))"
    } catch {
        return [System.Environment]::OSVersion.VersionString
    }
}

function Get-BackupDir {
    $parent = Split-Path -Parent $PSScriptRoot
    $backupDir = Join-Path $parent "backups"
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    }
    return (Resolve-Path $backupDir).Path
}

function Save-OpSecState {
    param (
        [string]$Description = "snapshot"
    )
    $backupDir = Get-BackupDir
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFile = Join-Path $backupDir "state_${Description}_${timestamp}.json"

    $isWin = ($env:OS -eq "Windows_NT") -and (-not $IsLinux) -and (-not $IsMacOS)

    $state = @{
        Timestamp       = $timestamp
        Platform        = if ($isWin) { "Windows" } elseif ($IsMacOS) { "macOS" } else { "Linux/Unix" }
        OSVersion       = Get-OSLabel
        RegistryEntries = @()
        Services        = @()
        Files           = @()
    }

    if ($isWin) {
        $keysToMonitor = @(
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "DoNotShowFeedbackNotifications" },
            @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableTailoredExperiencesWithDiagnosticData" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name = "EnableMulticast" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name = "DoHPolicy" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name = "DisableSmartNameResolution" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "DisableSmartNameResolution" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; Name = "EnableMDNS" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name = "RequireSecuritySignature" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "DisableIPSourceRouting" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "EnableICMPRedirect" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name = "UseLogonCredential" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymous" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymousSAM" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RunAsPPL" },
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LmCompatibilityLevel" },
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name = "CachedLogonsCount" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "Disabled" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "DisableWebSearch" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "ConnectedSearchUseWeb" },
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoDriveTypeAutoRun" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "AllowClipboardHistory" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "AllowCrossDeviceClipboard" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "PublishUserActivities" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "UploadUserActivities" },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name = "Enabled" },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Name = "BingSearchEnabled" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name = "DisableAIDataAnalysis" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name = "AllowRecall" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name = "TurnOffSavingSnapshots" },
            @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"; Name = "TurnOffWindowsCopilot" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"; Name = "TurnOffWindowsCopilot" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name = "DisableLocation" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name = "DisableWindowsLocationProvider" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name = "DisableLocationScripting" },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Location"; Name = "Enabled" },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy"; Name = "LocationNotificationsEnabled" },
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"; Name = "Value" },
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"; Name = "Value" },
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"; Name = "Value" },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"; Name = "Value" },
            @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"; Name = "Value" },
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"; Name = "fRandomizeIdentifiers" },
            @{ Path = "HKCU:\Software\Policies\BraveSoftware\Brave"; Name = "WebRtcIPHandlingPolicy" },
            @{ Path = "HKCU:\Software\Policies\BraveSoftware\Brave"; Name = "PasswordManagerEnabled" },
            @{ Path = "HKCU:\Software\Policies\BraveSoftware\Brave"; Name = "DnsOverHttpsMode" },
            @{ Path = "HKCU:\Software\Policies\BraveSoftware\Brave"; Name = "DnsOverHttpsTemplates" },
            @{ Path = "HKCU:\Software\Policies\Google\Chrome"; Name = "WebRtcIPHandlingPolicy" },
            @{ Path = "HKCU:\Software\Policies\Google\Chrome"; Name = "PasswordManagerEnabled" },
            @{ Path = "HKCU:\Software\Policies\Google\Chrome"; Name = "DnsOverHttpsMode" },
            @{ Path = "HKCU:\Software\Policies\Google\Chrome"; Name = "DnsOverHttpsTemplates" },
            @{ Path = "HKCU:\Software\Policies\Microsoft\Edge"; Name = "WebRtcIPHandlingPolicy" },
            @{ Path = "HKCU:\Software\Policies\Microsoft\Edge"; Name = "PasswordManagerEnabled" },
            @{ Path = "HKCU:\Software\Policies\Microsoft\Edge"; Name = "DnsOverHttpsMode" },
            @{ Path = "HKCU:\Software\Policies\Microsoft\Edge"; Name = "DnsOverHttpsTemplates" }
        )

        foreach ($entry in $keysToMonitor) {
            $val = $null
            if (Test-Path $entry.Path) {
                $item = Get-ItemProperty -Path $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue
                if ($null -ne $item) {
                    $val = $item.$($entry.Name)
                }
            }
            $state.RegistryEntries += @{
                Path   = $entry.Path
                Name   = $entry.Name
                Value  = $val
                Exists = ($null -ne $val)
            }
        }

        $servicesToMonitor = @("DiagTrack", "dmwappushservice", "WerSvc", "lfsvc")
        foreach ($svcName in $servicesToMonitor) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($null -ne $svc) {
                $state.Services += @{
                    Name      = $svc.Name
                    StartType = $svc.StartType.ToString()
                    Status    = $svc.Status.ToString()
                }
            }
        }
    } else {
        $confFiles = @("/etc/systemd/resolved.conf", "/etc/NetworkManager/conf.d/90-mac-randomization.conf")
        foreach ($cf in $confFiles) {
            if (Test-Path $cf) {
                $state.Files += @{
                    Path    = $cf
                    Content = (Get-Content -Path $cf -Raw -ErrorAction SilentlyContinue)
                }
            }
        }
    }

    $json = $state | ConvertTo-Json -Depth 5
    Set-Content -Path $backupFile -Value $json -Encoding UTF8 -Force
    return $backupFile
}

function Restore-OpSecState {
    param (
        [string]$BackupFilePath
    )

    if (-not $BackupFilePath) {
        $backupDir = Get-BackupDir
        $latest = Get-ChildItem -Path $backupDir -Filter "*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $latest) {
            Write-Host "  [!] no state snapshots found in $backupDir" -ForegroundColor Yellow
            return $false
        }
        $BackupFilePath = $latest.FullName
    }

    if (-not (Test-Path $BackupFilePath)) {
        Write-Host "  [!] snapshot file not found: $BackupFilePath" -ForegroundColor Red
        return $false
    }

    Write-Host "  restoring from: $BackupFilePath" -ForegroundColor Gray
    $jsonContent = Get-Content -Path $BackupFilePath -Raw -Encoding UTF8
    $state = $jsonContent | ConvertFrom-Json

    if ($state.RegistryEntries) {
        foreach ($entry in $state.RegistryEntries) {
            try {
                if ($entry.Exists) {
                    if (-not (Test-Path $entry.Path)) {
                        New-Item -Path $entry.Path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $entry.Path -Name $entry.Name -Value $entry.Value -Force -ErrorAction Stop
                    Write-Host "  restored $($entry.Path)\$($entry.Name) = $($entry.Value)" -ForegroundColor Green
                } else {
                    if (Test-Path $entry.Path) {
                        Remove-ItemProperty -Path $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue
                        Write-Host "  removed  $($entry.Path)\$($entry.Name)" -ForegroundColor DarkGray
                    }
                }
            } catch {
                Write-Host "  skipped  $($entry.Path)\$($entry.Name) ($($_.Exception.Message))" -ForegroundColor Yellow
            }
        }
    }

    if ($state.Services) {
        foreach ($svc in $state.Services) {
            try {
                Set-Service -Name $svc.Name -StartupType $svc.StartType -ErrorAction Stop
                if ($svc.Status -eq "Running") {
                    Start-Service -Name $svc.Name -ErrorAction SilentlyContinue
                }
                Write-Host "  service  $($svc.Name) -> $($svc.StartType)" -ForegroundColor Green
            } catch {
                Write-Host "  skipped  service $($svc.Name) ($($_.Exception.Message))" -ForegroundColor Yellow
            }
        }
    }

    if ($state.Files) {
        foreach ($f in $state.Files) {
            try {
                Set-Content -Path $f.Path -Value $f.Content -Encoding UTF8 -Force -ErrorAction Stop
                Write-Host "  restored $($f.Path)" -ForegroundColor Green
            } catch {
                Write-Host "  skipped  $($f.Path) ($($_.Exception.Message))" -ForegroundColor Yellow
            }
        }
    }

    Write-Host "  state restore complete." -ForegroundColor Green
    return $true
}

Export-ModuleMember -Function Get-OSLabel, Get-BackupDir, Save-OpSecState, Restore-OpSecState
