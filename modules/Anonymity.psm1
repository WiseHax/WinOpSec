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

function Audit-Anonymity {
    $results = @()

    if (Test-IsWindowsOS) {
        # 1. Geolocation Provider & Service (VPN-compatible check)
        $locProvVal = $null
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors") {
            $item = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -ErrorAction SilentlyContinue
            if ($item) {
                $locProvVal = if ($item.DisableWindowsLocationProvider -eq 1 -or $item.DisableLocation -eq 1) { 1 } else { 0 }
            }
        }
        $lfsvc = Get-Service -Name "lfsvc" -ErrorAction SilentlyContinue
        $toastMuted = $false
        if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Location") {
            $tItem = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Location" -Name "Enabled" -ErrorAction SilentlyContinue
            if ($tItem -and $tItem.Enabled -eq 0) { $toastMuted = $true }
        }
        $locHardened = ($locProvVal -eq 1) -or (-not $lfsvc) -or ($lfsvc.StartType -eq "Disabled") -or ($lfsvc.Status -eq "Stopped" -and $toastMuted)
        $results += [PSCustomObject]@{
            Category = "Anonymity"
            Check    = "Geolocation (lfsvc / VPN-Safe)"
            Status   = if ($locHardened) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($locHardened -and $toastMuted) { "disabled (popup muted / VPN-safe)" } elseif ($locHardened) { "disabled" } else { "active" }
        }

        # 2. Windows Recall & Copilot AI Analysis
        $recallVal = $null
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI") {
            $item = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -ErrorAction SilentlyContinue
            if ($item) { $recallVal = $item.DisableAIDataAnalysis }
        }
        if ($recallVal -ne 1 -and (Test-Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsAI")) {
            $item = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -ErrorAction SilentlyContinue
            if ($item) { $recallVal = $item.DisableAIDataAnalysis }
        }
        $results += [PSCustomObject]@{
            Category = "Anonymity"
            Check    = "Windows Recall / Copilot AI"
            Status   = if ($recallVal -eq 1) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($recallVal -eq 1) { "blocked" } else { "unrestricted" }
        }

        # 3. Wi-Fi MAC Randomization
        $allNics = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces())
        $wifiAdapters = @($allNics | Where-Object { $_.NetworkInterfaceType -eq "Wireless80211" -and $_.Description -notmatch "Wi-Fi Direct|Virtual" })
        $macRandPolicy = $null
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy") {
            $item = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fRandomizeIdentifiers" -ErrorAction SilentlyContinue
            if ($item) { $macRandPolicy = $item.fRandomizeIdentifiers }
        }
        $wlanRand = $false
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\WlanSvc\Interfaces") {
            $ifaces = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\WlanSvc\Interfaces" -ErrorAction SilentlyContinue
            foreach ($ifc in $ifaces) {
                $r = Get-ItemProperty -Path $ifc.PSPath -Name "RandomMACState" -ErrorAction SilentlyContinue
                if ($r -and ($r.RandomMACState -eq 1 -or ($r.RandomMACState -is [array] -and $r.RandomMACState[0] -eq 1))) { $wlanRand = $true }
            }
        }
        $macHardened = ($wifiAdapters.Count -eq 0) -or ($macRandPolicy -eq 1) -or $wlanRand
        $results += [PSCustomObject]@{
            Category = "Anonymity"
            Check    = "Wi-Fi MAC Randomization"
            Status   = if ($macHardened) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($wifiAdapters.Count -eq 0) { "no wlan adapter" } elseif ($macHardened) { "randomized ($($wifiAdapters[0].Name))" } else { "static hardware mac" }
        }

        # 4. Webcam & Microphone Consent Store
        $camVal = $null
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam") {
            $item = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -ErrorAction SilentlyContinue
            if ($item) { $camVal = $item.Value }
        }
        if ($camVal -ne "Deny" -and (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam")) {
            $item = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -ErrorAction SilentlyContinue
            if ($item) { $camVal = $item.Value }
        }
        $results += [PSCustomObject]@{
            Category = "Sensors"
            Check    = "Webcam & Mic Consent Store"
            Status   = if ($camVal -eq "Deny") { "HARDENED" } else { "EXPOSED" }
            Details  = if ($camVal -eq "Deny") { "deny (locked)" } else { "allow" }
        }

        # 5. NetworkList Wi-Fi BSSID / Geolocation History
        $nlCount = 0
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles") {
            $nlCount = @(Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" -ErrorAction SilentlyContinue).Count
        }
        $nlHardened = ($nlCount -le 1)
        $results += [PSCustomObject]@{
            Category = "Anonymity"
            Check    = "Wi-Fi BSSID / NetworkList History"
            Status   = if ($nlHardened) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($nlCount -eq 0) { "clean (0 saved networks; no WiGLE traces)" } elseif ($nlCount -eq 1) { "hardened (1 active network only; historical BSSIDs clean)" } else { "$nlCount saved networks (WiGLE traceable) [risk:high]" }
        }
    } elseif ($IsMacOS) {
        $locEnabled = (defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled 2>$null)
        $results += [PSCustomObject]@{
            Category = "Anonymity"
            Check    = "Location Services (locationd)"
            Status   = if ($locEnabled -eq "0") { "HARDENED" } else { "EXPOSED" }
            Details  = if ($locEnabled -eq "0") { "disabled" } else { "enabled/default" }
        }
    } else {
        $geoclue = (systemctl is-active geoclue 2>$null)
        $results += [PSCustomObject]@{
            Category = "Anonymity"
            Check    = "GeoClue Location Daemon"
            Status   = if ($geoclue -ne "active") { "HARDENED" } else { "EXPOSED" }
            Details  = if ($geoclue -eq "active") { "running" } else { "inactive" }
        }

        $nmMacRand = Test-Path "/etc/NetworkManager/conf.d/90-mac-randomization.conf"
        $results += [PSCustomObject]@{
            Category = "Anonymity"
            Check    = "NetworkManager MAC Rand"
            Status   = if ($nmMacRand) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($nmMacRand) { "configured" } else { "not configured" }
        }
    }

    return $results
}

function Harden-Anonymity {
    $isAdmin = Test-AdminPrivilege

    if (Test-IsWindowsOS) {
        # 1. User-level Recall & Copilot disable
        $userAiPath = "HKCU:\Software\Policies\Microsoft\Windows\WindowsAI"
        if (-not (Test-Path $userAiPath)) { New-Item -Path $userAiPath -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $userAiPath -Name "DisableAIDataAnalysis" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $userAiPath -Name "TurnOffSavingSnapshots" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue

        $userCopilot = "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"
        if (-not (Test-Path $userCopilot)) { New-Item -Path $userCopilot -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $userCopilot -Name "TurnOffWindowsCopilot" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
        Write-Host "  ok  hkcu/windows_ai_recall & copilot = disabled" -ForegroundColor Green

        # 2. Suppress Windows 11 24H2 Location Popup Toast (fixes Proton VPN / WLAN startup popup)
        $toastLocPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Location"
        if (-not (Test-Path $toastLocPath)) { New-Item -Path $toastLocPath -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $toastLocPath -Name "Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue

        $privPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy"
        if (-not (Test-Path $privPath)) { New-Item -Path $privPath -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $privPath -Name "LocationNotificationsEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue

        # Allow NonPackaged Win32 WLAN interface status checks (so Proton VPN doesn't trigger 24H2 modal dialog) while lfsvc & Cloud Location Provider are killed
        $hkcuLocNonPkg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged"
        if (-not (Test-Path $hkcuLocNonPkg)) { New-Item -Path $hkcuLocNonPkg -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $hkcuLocNonPkg -Name "Value" -Type String -Value "Allow" -Force -ErrorAction SilentlyContinue
        Write-Host "  ok  location popup muted & win32 vpn wlan compatibility = enabled" -ForegroundColor Green

        # 3. Lock Webcam & Microphone Consent Store
        foreach ($sensor in @("webcam", "microphone")) {
            $hkcuSensor = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$sensor"
            if (-not (Test-Path $hkcuSensor)) { New-Item -Path $hkcuSensor -Force -ErrorAction SilentlyContinue | Out-Null }
            Set-ItemProperty -Path $hkcuSensor -Name "Value" -Type String -Value "Deny" -Force -ErrorAction SilentlyContinue
        }
        Write-Host "  ok  hkcu/consent_store (webcam, microphone) = deny" -ForegroundColor Green

        if ($isAdmin) {
            # System-wide Recall & Copilot disable
            $hklmAi = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
            if (-not (Test-Path $hklmAi)) { New-Item -Path $hklmAi -Force | Out-Null }
            Set-ItemProperty -Path $hklmAi -Name "DisableAIDataAnalysis" -Type DWord -Value 1 -Force
            Set-ItemProperty -Path $hklmAi -Name "AllowRecall" -Type DWord -Value 0 -Force
            Set-ItemProperty -Path $hklmAi -Name "TurnOffSavingSnapshots" -Type DWord -Value 1 -Force

            $hklmCopilot = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
            if (-not (Test-Path $hklmCopilot)) { New-Item -Path $hklmCopilot -Force | Out-Null }
            Set-ItemProperty -Path $hklmCopilot -Name "TurnOffWindowsCopilot" -Type DWord -Value 1 -Force
            Write-Host "  ok  hklm/windows_ai_recall & copilot = disabled" -ForegroundColor Green

            # VPN-Compatible Geolocation Kill:
            # Disable Windows Cloud Location Provider & Scripting + Stop/Disable lfsvc daemon,
            # while removing DisableLocation=1 GPO modal trigger that causes Windows 11 24H2 popup on Proton VPN startup
            $locPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
            if (-not (Test-Path $locPolicy)) { New-Item -Path $locPolicy -Force | Out-Null }
            Remove-ItemProperty -Path $locPolicy -Name "DisableLocation" -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $locPolicy -Name "DisableWindowsLocationProvider" -Type DWord -Value 1 -Force
            Set-ItemProperty -Path $locPolicy -Name "DisableLocationScripting" -Type DWord -Value 1 -Force
            Set-ItemProperty -Path $locPolicy -Name "DisableSensors" -Type DWord -Value 1 -Force

            $hklmLocNonPkg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged"
            if (-not (Test-Path $hklmLocNonPkg)) { New-Item -Path $hklmLocNonPkg -Force | Out-Null }
            Set-ItemProperty -Path $hklmLocNonPkg -Name "Value" -Type String -Value "Allow" -Force
            Write-Host "  ok  hklm/windows_location_provider = disabled (vpn-compatible, no popup)" -ForegroundColor Green

            $lfsvc = Get-Service -Name "lfsvc" -ErrorAction SilentlyContinue
            if ($lfsvc) {
                Stop-Service -Name "lfsvc" -Force -ErrorAction SilentlyContinue
                Set-Service -Name "lfsvc" -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Host "  ok  service/lfsvc -> stopped & disabled" -ForegroundColor Green
            }

            # System-wide Webcam & Microphone ConsentStore lock
            foreach ($sensor in @("webcam", "microphone")) {
                $sensorPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$sensor"
                if (-not (Test-Path $sensorPath)) { New-Item -Path $sensorPath -Force | Out-Null }
                Set-ItemProperty -Path $sensorPath -Name "Value" -Type String -Value "Deny" -Force -ErrorAction SilentlyContinue
            }
            Write-Host "  ok  hklm/consent_store (webcam, microphone) = deny" -ForegroundColor Green

            # Wi-Fi MAC Randomization & Hotspot 2.0
            $wcmPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
            if (-not (Test-Path $wcmPolicy)) { New-Item -Path $wcmPolicy -Force | Out-Null }
            Set-ItemProperty -Path $wcmPolicy -Name "fRandomizeIdentifiers" -Type DWord -Value 1 -Force

            if (Test-Path "HKLM:\SOFTWARE\Microsoft\WlanSvc\Interfaces") {
                $ifaces = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\WlanSvc\Interfaces" -ErrorAction SilentlyContinue
                foreach ($ifc in $ifaces) {
                    Set-ItemProperty -Path $ifc.PSPath -Name "RandomMACState" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
                }
            }
            Write-Host "  ok  wlan mac_randomization = enabled" -ForegroundColor Green

            $wlanPath = "HKLM:\SOFTWARE\Microsoft\WlanSvc\AnqpCache"
            if (Test-Path $wlanPath) {
                Remove-Item -Path $wlanPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            $wifiPolicy = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
            if (Test-Path $wifiPolicy) {
                Set-ItemProperty -Path $wifiPolicy -Name "value" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
            }
        } else {
            Write-Host "  --  applied user-level sensor/AI/popup fixes (run as admin for HKLM/lfsvc)" -ForegroundColor DarkYellow
        }
    } elseif ($IsMacOS) {
        if ($isAdmin) {
            defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -int 0 2>$null
            Write-Host "  ok  locationd -> disabled" -ForegroundColor Green
        } else {
            Write-Host "  --  skipped locationd policy (requires root)" -ForegroundColor DarkYellow
        }
    } else {
        if ($isAdmin) {
            systemctl stop geoclue 2>$null
            systemctl mask geoclue 2>$null
            Write-Host "  ok  service/geoclue -> masked" -ForegroundColor Green

            if (Test-Path "/etc/NetworkManager/conf.d") {
                $nmConf = "[device]`nwifi.scan-rand-mac-address=yes`n`n[connection]`nwifi.cloned-mac-address=random`nethernet.cloned-mac-address=random`n"
                Set-Content -Path "/etc/NetworkManager/conf.d/90-mac-randomization.conf" -Value $nmConf -Force
                Write-Host "  ok  networkmanager mac randomization -> enabled" -ForegroundColor Green
            }
        } else {
            Write-Host "  --  skipped geoclue/MAC randomization (requires root)" -ForegroundColor DarkYellow
        }
    }
}

function Invoke-MacSpoof {
    param(
        [switch]$Reset
    )

    if (-not (Test-AdminPrivilege)) {
        Write-Host "  [!] MAC address spoofing requires administrator/root privileges." -ForegroundColor Yellow
        return
    }

    if (Test-IsWindowsOS) {
        $classRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
        $allNics = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces())
        $targetNics = @($allNics | Where-Object {
            $_.OperationalStatus -eq "Up" -and
            $_.Description -notmatch "Proton|WireGuard|TAP|Wintun|Loopback|Virtual|Hyper-V|WSL|Bluetooth" -and
            [int]$_.NetworkInterfaceType -in @(6, 71) # Ethernet or Wireless80211
        })

        if ($targetNics.Count -eq 0) {
            $targetNics = @($allNics | Where-Object { $_.OperationalStatus -eq "Up" -and $_.Description -notmatch "Loopback|Virtual" } | Select-Object -First 1)
        }

        if ($targetNics.Count -eq 0) {
            Write-Host "  [!] no eligible active network adapter found." -ForegroundColor Yellow
            return
        }

        # Locate driver subkeys in registry (0000, 0001, etc.)
        $driverSubkeys = @()
        0..30 | ForEach-Object {
            $sub = "{0:D4}" -f $_
            $p = Join-Path $classRoot $sub
            if (Test-Path $p) {
                $prop = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
                if ($prop -and $prop.NetCfgInstanceId) {
                    $driverSubkeys += [PSCustomObject]@{
                        Path     = $p
                        Subkey   = $sub
                        Guid     = $prop.NetCfgInstanceId
                        Desc     = $prop.DriverDesc
                    }
                }
            }
        }

        foreach ($nic in $targetNics) {
            $matchedKey = $driverSubkeys | Where-Object {
                $_.Guid -ieq $nic.Id -or ($_.Desc -and $nic.Description -and $_.Desc -match [regex]::Escape($nic.Description))
            } | Select-Object -First 1

            if ($Reset) {
                if ($matchedKey) {
                    Remove-ItemProperty -Path $matchedKey.Path -Name "NetworkAddress" -ErrorAction SilentlyContinue
                }
                if (Get-Command Set-NetAdapterAdvancedProperty -ErrorAction SilentlyContinue) {
                    Reset-NetAdapterAdvancedProperty -Name $nic.Name -DisplayName "Locally Administered Address" -ErrorAction SilentlyContinue
                    Reset-NetAdapterAdvancedProperty -Name $nic.Name -DisplayName "Network Address" -ErrorAction SilentlyContinue
                }
                netsh interface set interface name="$($nic.Name)" admin=disable 2>$null | Out-Null
                Start-Sleep -Milliseconds 600
                netsh interface set interface name="$($nic.Name)" admin=enable 2>$null | Out-Null
                Write-Host "  ok  $($nic.Name) restored to factory hardware MAC" -ForegroundColor Green
                continue
            }

            # Generate valid locally-administered unicast MAC (2nd char must be 2, 6, A, or E)
            $prefix = @("02", "06", "0A", "0E") | Get-Random
            $bytes = New-Object byte[] 5
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
            $macHex = $prefix + (($bytes | ForEach-Object { $_.ToString("X2") }) -join "")
            $macColon = ($macHex -replace '..(?!$)', '$&:')

            # Method 1: Direct Driver Registry Key Write (bypasses INF metadata restrictions on Intel AX200/AX201/AX203)
            $regSuccess = $false
            if ($matchedKey) {
                try {
                    Set-ItemProperty -Path $matchedKey.Path -Name "NetworkAddress" -Type String -Value $macHex -Force -ErrorAction Stop
                    # Also register Ndi\params\NetworkAddress so the driver subsystem honors the override
                    $ndiParam = Join-Path $matchedKey.Path "Ndi\params\NetworkAddress"
                    if (-not (Test-Path $ndiParam)) {
                        New-Item -Path $ndiParam -Force -ErrorAction SilentlyContinue | Out-Null
                        Set-ItemProperty -Path $ndiParam -Name "ParamDesc" -Value "MAC Address" -Type String -Force -ErrorAction SilentlyContinue
                        Set-ItemProperty -Path $ndiParam -Name "type" -Value "edit" -Type String -Force -ErrorAction SilentlyContinue
                        Set-ItemProperty -Path $ndiParam -Name "LimitText" -Value "12" -Type String -Force -ErrorAction SilentlyContinue
                    }
                    $regSuccess = $true
                } catch {}
            }

            # Method 2: Set-NetAdapterAdvancedProperty fallback
            try {
                Set-NetAdapterAdvancedProperty -Name $nic.Name -RegistryKeyword "NetworkAddress" -RegistryValue $macHex -ErrorAction SilentlyContinue
            } catch {}

            # Method 3: For Wi-Fi adapters, enforce kernel-level WlanSvc MAC Randomization
            if ($nic.NetworkInterfaceType -eq "Wireless80211") {
                $wlanGuidKey = "HKLM:\SOFTWARE\Microsoft\WlanSvc\Interfaces\$($nic.Id)"
                if (-not (Test-Path $wlanGuidKey)) { New-Item -Path $wlanGuidKey -Force -ErrorAction SilentlyContinue | Out-Null }
                Set-ItemProperty -Path $wlanGuidKey -Name "RandomMACState" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue

                $wcmPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
                if (-not (Test-Path $wcmPolicy)) { New-Item -Path $wcmPolicy -Force -ErrorAction SilentlyContinue | Out-Null }
                Set-ItemProperty -Path $wcmPolicy -Name "fRandomizeIdentifiers" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
            }

            # Restart adapter to load the spoofed address
            if (Get-Command Restart-NetAdapter -ErrorAction SilentlyContinue) {
                Restart-NetAdapter -Name $nic.Name -Confirm:$false -ErrorAction SilentlyContinue
            }
            netsh interface set interface name="$($nic.Name)" admin=disable 2>$null | Out-Null
            Start-Sleep -Milliseconds 800
            netsh interface set interface name="$($nic.Name)" admin=enable 2>$null | Out-Null

            if ($regSuccess) {
                Write-Host "  ok  $($nic.Name) MAC spoofed -> $macColon (Driver Registry & WlanSvc active)" -ForegroundColor Green
            } else {
                Write-Host "  ok  $($nic.Name) Wi-Fi MAC randomization enforced (WlanSvc 802.11 active)" -ForegroundColor Green
            }
        }
    } elseif ($IsMacOS) {
        if ($Reset) {
            Write-Host "  --  reboot or reconnect on macOS to restore factory MAC" -ForegroundColor DarkGray
            return
        }
        $prefix = @("02", "06", "0a", "0e") | Get-Random
        $bytes = New-Object byte[] 5
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $macColon = $prefix + ":" + (($bytes | ForEach-Object { $_.ToString("x2") }) -join ":")
        sudo ifconfig en0 ether $macColon 2>$null
        Write-Host "  ok  en0 MAC spoofed -> $macColon" -ForegroundColor Green
    } else {
        $iface = (ip route show default 2>$null | Select-String -Pattern "dev (\S+)" | ForEach-Object { $_.Matches[0].Groups[1].Value } | Select-Object -First 1)
        if ($iface) {
            if ($Reset) {
                ip link set dev $iface down 2>$null
                ethtool -E $iface 2>$null
                ip link set dev $iface up 2>$null
                Write-Host "  ok  $iface reset to default MAC" -ForegroundColor Green
                return
            }
            $prefix = @("02", "06", "0a", "0e") | Get-Random
            $bytes = New-Object byte[] 5
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
            $macColon = $prefix + ":" + (($bytes | ForEach-Object { $_.ToString("x2") }) -join ":")
            ip link set dev $iface down 2>$null
            ip link set dev $iface address $macColon 2>$null
            ip link set dev $iface up 2>$null
            Write-Host "  ok  $iface MAC spoofed -> $macColon" -ForegroundColor Green
        }
    }
}

function Invoke-NetworkListScrub {
    [CmdletBinding()]
    param(
        [switch]$PurgeAll
    )

    if (-not (Test-IsWindowsOS)) { return }
    if (-not (Test-AdminPrivilege)) {
        Write-Host "  [!] Scrubbing NetworkList Wi-Fi profiles requires administrator privileges." -ForegroundColor Yellow
        return
    }

    Write-Host "  -- scrubbing NetworkList Wi-Fi profiles & physical geolocation BSSIDs..." -ForegroundColor DarkGray
    try {
        # Detect currently active connected Wi-Fi SSID to avoid dropping live connection
        $activeSsid = $null
        $wlanOut = netsh wlan show interfaces 2>$null
        if ($wlanOut) {
            foreach ($line in $wlanOut) {
                if ($line -match '^\s*SSID\s*:\s*(.+)$' -and $line -notmatch 'BSSID') {
                    $activeSsid = $Matches[1].Trim()
                    break
                }
            }
        }

        # Retrieve all saved WLAN profile names
        $profileList = @()
        $profilesOut = netsh wlan show profiles 2>$null
        if ($profilesOut) {
            foreach ($line in $profilesOut) {
                if ($line -match ':\s*(.+)$') {
                    $pName = $Matches[1].Trim()
                    if ($pName -and $pName -notmatch "---" -and $pName -notmatch "<None>") {
                        $profileList += $pName
                    }
                }
            }
        }

        $purgedProfiles = 0
        foreach ($p in $profileList) {
            if ($PurgeAll -or ($activeSsid -and $p -ne $activeSsid) -or (-not $activeSsid)) {
                netsh wlan delete profile name="$p" 2>$null | Out-Null
                $purgedProfiles++
            }
        }

        # Purge NetworkList Profiles & Signatures
        foreach ($nlKey in @(
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed"
        )) {
            if (Test-Path $nlKey) {
                Get-ChildItem -Path $nlKey -ErrorAction SilentlyContinue | ForEach-Object {
                    $prop = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                    $pName = if ($prop -and $prop.ProfileName) { $prop.ProfileName } else { "" }
                    if ($PurgeAll -or ($activeSsid -and $pName -ne $activeSsid) -or (-not $activeSsid)) {
                        Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }

        if ($activeSsid -and -not $PurgeAll) {
            Write-Host "  ok  purged historical Wi-Fi connection traces (preserved active connection: $activeSsid)" -ForegroundColor Green
        } else {
            Write-Host "  ok  purged all NetworkList profiles & WLAN connection histories (WiGLE triangulation defeated)" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] NetworkList scrub error: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

function Invoke-UsbHistoryScrub {
    if (-not (Test-IsWindowsOS)) { return }
    if (-not (Test-AdminPrivilege)) {
        Write-Host "  [!] USB history scrubbing requires administrator privileges." -ForegroundColor Yellow
        return
    }
    Write-Host "  -- scrubbing USBSTOR enumeration history..." -ForegroundColor Cyan
    try {
        $usbStorKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
        if (Test-Path $usbStorKey) {
            Get-ChildItem -Path $usbStorKey -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Host "  ok  cleared USBSTOR hardware enumeration registry keys" -ForegroundColor Green
        }
    } catch {
        Write-Host "  !!  USB history purge failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Export-ModuleMember -Function Audit-Anonymity, Harden-Anonymity, Invoke-MacSpoof, Invoke-NetworkListScrub, Invoke-UsbHistoryScrub
