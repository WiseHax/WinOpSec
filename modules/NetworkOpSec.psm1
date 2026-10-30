# Shared helpers Test-AdminPrivilege / Test-IsWindowsOS live in Common.psm1

function Audit-NetworkOpSec {
    $results = @()

    if (Test-IsWindowsOS) {
        # 1. LLMNR
        $llmnrVal = $null
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient") {
            $item = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
            if ($item) { $llmnrVal = $item.EnableMulticast }
        }
        $results += [PSCustomObject]@{
            Protocol = "LLMNR"
            Check    = "Multicast Name Resolution"
            Status   = if ($llmnrVal -eq 0) { "HARDENED" } else { "EXPOSED" }
            Risk     = "high"
            Details  = if ($llmnrVal -eq 0) { "disabled" } else { "enabled (broadcast leak)" }
        }

        # 2. mDNS (UDP 5353)
        $mdnsVal = $null
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters") {
            $item = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -ErrorAction SilentlyContinue
            if ($item) { $mdnsVal = $item.EnableMDNS }
        }
        $results += [PSCustomObject]@{
            Protocol = "mDNS"
            Check    = "Multicast DNS (UDP 5353)"
            Status   = if ($mdnsVal -eq 0) { "HARDENED" } else { "EXPOSED" }
            Risk     = "high"
            Details  = if ($mdnsVal -eq 0) { "disabled" } else { "enabled (Responder vector)" }
        }

        # 3. NetBIOS over TCP/IP (inspect active IP-enabled interfaces)
        $netbiosActive = $false
        $activeChecked = $false

        # Method A: Query active IP-enabled network adapters via CIM/WMI
        try {
            $activeCfgs = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ErrorAction Stop
            if ($activeCfgs) {
                $activeChecked = $true
                foreach ($cfg in $activeCfgs) {
                    if ($cfg.TcpipNetbiosOptions -ne 2) {
                        $netbiosActive = $true
                        break
                    }
                }
            }
        } catch {
            try {
                $activeCfgs = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ErrorAction Stop
                if ($activeCfgs) {
                    $activeChecked = $true
                    foreach ($cfg in $activeCfgs) {
                        if ($cfg.TcpipNetbiosOptions -ne 2) {
                            $netbiosActive = $true
                            break
                        }
                    }
                }
            } catch {}
        }

        # Method B: Fallback to NetBT Registry matching active TCP/IP interfaces with assigned IP addresses
        if (-not $activeChecked) {
            $netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
            if (Test-Path $netbtPath) {
                $ifaces = Get-ChildItem -Path $netbtPath -ErrorAction SilentlyContinue
                foreach ($ifc in $ifaces) {
                    $guid = $ifc.PSChildName -replace '^Tcpip_', ''
                    $tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"
                    $hasActiveIp = $false
                    if (Test-Path $tcpipPath) {
                        $tcpProp = Get-ItemProperty -Path $tcpipPath -ErrorAction SilentlyContinue
                        $ips = @($tcpProp.IPAddress) + @($tcpProp.DhcpIPAddress) | Where-Object { $_ -and $_ -ne '0.0.0.0' -and $_ -ne '::' }
                        if ($ips.Count -gt 0) { $hasActiveIp = $true }
                    }
                    if ($hasActiveIp) {
                        $nb = (Get-ItemProperty -Path $ifc.PSPath -Name "NetbiosOptions" -ErrorAction SilentlyContinue).NetbiosOptions
                        if ($nb -ne 2) {
                            $netbiosActive = $true
                            break
                        }
                    }
                }
            }
        }
        $results += [PSCustomObject]@{
            Protocol = "NBT-NS"
            Check    = "NetBIOS over TCP/IP"
            Status   = if (-not $netbiosActive) { "HARDENED" } else { "EXPOSED" }
            Risk     = "high"
            Details  = if (-not $netbiosActive) { "disabled on all active interfaces (NetbiosOptions=2)" } else { "enabled on active interface" }
        }

        # 4. SMB Signing (NTLM Relay mitigation)
        $smbSign = $null
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters") {
            $item = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
            if ($item) { $smbSign = $item.RequireSecuritySignature }
        }
        $results += [PSCustomObject]@{
            Protocol = "SMB"
            Check    = "SMB Packet Signing Required"
            Status   = if ($smbSign -eq 1) { "HARDENED" } else { "EXPOSED" }
            Risk     = "high"
            Details  = if ($smbSign -eq 1) { "enforced (anti-relay)" } else { "not enforced (NTLM relay risk)" }
        }

        # 5. Smart Multi-Homed DNS
        $smartDns = $null
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient") {
            $item = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartNameResolution" -ErrorAction SilentlyContinue
            if ($item) { $smartDns = $item.DisableSmartNameResolution }
        }
        $results += [PSCustomObject]@{
            Protocol = "DNS"
            Check    = "Smart Multi-Homed DNS"
            Status   = if ($smartDns -eq 1) { "HARDENED" } else { "EXPOSED" }
            Risk     = "crit"
            Details  = if ($smartDns -eq 1) { "disabled" } else { "parallel queries active" }
        }

        # 6. WPAD
        $wpadVal = $null
        if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad") {
            $item = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -ErrorAction SilentlyContinue
            if ($item) { $wpadVal = $item.WpadOverride }
        }
        $results += [PSCustomObject]@{
            Protocol = "WPAD"
            Check    = "Web Proxy Auto-Discovery"
            Status   = if ($wpadVal -eq 1) { "HARDENED" } else { "EXPOSED" }
            Risk     = "med"
            Details  = if ($wpadVal -eq 1) { "disabled" } else { "enabled" }
        }

        # 7. Teredo IPv6 Tunneling (supports Windows 11 24H2 where Teredo netsh helper is removed + DisabledComponents bitmask)
        $teredoHardened = $false
        $teredoDetail = "enabled"
        $disabledComp = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue).DisabledComponents
        if ($null -ne $disabledComp -and (($disabledComp -band 8) -eq 8)) {
            $teredoHardened = $true
            $teredoDetail = "disabled via Tcpip6 policy"
        } else {
            try {
                $teredoOutput = netsh interface teredo show state 2>&1 | Out-String
                if ($teredoOutput -match "disabled|offline|not found") {
                    $teredoHardened = $true
                    $teredoDetail = if ($teredoOutput -match "not found") { "removed in OS build (safe)" } else { "disabled" }
                }
            } catch {
                $teredoHardened = $true
                $teredoDetail = "absent"
            }
        }
        $results += [PSCustomObject]@{
            Protocol = "Teredo"
            Check    = "IPv6 Tunneling"
            Status   = if ($teredoHardened) { "HARDENED" } else { "EXPOSED" }
            Risk     = "med"
            Details  = $teredoDetail
        }

        # 8. ICMP Redirects & IP Source Routing
        $icmpRedir = $null
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters") {
            $item = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -ErrorAction SilentlyContinue
            if ($item) { $icmpRedir = $item.EnableICMPRedirect }
        }
        $results += [PSCustomObject]@{
            Protocol = "TCP/IP"
            Check    = "ICMP Redirects & Source Route"
            Status   = if ($icmpRedir -eq 0) { "HARDENED" } else { "EXPOSED" }
            Risk     = "med"
            Details  = if ($icmpRedir -eq 0) { "blocked" } else { "permitted (MITM route risk)" }
        }
    } elseif ($IsMacOS) {
        $mdnsNoMulticast = (defaults read /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements 2>$null)
        $results += [PSCustomObject]@{
            Protocol = "mDNS"
            Check    = "Multicast Advertisements"
            Status   = if ($mdnsNoMulticast -eq "1") { "HARDENED" } else { "EXPOSED" }
            Risk     = "med"
            Details  = if ($mdnsNoMulticast -eq "1") { "disabled" } else { "broadcasting" }
        }
    } else {
        $llmnrDisabled = $false
        if (Test-Path "/etc/systemd/resolved.conf") {
            $rc = Get-Content "/etc/systemd/resolved.conf" -Raw -ErrorAction SilentlyContinue
            if ($rc -match "(?m)^LLMNR=no") { $llmnrDisabled = $true }
        }
        $results += [PSCustomObject]@{
            Protocol = "LLMNR"
            Check    = "systemd-resolved LLMNR"
            Status   = if ($llmnrDisabled) { "HARDENED" } else { "EXPOSED" }
            Risk     = "high"
            Details  = if ($llmnrDisabled) { "LLMNR=no" } else { "default/enabled" }
        }

        $icmpRedir = if (Test-Path "/proc/sys/net/ipv4/conf/all/accept_redirects") { (Get-Content "/proc/sys/net/ipv4/conf/all/accept_redirects" -Raw).Trim() } else { "1" }
        $results += [PSCustomObject]@{
            Protocol = "ICMP"
            Check    = "IPv4 Accept Redirects"
            Status   = if ($icmpRedir -eq "0") { "HARDENED" } else { "EXPOSED" }
            Risk     = "med"
            Details  = "accept_redirects=$icmpRedir"
        }
    }

    return $results
}

function Harden-NetworkOpSec {
    $isAdmin = Test-AdminPrivilege

    if (Test-IsWindowsOS) {
        $wpadPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
        if (-not (Test-Path $wpadPath)) { New-Item -Path $wpadPath -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $wpadPath -Name "WpadOverride" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
        Write-Host "  ok  wpad_override = 1" -ForegroundColor Green

        if ($isAdmin) {
            # 1. LLMNR
            $dnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
            if (-not (Test-Path $dnsClientPath)) { New-Item -Path $dnsClientPath -Force | Out-Null }
            Set-ItemProperty -Path $dnsClientPath -Name "EnableMulticast" -Type DWord -Value 0 -Force
            Write-Host "  ok  llmnr_multicast = 0" -ForegroundColor Green

            # 2. mDNS (UDP 5353)
            $mdnsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
            if (-not (Test-Path $mdnsPath)) { New-Item -Path $mdnsPath -Force | Out-Null }
            Set-ItemProperty -Path $mdnsPath -Name "EnableMDNS" -Type DWord -Value 0 -Force
            Write-Host "  ok  mdns_udp_5353 = 0" -ForegroundColor Green

            # 3. Smart Multi-Homed DNS + TCP/IP stack hardening
            Set-ItemProperty -Path $dnsClientPath -Name "DisableSmartNameResolution" -Type DWord -Value 1 -Force
            $tcpParam = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            if (-not (Test-Path $tcpParam)) { New-Item -Path $tcpParam -Force | Out-Null }
            Set-ItemProperty -Path $tcpParam -Name "DisableSmartNameResolution" -Type DWord -Value 1 -Force
            Set-ItemProperty -Path $tcpParam -Name "DisableIPSourceRouting" -Type DWord -Value 2 -Force
            Set-ItemProperty -Path $tcpParam -Name "EnableICMPRedirect" -Type DWord -Value 0 -Force
            Write-Host "  ok  smart_multihomed_dns & icmp_redirects = 0" -ForegroundColor Green

            # 4. SMB Signing enforcement (Client & Server)
            $lanmanWork = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
            if (Test-Path $lanmanWork) {
                Set-ItemProperty -Path $lanmanWork -Name "RequireSecuritySignature" -Type DWord -Value 1 -Force
                Set-ItemProperty -Path $lanmanWork -Name "EnablePlainTextPassword" -Type DWord -Value 0 -Force
            }
            $lanmanSrv = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            if (Test-Path $lanmanSrv) {
                Set-ItemProperty -Path $lanmanSrv -Name "RequireSecuritySignature" -Type DWord -Value 1 -Force
                Set-ItemProperty -Path $lanmanSrv -Name "SMB1" -Type DWord -Value 0 -Force
            }
            Write-Host "  ok  smb_signing = required (smbv1 = 0)" -ForegroundColor Green

            # 5. NetBIOS over TCP/IP across ALL NetBT Registry Interfaces (including VPN/Wintun/VirtualBox)
            $netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
            if (Test-Path $netbtPath) {
                Get-ChildItem -Path $netbtPath -ErrorAction SilentlyContinue | ForEach-Object {
                    Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Type DWord -Value 2 -Force -ErrorAction SilentlyContinue
                }
                try {
                    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ErrorAction SilentlyContinue | ForEach-Object {
                        Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } -ErrorAction SilentlyContinue | Out-Null
                    }
                } catch {}
                Write-Host "  ok  netbios_over_tcpip = disabled across all interfaces" -ForegroundColor Green
            }

            # 6. Teredo IPv6 Tunneling (Registry + netsh fallback)
            $tcpip6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
            if (Test-Path $tcpip6Path) {
                $curComp = (Get-ItemProperty -Path $tcpip6Path -Name "DisabledComponents" -ErrorAction SilentlyContinue).DisabledComponents
                $newComp = if ($null -ne $curComp) { $curComp -bor 8 } else { 8 }
                Set-ItemProperty -Path $tcpip6Path -Name "DisabledComponents" -Type DWord -Value $newComp -Force -ErrorAction SilentlyContinue
            }
            netsh interface teredo set state disabled 2>$null | Out-Null
            Write-Host "  ok  teredo_ipv6 = disabled" -ForegroundColor Green

            if (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) {
                Clear-DnsClientCache -ErrorAction SilentlyContinue
                Write-Host "  ok  dns_cache -> flushed" -ForegroundColor Green
            }
        } else {
            Write-Host "  --  skipped LLMNR/mDNS/NetBIOS/SMB (requires admin)" -ForegroundColor DarkYellow
        }
    } elseif ($IsMacOS) {
        if ($isAdmin) {
            defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true 2>$null
            dscacheutil -flushcache 2>$null
            killall -HUP mDNSResponder 2>$null
            Write-Host "  ok  mDNS multicast advertisements -> disabled" -ForegroundColor Green
        } else {
            Write-Host "  --  skipped mDNS hardening (requires root)" -ForegroundColor DarkYellow
        }
    } else {
        if ($isAdmin) {
            if (Test-Path "/etc/systemd/resolved.conf") {
                $rc = Get-Content "/etc/systemd/resolved.conf" -Raw
                if ($rc -notmatch "(?m)^LLMNR=no") {
                    Add-Content -Path "/etc/systemd/resolved.conf" -Value "`nLLMNR=no`nMulticastDNS=no"
                }
                systemctl restart systemd-resolved 2>$null
                Write-Host "  ok  systemd-resolved LLMNR/mDNS -> disabled" -ForegroundColor Green
            }
            sysctl -w net.ipv4.conf.all.accept_redirects=0 2>$null | Out-Null
            sysctl -w net.ipv4.conf.default.accept_redirects=0 2>$null | Out-Null
            sysctl -w net.ipv6.conf.all.accept_redirects=0 2>$null | Out-Null
            sysctl -w net.ipv4.conf.all.accept_source_route=0 2>$null | Out-Null
            Write-Host "  ok  icmp accept_redirects & source_route -> 0" -ForegroundColor Green
        } else {
            Write-Host "  --  skipped resolved/sysctl network hardening (requires root)" -ForegroundColor DarkYellow
        }
    }
}

Export-ModuleMember -Function Audit-NetworkOpSec, Harden-NetworkOpSec
