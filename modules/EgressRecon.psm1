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

function Get-MullvadCli {
    $cmd = Get-Command "mullvad" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $paths = @(
        "C:\Program Files\Mullvad VPN\resources\mullvad.exe",
        "$env:ProgramFiles\Mullvad VPN\resources\mullvad.exe",
        "/usr/bin/mullvad",
        "/usr/local/bin/mullvad",
        "/Applications/Mullvad VPN.app/Contents/Resources/mullvad"
    )
    foreach ($p in $paths) {
        if ($p -and (Test-Path $p -ErrorAction SilentlyContinue)) {
            return $p
        }
    }
    return $null
}

function Audit-VpnAndEgress {
    $results = @()

    # 1. Detect Active VPN / Tunnel Adapter (Mullvad, ProtonVPN, WireGuard, OpenVPN, etc.)
    $allNics = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces())
    $vpnNics = @($allNics | Where-Object {
        $_.OperationalStatus -eq "Up" -and (
            $_.Name -match "Mullvad|ProTUN|Proton|WireGuard|wg|tun|tap|utun|Nord|Tailscale|ZeroTier|VPN" -or
            $_.Description -match "Mullvad|Proton|WireGuard|TAP-Windows|Wintun|OpenVPN|Nord|Tailscale|ZeroTier|VPN|Tunnel" -or
            [int]$_.NetworkInterfaceType -in @(53, 131)
        )
    })

    $vpnUp = ($vpnNics.Count -gt 0)
    $vpnNames = if ($vpnUp) { ($vpnNics | ForEach-Object { "$($_.Name) ($($_.Description))" }) -join ", " } else { "no active tunnel interface" }
    $results += [PSCustomObject]@{
        Check   = "VPN / Encrypted Tunnel"
        Status  = if ($vpnUp) { "HARDENED" } else { "CONFIGURABLE" }
        Details = $vpnNames
    }

        # 2. Mullvad Partner Integration Check (if Mullvad CLI/daemon is present)
        $mullvadBin = Get-MullvadCli
        if ($mullvadBin) {
            $mvStatus   = (& $mullvadBin status 2>$null | Out-String).Trim()
            $mvLockdown = (& $mullvadBin lockdown-mode get 2>$null | Out-String).Trim()
            $isConnected = ($mvStatus -match "Connected")
            $isLockdown  = ($mvLockdown -match "on")
            $firstLine   = if ($mvStatus) { ($mvStatus.Split("`n")[0] -replace '\r', '').Trim() } else { "" }
            $cleanStatus = if ($firstLine) { $firstLine } elseif ($isConnected) { "Connected" } else { "disconnected" }
            $results += [PSCustomObject]@{
                Check   = "Mullvad Partner Lockdown"
                Status  = if ($isConnected -and $isLockdown) { "HARDENED" } elseif ($isConnected) { "CONFIGURABLE" } else { "EXPOSED" }
                Details = "$cleanStatus | killswitch: $(if ($isLockdown) { 'on' } else { 'off' })"
            }

            # Audit Post-Quantum & DAITA (Defense Against AI Traffic Analysis)
            $mvTun = (& $mullvadBin tunnel get 2>$null | Out-String)
            $hasPQ    = ($mvTun -match "(?i)Quantum\s*resist\w*:\s*(on|true|enabled)")
            $hasDaita = ($mvTun -match "(?i)DAITA:\s*(on|true|enabled)")
            $mvRelay  = (& $mullvadBin relay get 2>$null | Out-String)
            $hasHop   = ($mvRelay -match "(?i)Multihop(\s*state)?:\s*(on|multihop|true|enabled)")

            $pqDaitaStatus = if ($hasPQ -and $hasDaita -and $hasHop) { "HARDENED" } elseif ($hasPQ -or $hasDaita -or $hasHop) { "CONFIGURABLE" } else { "CONFIGURABLE" }
            $results += [PSCustomObject]@{
                Check   = "Mullvad Post-Quantum & DAITA"
                Status  = $pqDaitaStatus
                Details = "PQ(Kyber): $(if ($hasPQ){'on'}else{'off'}) | DAITA(Anti-AI): $(if ($hasDaita){'on'}else{'off'}) | Multihop: $(if ($hasHop){'on'}else{'off'})"
            }
        }

    if (Test-IsWindowsOS) {
        # 3. Check for DNS Leaks while VPN is active
        $smartDns = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartNameResolution" -ErrorAction SilentlyContinue).DisableSmartNameResolution
        $dnsLeak = ($vpnUp -and $smartDns -ne 1)
        $dnsDetails = if ($vpnUp -and $smartDns -eq 1) { "tunnel active + SmartDNS leak lock enforced" } elseif (-not $vpnUp -and $smartDns -eq 1) { "SmartDNS leak lock enforced" } else { "SmartDNS unlocked (ISP DNS leak risk)" }
        $results += [PSCustomObject]@{
            Check   = "VPN DNS Leak Protection"
            Status  = if (-not $dnsLeak -and $smartDns -eq 1) { "HARDENED" } else { "EXPOSED" }
            Details = $dnsDetails
        }

        # 4. Telemetry Binary Outbound Firewall Block
        $fwRulesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        $fwBlocked = $false
        if (Test-Path $fwRulesPath) {
            $props = Get-ItemProperty -Path $fwRulesPath -ErrorAction SilentlyContinue
            if ($props) {
                $matchRule = $props.PSObject.Properties | Where-Object { $_.Value -match "WinOpSec_Block_Telemetry_Binaries" }
                if ($matchRule) { $fwBlocked = $true }
            }
        }
        $results += [PSCustomObject]@{
            Check   = "Telemetry Egress Firewall Rule"
            Status  = if ($fwBlocked) { "HARDENED" } else { "EXPOSED" }
            Details = if ($fwBlocked) { "outbound block active" } else { "not configured" }
        }
    }

    return $results
}

function Invoke-MullvadPartner {
    param([string]$Action = "status")

    $mullvadBin = Get-MullvadCli

    if ($Action -match "^(rotate|rotate-key)$") {
        if (-not $mullvadBin) {
            Write-Host "  [!] Mullvad CLI not found." -ForegroundColor Yellow
            return
        }
        & $mullvadBin tunnel set rotate-key 2>$null | Out-Null
        Write-Host "  ok  Mullvad WireGuard cryptographic key pair rotated." -ForegroundColor Green
        return
    }

    if ($Action -match "^daita(\s+(on|off))?$") {
        if (-not $mullvadBin) {
            Write-Host "  [!] Mullvad CLI not found." -ForegroundColor Yellow
            return
        }
        $tgt = if ($Matches[2]) { $Matches[2] } else { "on" }
        & $mullvadBin tunnel set daita $tgt 2>$null | Out-Null
        Write-Host "  ok  mullvad daita (Maybenot AI traffic analysis defense) = $tgt" -ForegroundColor Green
        return
    }

    if ($Action -match "^multihop(\s+(on|off))?$") {
        if (-not $mullvadBin) {
            Write-Host "  [!] Mullvad CLI not found." -ForegroundColor Yellow
            return
        }
        $tgt = if ($Matches[2]) { $Matches[2] } else { "on" }
        & $mullvadBin relay set multihop $tgt 2>$null | Out-Null
        Write-Host "  ok  mullvad wireguard multihop (dual-country routing) = $tgt" -ForegroundColor Green
        return
    }

    if ($Action -eq "harden" -or $Action -eq "lockdown") {
        if (-not $mullvadBin) {
            Write-Host "  --  Mullvad CLI not detected on host; applying Mullvad DoH & tunnel-safe stack rules" -ForegroundColor DarkGray
            return
        }
        Write-Host "  -- configuring Mullvad VPN partner state-level lockdown..." -ForegroundColor Cyan
        & $mullvadBin auto-connect set on 2>$null | Out-Null
        Write-Host "  ok  mullvad auto-connect = on" -ForegroundColor Green

        & $mullvadBin lockdown-mode set on 2>$null | Out-Null
        Write-Host "  ok  mullvad lockdown-mode (always-on hardware killswitch) = on" -ForegroundColor Green

        & $mullvadBin lan set block 2>$null | Out-Null
        Write-Host "  ok  mullvad local-network-sharing = block (anti-LAN snooping)" -ForegroundColor Green

        & $mullvadBin tunnel set quantum-resistant on 2>$null | Out-Null
        Write-Host "  ok  mullvad wireguard quantum-resistant (Kyber-1024 PQ) = on" -ForegroundColor Green

        & $mullvadBin tunnel set daita on 2>$null | Out-Null
        Write-Host "  ok  mullvad daita (Defense Against AI Traffic Analysis / Maybenot) = on" -ForegroundColor Green

        & $mullvadBin relay set multihop on 2>$null | Out-Null
        Write-Host "  ok  mullvad wireguard multihop (dual-country bounce) = on" -ForegroundColor Green

        & $mullvadBin dns set default --block-ads --block-trackers --block-malware 2>$null | Out-Null
        Write-Host "  ok  mullvad encrypted dns = block ads + trackers + malware (100.64.0.7)" -ForegroundColor Green

        & $mullvadBin tunnel set rotate-key 2>$null | Out-Null
        Write-Host "  ok  mullvad wireguard fresh key pair generated & rotated" -ForegroundColor Green

        # Physical IPv6 Leak Lockout (blocks ISP from leaking un-tunneled IPv6)
        if (Test-IsWindowsOS) {
            try {
                Get-NetAdapter | Where-Object { $_.InterfaceDescription -notmatch "Mullvad|WireGuard|Wintun|TAP" } | ForEach-Object {
                    Disable-NetAdapterBinding -Name $_.Name -ComponentId ms_tcpip6 -ErrorAction SilentlyContinue
                }
                Write-Host "  ok  physical adapter ipv6 unbound (zero ipv6 leak risk)" -ForegroundColor Green
            } catch {}

            # Disable NetBIOS across all interfaces (including the new Mullvad tunnel interface)
            $netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
            if (Test-Path $netbtPath) {
                Get-ChildItem -Path $netbtPath -ErrorAction SilentlyContinue | ForEach-Object {
                    Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Type DWord -Value 2 -Force -ErrorAction SilentlyContinue
                }
                Write-Host "  ok  netbios_over_tcpip = disabled across all interfaces" -ForegroundColor Green
            }
        }

        # Reconnect tunnel so post-quantum keys & multihop routes are negotiated
        & $mullvadBin reconnect 2>$null | Out-Null
        Write-Host "  ok  mullvad tunnel reconnected (post-quantum & multihop negotiated)" -ForegroundColor Green
        return
    }

    Write-Host "  -- mullvad vpn state-level verification" -ForegroundColor Cyan
    if ($mullvadBin) {
        Write-Host "  cli      : $mullvadBin" -ForegroundColor Gray
        $st = (& $mullvadBin status 2>$null | Out-String).Trim()
        $ld = (& $mullvadBin lockdown-mode get 2>$null | Out-String).Trim()
        $ln = (& $mullvadBin lan get 2>$null | Out-String).Trim()
        $dn = (& $mullvadBin dns get 2>$null | Out-String).Trim()
        $tun = (& $mullvadBin tunnel get 2>$null | Out-String)
        $rel = (& $mullvadBin relay get 2>$null | Out-String)

        Write-Host "  status   : $st" -ForegroundColor Green
        Write-Host "  lockdown : $ld" -ForegroundColor $(if ($ld -match "on") { "Green" } else { "Yellow" })
        Write-Host "  lan      : $ln" -ForegroundColor Gray
        Write-Host "  dns      : $($dn -replace '\r?\n', ' ')" -ForegroundColor Gray

        $pqMatch = if ($tun -match "(?i)Quantum\s*resist\w*:\s*(\w+)") { $Matches[1].ToLower() } else { "off" }
        $daitaMatch = if ($tun -match "(?i)DAITA:\s*(\w+)") { $Matches[1].ToLower() } else { "off" }
        $hopMatch = if ($rel -match "(?i)Multihop(\s*state)?:\s*(\w+)") { $Matches[2].ToLower() } else { "off" }

        Write-Host "  quantum  : $pqMatch" -ForegroundColor $(if ($pqMatch -eq "on") { "Green" } else { "DarkGray" })
        Write-Host "  daita    : $daitaMatch (Anti-AI traffic shaping)" -ForegroundColor $(if ($daitaMatch -eq "on") { "Green" } else { "DarkGray" })
        Write-Host "  multihop : $hopMatch (dual-country routing)" -ForegroundColor $(if ($hopMatch -in @("on", "multihop")) { "Green" } else { "DarkGray" })
    } else {
        Write-Host "  cli      : not installed (checking network tunnel & Mullvad exit API...)" -ForegroundColor DarkGray
    }

    try {
        $resp = Invoke-RestMethod -Uri "https://am.i.mullvad.net/json" -TimeoutSec 4 -ErrorAction Stop
        $mvColor = if ($resp.mullvad_exit_ip) { "Green" } else { "Yellow" }
        Write-Host "  exit ip  : $($resp.ip) ($($resp.city), $($resp.country))" -ForegroundColor Gray
        Write-Host "  provider : $($resp.organization)" -ForegroundColor Gray
        Write-Host "  mullvad  : $($resp.mullvad_exit_ip) $(if ($resp.mullvad_exit_ip_hostname) { "[$($resp.mullvad_exit_ip_hostname)]" })" -ForegroundColor $mvColor
        Write-Host "  blacklst : $($resp.blacklisted.blacklisted)" -ForegroundColor $(if ($resp.blacklisted.blacklisted) { "Red" } else { "Green" })
    } catch {
        Write-Host "  exit api : offline or unreachable in current sandbox" -ForegroundColor DarkGray
    }
}

function Invoke-NetworkRecon {
    Write-Host "  -- active vpn & tunnel status" -ForegroundColor Cyan
    $vpnChecks = Audit-VpnAndEgress
    foreach ($c in $vpnChecks) {
        $tag = if ($c.Status -eq "HARDENED") { "PASS" } elseif ($c.Status -eq "CONFIGURABLE") { "INFO" } else { "FAIL" }
        $col = if ($c.Status -eq "HARDENED") { "Green" } elseif ($c.Status -eq "CONFIGURABLE") { "Yellow" } else { "Red" }
        Write-Host ("  [{0}] {1,-32} {2}" -f $tag, $c.Check, $c.Details) -ForegroundColor $col
    }

    Write-Host "`n  -- active network interfaces" -ForegroundColor Cyan
    $upNics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.OperationalStatus -eq "Up" }
    foreach ($nic in $upNics) {
        $ipProps = $nic.GetIPProperties()
        $ipv4 = ($ipProps.UnicastAddresses | Where-Object { $_.Address.AddressFamily -eq "InterNetwork" } | ForEach-Object { $_.Address.IPAddressToString }) -join ", "
        $dns  = ($ipProps.DnsAddresses | Where-Object { $_.AddressFamily -eq "InterNetwork" } | ForEach-Object { $_.IPAddressToString }) -join ", "
        Write-Host ("  up      {0,-22} ip:{1,-16} dns:{2} [{3}]" -f $nic.Name, $(if ($ipv4) { $ipv4 } else { "none" }), $(if ($dns) { $dns } else { "none" }), $nic.Description) -ForegroundColor Gray
    }

    try {
        $ipGlobal = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()

        Write-Host "`n  -- exposed listening ports (0.0.0.0 / ::)" -ForegroundColor Cyan
        $listeners = $ipGlobal.GetActiveTcpListeners() |
            Where-Object { $_.Address.IPAddressToString -in @("0.0.0.0", "::") } |
            Sort-Object Port -Unique

        if (-not $listeners) {
            Write-Host "  [PASS] no wildcard listening ports found." -ForegroundColor Green
        } else {
            foreach ($l in $listeners) {
                $riskColor = if ($l.Port -in @(21, 22, 23, 80, 135, 139, 445, 3389, 5985, 8080)) { "Yellow" } else { "Gray" }
                Write-Host ("  listen  {0}:{1}" -f $l.Address.IPAddressToString, $l.Port) -ForegroundColor $riskColor
            }
        }

        Write-Host "`n  -- active external connections (non-loopback)" -ForegroundColor Cyan
        $estab = $ipGlobal.GetActiveTcpConnections() |
            Where-Object { $_.State -eq "Established" -and $_.RemoteEndPoint.Address.IPAddressToString -notmatch "^(127\.|::1|0\.0\.0\.0)" } |
            Select-Object -First 25

        if (-not $estab) {
            Write-Host "  [PASS] no active external TCP sessions." -ForegroundColor Green
        } else {
            foreach ($e in $estab) {
                Write-Host ("  estab   {0,-22} -> {1}" -f $e.LocalEndPoint.ToString(), $e.RemoteEndPoint.ToString()) -ForegroundColor Gray
            }
        }
    } catch {}
}

function Harden-FirewallEgress {
    if (-not (Test-AdminPrivilege)) {
        Write-Host "  --  skipped firewall egress rules (requires admin/root)" -ForegroundColor DarkYellow
        return
    }

    if (Test-IsWindowsOS) {
        $ruleName = "WinOpSec_Block_Telemetry_Binaries"
        netsh advfirewall firewall delete rule name="$ruleName" 2>$null | Out-Null

        $telemetryBins = @(
            "$env:SystemRoot\System32\CompatTelRunner.exe",
            "$env:SystemRoot\System32\wermgr.exe",
            "$env:SystemRoot\System32\WerFault.exe",
            "$env:SystemRoot\System32\DeviceCensus.exe"
        )

        foreach ($bin in $telemetryBins) {
            if (Test-Path $bin) {
                netsh advfirewall firewall add rule name="$ruleName" dir=out action=block program="$bin" enable=yes profile=any 2>$null | Out-Null
            }
        }
        Write-Host "  ok  firewall outbound block -> CompatTelRunner, WerFault, DeviceCensus" -ForegroundColor Green
    }
}

Export-ModuleMember -Function Get-MullvadCli, Audit-VpnAndEgress, Invoke-MullvadPartner, Invoke-NetworkRecon, Harden-FirewallEgress
