# SentryMonitor.psm1 - Real-Time Public Sentry, Intrusion Tripwire & Eavesdropping Defense
# WinOpSec Sovereign Tier Defensive Monitor

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

function Get-DefaultGatewayInfo {
    $gwInfo = [PSCustomObject]@{
        GatewayIP   = $null
        InterfaceIP = $null
        GatewayMAC  = $null
        Interface   = $null
        Metric      = 9999
    }

    if (-not (Test-IsWindowsOS)) {
        return $gwInfo
    }

    try {
        $routes = route print 0.0.0.0 2>$null
        foreach ($line in $routes) {
            if ($line -match '^\s+0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d+)') {
                $gw  = $Matches[1]
                $iface = $Matches[2]
                $met = [int]$Matches[3]
                if ($gw -ne "0.0.0.0" -and $gw -ne "127.0.0.1") {
                    if ($met -lt $gwInfo.Metric -or ($gwInfo.GatewayIP -match "^10\." -and $gw -match "^192\.168\.")) {
                        $gwInfo.GatewayIP   = $gw
                        $gwInfo.InterfaceIP = $iface
                        $gwInfo.Metric      = $met
                    }
                }
            }
        }
    } catch {}

    if ($gwInfo.GatewayIP) {
        $gwInfo.GatewayMAC = Get-MacForIp -IpAddress $gwInfo.GatewayIP
    }

    return $gwInfo
}

function Get-MacForIp {
    param([string]$IpAddress)
    if (-not $IpAddress) { return $null }

    try {
        $neighbor = Get-NetNeighbor -IPAddress $IpAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($neighbor -and $neighbor.LinkLayerAddress) {
            return $neighbor.LinkLayerAddress.ToUpper().Replace("-", ":")
        }
    } catch {}

    try {
        $arpLines = arp -a 2>$null
        foreach ($line in $arpLines) {
            if ($line -match ("\s+" + [regex]::Escape($IpAddress) + "\s+([0-9a-fA-F\-]{17})\s+")) {
                return $Matches[1].ToUpper().Replace("-", ":")
            }
        }
    } catch {}

    return $null
}

function Get-ArpTableSnapshot {
    $table = @{}
    try {
        $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue
        foreach ($n in $neighbors) {
            if ($n.LinkLayerAddress -and $n.IPAddress -and $n.LinkLayerAddress -ne "00-00-00-00-00-00" -and $n.State -ne "Unreachable") {
                $mac = $n.LinkLayerAddress.ToUpper().Replace("-", ":")
                if (-not $table.ContainsKey($mac)) {
                    $table[$mac] = [System.Collections.Generic.List[string]]::new()
                }
                if (-not $table[$mac].Contains($n.IPAddress)) {
                    $table[$mac].Add($n.IPAddress)
                }
            }
        }
    } catch {}

    if ($table.Count -eq 0) {
        try {
            $arpOut = arp -a 2>$null
            foreach ($line in $arpOut) {
                if ($line -match '^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F\-]{17})\s+') {
                    $ip = $Matches[1]
                    $mac = $Matches[2].ToUpper().Replace("-", ":")
                    if ($mac -ne "FF:FF:FF:FF:FF:FF" -and $mac -ne "00:00:00:00:00:00") {
                        if (-not $table.ContainsKey($mac)) {
                            $table[$mac] = [System.Collections.Generic.List[string]]::new()
                        }
                        if (-not $table[$mac].Contains($ip)) {
                            $table[$mac].Add($ip)
                        }
                    }
                }
            }
        } catch {}
    }

    return $table
}

function Test-ArpPoisoning {
    param(
        [string]$BaselineGatewayIP,
        [string]$BaselineGatewayMAC
    )

    $alerts = @()

    if ($BaselineGatewayIP -and $BaselineGatewayMAC) {
        $currentMAC = Get-MacForIp -IpAddress $BaselineGatewayIP
        if ($currentMAC -and ($currentMAC -ne $BaselineGatewayMAC)) {
            $alerts += [PSCustomObject]@{
                Severity = "CRITICAL"
                Type     = "ARP_GATEWAY_POISONED"
                Target   = $BaselineGatewayIP
                Detail   = "Gateway MAC changed from $BaselineGatewayMAC to $currentMAC! MITM in progress."
            }
        }
    }

    $arpTable = Get-ArpTableSnapshot
    foreach ($mac in $arpTable.Keys) {
        $ips = $arpTable[$mac]
        if ($ips.Count -gt 1) {
            $validIps = @($ips | Where-Object { $_ -notmatch "^224\." -and $_ -notmatch "^239\." -and $_ -notmatch "\.255$" })
            if ($validIps.Count -gt 1) {
                $alerts += [PSCustomObject]@{
                    Severity = "CRITICAL"
                    Type     = "ARP_MAC_COLLISION_DETECTED"
                    Target   = $mac
                    Detail   = "Single MAC [$mac] is claiming multiple IPs: $($validIps -join ', ') (Bettercap/arpspoof signature)."
                }
            }
        }
    }

    return $alerts
}

Export-ModuleMember -Function Test-ArpPoisoning, Get-DefaultGatewayInfo
