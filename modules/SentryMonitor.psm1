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

function Test-PortScanActivity {
    $alerts = @()
    $synCount = 0
    $probeSources = [System.Collections.Generic.List[string]]::new()

    try {
        $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue
        if ($conns) {
            foreach ($c in $conns) {
                if ($c.State -eq "SynReceived") {
                    $synCount++
                    if ($c.RemoteAddress -and $c.RemoteAddress -ne "0.0.0.0") {
                        $probeSources.Add("$($c.RemoteAddress):$($c.LocalPort)")
                    }
                }
                if ($c.LocalPort -in @(135, 137, 138, 139, 445, 3389, 5985) -and $c.State -in @("Established", "SynReceived")) {
                    if ($c.RemoteAddress -notmatch "^127\." -and $c.RemoteAddress -ne "::1" -and $c.RemoteAddress -ne "0.0.0.0") {
                        $alerts += [PSCustomObject]@{
                            Severity = "HIGH"
                            Type     = "SENSITIVE_PORT_INBOUND_HIT"
                            Target   = "$($c.LocalPort) ($($c.RemoteAddress))"
                            Detail   = "Inbound active TCP socket on port $($c.LocalPort) from $($c.RemoteAddress)."
                        }
                    }
                }
            }
        }
    } catch {}

    if ($alerts.Count -eq 0 -and $synCount -eq 0) {
        try {
            $netstat = netstat -ano 2>$null
            foreach ($line in $netstat) {
                if ($line -match 'SYN_RECEIVED') {
                    $synCount++
                    if ($line -match '^\s*TCP\s+\S+:(\d+)\s+(\S+):\d+\s+SYN_RECEIVED') {
                        $probeSources.Add("$($Matches[2]) -> port $($Matches[1])")
                    }
                }
                if ($line -match '^\s*TCP\s+\S+:(135|139|445|3389|5985)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+\s+ESTABLISHED') {
                    $remIp = $Matches[2]
                    if ($remIp -notmatch "^127\.") {
                        $alerts += [PSCustomObject]@{
                            Severity = "HIGH"
                            Type     = "SENSITIVE_PORT_INBOUND_HIT"
                            Target   = "$remIp"
                            Detail   = "Established inbound connection on sensitive port from $remIp."
                        }
                    }
                }
            }
        } catch {}
    }

    if ($synCount -ge 2) {
        $alerts += [PSCustomObject]@{
            Severity = "HIGH"
            Type     = "SYN_PORT_SCAN_DETECTED"
            Target   = "$synCount half-open probes"
            Detail   = "Half-open SYN scan detected ($synCount probes: $($probeSources -join ', '))."
        }
    }

    return $alerts
}

function Test-ActiveEavesdropping {
    $alerts = @()
    if (-not (Test-IsWindowsOS)) { return $alerts }

    $consentRoots = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    )

    foreach ($sensor in @("microphone", "webcam")) {
        foreach ($root in $consentRoots) {
            $sensorPath = Join-Path $root $sensor
            if (-not (Test-Path $sensorPath -ErrorAction SilentlyContinue)) { continue }

            try {
                $subkeys = Get-ChildItem -Path $sensorPath -Recurse -ErrorAction SilentlyContinue
                foreach ($sub in $subkeys) {
                    $props = Get-ItemProperty -Path $sub.PSPath -ErrorAction SilentlyContinue
                    if ($props -and $props.LastUsedTimeStart -ne $null) {
                        $tStart = [int64]$props.LastUsedTimeStart
                        $tStop  = if ($props.LastUsedTimeStop -ne $null) { [int64]$props.LastUsedTimeStop } else { 0 }

                        if ($tStart -gt 0 -and ($tStop -eq 0 -or $tStart -gt $tStop)) {
                            $appName = $sub.PSChildName
                            if ($appName -match '#([^#]+)$') { $appName = $Matches[1] }
                            $alerts += [PSCustomObject]@{
                                Severity = "CRITICAL"
                                Type     = "EAVESDROPPING_SENSOR_ACTIVE"
                                Target   = "$sensor ($appName)"
                                Detail   = "Sensor '$sensor' is ACTIVELY RECORDING by application: $appName"
                            }
                        }
                    }
                }
            } catch {}
        }
    }

    return $alerts
}

Export-ModuleMember -Function Test-ArpPoisoning, Get-DefaultGatewayInfo, Test-PortScanActivity, Test-ActiveEavesdropping
