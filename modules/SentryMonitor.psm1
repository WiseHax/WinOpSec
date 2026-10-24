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

function Get-UsbHardwareSnapshot {
    $devices = [System.Collections.Generic.HashSet[string]]::new()
    if (-not (Test-IsWindowsOS)) { return $devices }

    try {
        $usbKeys = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' -ErrorAction SilentlyContinue
        foreach ($k in $usbKeys) {
            $devices.Add($k.PSChildName) | Out-Null
        }
    } catch {}

    try {
        $drives = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType.ToString() -eq "Removable" -and $_.IsReady }
        foreach ($d in $drives) {
            $devices.Add("DRIVE_" + $d.Name.TrimEnd("\")) | Out-Null
        }
    } catch {}

    return $devices
}

function Test-UsbPerimeter {
    param([System.Collections.Generic.HashSet[string]]$BaselineUsbSet)

    $alerts = @()
    if (-not $BaselineUsbSet) { return $alerts }

    $currentUsb = Get-UsbHardwareSnapshot
    foreach ($dev in $currentUsb) {
        if (-not $BaselineUsbSet.Contains($dev)) {
            $alerts += [PSCustomObject]@{
                Severity = "CRITICAL"
                Type     = "ROGUE_USB_INSERTION"
                Target   = $dev
                Detail   = "Unauthorized physical USB device detected ($dev)! Potential Rubber Ducky / BadUSB injector."
            }
        }
    }

    return $alerts
}

function Test-DnsHijack {
    $alerts = @()
    if (-not (Test-IsWindowsOS)) { return $alerts }

    try {
        $dnsList = @()
        $dnsAddrs = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($dnsAddrs) {
            foreach ($d in $dnsAddrs) {
                if ($d.ServerAddresses) { $dnsList += $d.ServerAddresses }
            }
        }

        if ($dnsList.Count -eq 0) {
            $ipLines = ipconfig /all 2>$null
            foreach ($l in $ipLines) {
                if ($l -match 'DNS Servers[ .:]+:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                    $dnsList += $Matches[1]
                }
            }
        }

        foreach ($dns in $dnsList) {
            if ($dns -match "^192\.168\." -or ($dns -match "^10\." -and $dns -ne "10.64.0.1")) {
                $alerts += [PSCustomObject]@{
                    Severity = "HIGH"
                    Type     = "ROGUE_DNS_RESOLVER"
                    Target   = $dns
                    Detail   = "Insecure local resolver ($dns) active. Unencrypted DNS vulnerable to MITM/poisoning."
                }
            }
        }
    } catch {}

    try {
        $hostsPath = "$env:windir\System32\drivers\etc\hosts"
        if (Test-Path $hostsPath) {
            $hostsLines = Get-Content $hostsPath -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' }
            if ($hostsLines.Count -gt 5) {
                $alerts += [PSCustomObject]@{
                    Severity = "HIGH"
                    Type     = "HOSTS_FILE_TAMPERED"
                    Target   = $hostsPath
                    Detail   = "Unusual number of active overrides found in hosts file ($($hostsLines.Count) entries)."
                }
            }
        }
    } catch {}

    return $alerts
}

function Test-WifiPerimeter {
    param([ref]$CurrentBssidRef)

    $alerts = @()
    if (-not (Test-IsWindowsOS)) { return $alerts }

    try {
        $wlan = netsh wlan show interfaces 2>$null
        $ssid  = $null
        $bssid = $null
        $auth  = $null

        foreach ($line in $wlan) {
            if ($line -match '^\s*SSID\s*:\s*(.+)$')  { $ssid = $Matches[1].Trim() }
            if ($line -match '^\s*BSSID\s*:\s*(.+)$') { $bssid = $Matches[1].Trim().ToUpper() }
            if ($line -match '^\s*Authentication\s*:\s*(.+)$') { $auth = $Matches[1].Trim() }
        }

        if ($bssid) {
            if ($CurrentBssidRef.Value -ne $null -and $CurrentBssidRef.Value -ne $bssid) {
                $alerts += [PSCustomObject]@{
                    Severity = "HIGH"
                    Type     = "WIFI_BSSID_MUTATION"
                    Target   = "$ssid ($bssid)"
                    Detail   = "Access Point BSSID changed from $($CurrentBssidRef.Value) to $bssid! Potential Evil Twin rogue AP handover."
                }
            }
            $CurrentBssidRef.Value = $bssid

            if ($auth -match "Open" -or $auth -match "None") {
                $alerts += [PSCustomObject]@{
                    Severity = "HIGH"
                    Type     = "WIFI_UNENCRYPTED_OPEN"
                    Target   = "$ssid"
                    Detail   = "Connected to completely unencrypted open Wi-Fi network. Public eavesdropping guaranteed."
                }
            }
        }
    } catch {}

    return $alerts
}

function Test-ReverseShellIntegrity {
    $alerts = @()
    if (-not (Test-IsWindowsOS)) { return $alerts }

    $suspiciousNames = @("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "certutil.exe")

    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        if ($conns) {
            foreach ($c in $conns) {
                if ($c.OwningProcess) {
                    $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
                    if ($proc -and ($proc.ProcessName + ".exe" -in $suspiciousNames)) {
                        if ($c.RemoteAddress -notmatch "^127\." -and $c.RemoteAddress -ne "::1") {
                            $alerts += [PSCustomObject]@{
                                Severity = "CRITICAL"
                                Type     = "REVERSE_SHELL_ACTIVE"
                                Target   = "$($proc.ProcessName) (PID $($proc.Id))"
                                Detail   = "Suspicious shell process $($proc.ProcessName) has established outbound socket to $($c.RemoteAddress):$($c.RemotePort)."
                            }
                        }
                    }
                }
            }
        }
    } catch {}

    return $alerts
}

function Invoke-SentryDefensiveAction {
    param(
        [array]$Threats,
        [switch]$AutoPanic
    )

    if ($Threats.Count -eq 0) { return }

    try { [Console]::Beep(2200, 300) } catch {}

    if ($AutoPanic) {
        Write-Host "`n  [CRITICAL AUTO-DEFENSE ENGAGED]" -ForegroundColor Red
        Write-Host "  Triggering immediate network severance & workstation lockdown..." -ForegroundColor Yellow

        try {
            if (Test-IsWindowsOS) {
                Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" } | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
                route delete 0.0.0.0 2>$null | Out-Null
            }
        } catch {}

        try {
            rundll32.exe user32.dll,LockWorkStation
        } catch {}

        Write-Host "  Workstation locked. Network severed." -ForegroundColor Red
    }
}

function Audit-SentryPosture {
    $results = @()

    $gw = Get-DefaultGatewayInfo
    $gwMacStatus = if ($gw.GatewayMAC) { "HARDENED" } else { "CONFIGURABLE" }
    $gwMacDetail = if ($gw.GatewayMAC) { "$($gw.GatewayIP) ($($gw.GatewayMAC))" } else { "No active gateway or virtualized adapter" }
    $results += [PSCustomObject]@{
        Status  = $gwMacStatus
        Check   = "Gateway ARP Baseline"
        Details = $gwMacDetail
    }

    $arpTable = Get-ArpTableSnapshot
    $arpCollisions = 0
    foreach ($k in $arpTable.Keys) {
        if ($arpTable[$k].Count -gt 1) { $arpCollisions++ }
    }
    $arpStatus = if ($arpCollisions -eq 0) { "CLEAN" } else { "FAIL" }
    $results += [PSCustomObject]@{
        Status  = $arpStatus
        Check   = "ARP Table Collision Check"
        Details = if ($arpCollisions -eq 0) { "Zero duplicate MAC anomalies detected" } else { "$arpCollisions duplicate MAC collisions found!" }
    }

    $micConsent = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -ErrorAction SilentlyContinue
    $camConsent = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -ErrorAction SilentlyContinue
    $sensorLock = ($micConsent.Value -eq "Deny" -or $camConsent.Value -eq "Deny")
    $results += [PSCustomObject]@{
        Status  = if ($sensorLock) { "HARDENED" } else { "CONFIGURABLE" }
        Check   = "Sensor Hardware Lockdown"
        Details = if ($sensorLock) { "Microphone/Webcam global consent blocked" } else { "Sensors open (allowed for user apps)" }
    }

    $activeEaves = Test-ActiveEavesdropping
    $eavesStatus = if ($activeEaves.Count -eq 0) { "CLEAN" } else { "FAIL" }
    $results += [PSCustomObject]@{
        Status  = $eavesStatus
        Check   = "Live Eavesdropping Sentinel"
        Details = if ($activeEaves.Count -eq 0) { "No active audio/video surveillance streams" } else { "$($activeEaves.Count) active recording processes detected!" }
    }

    $usbSet = Get-UsbHardwareSnapshot
    $results += [PSCustomObject]@{
        Status  = "HARDENED"
        Check   = "USB Perimeter Tripwire"
        Details = "$($usbSet.Count) baseline USB devices registered"
    }

    return $results
}

function Invoke-SentryMonitor {
    [CmdletBinding()]
    param(
        [int]$IntervalSec = 2,
        [switch]$AutoPanic,
        [switch]$AudioAlert,
        [switch]$SinglePass
    )

    if (-not (Test-IsWindowsOS)) {
        Write-Host "  [!] Real-Time Public Sentry is supported on Windows hosts." -ForegroundColor Yellow
        return
    }

    Write-Host "`n  -- public sentry guard -----------------------------------------" -ForegroundColor DarkGray
    Write-Host "  monitoring public Wi-Fi & LAN perimeter for hostile activity." -ForegroundColor Gray
    Write-Host "  interval  : every $IntervalSec seconds  |  autopanic: $(if ($AutoPanic) { 'armed (auto-sever)' } else { 'alert only' })" -ForegroundColor $(if ($AutoPanic) { 'Red' } else { 'DarkGray' })
    Write-Host "  press Ctrl+C to stop monitoring.`n" -ForegroundColor DarkGray

    Write-Host "  [*] Baselining Default Gateway..." -ForegroundColor DarkGray
    $gw = Get-DefaultGatewayInfo
    $baseGwIp  = $gw.GatewayIP
    $baseGwMac = $gw.GatewayMAC
    Write-Host "      Gateway IP  : $(if ($baseGwIp) { $baseGwIp } else { 'None/VPN' })" -ForegroundColor White
    Write-Host "      Gateway MAC : $(if ($baseGwMac) { $baseGwMac } else { 'Unknown/Dynamic' })" -ForegroundColor White

    Write-Host "  [*] Baselining USB Perimeter..." -ForegroundColor DarkGray
    $baseUsb = Get-UsbHardwareSnapshot
    Write-Host "      Baseline USB Devices: $($baseUsb.Count) attached" -ForegroundColor White

    Write-Host "  [*] Baselining Wi-Fi Access Point..." -ForegroundColor DarkGray
    $currentBssid = $null
    $bssidRef = [ref]$currentBssid
    Test-WifiPerimeter -CurrentBssidRef $bssidRef | Out-Null
    Write-Host "      Active BSSID: $(if ($bssidRef.Value) { $bssidRef.Value } else { 'Ethernet/VPN/Container' })" -ForegroundColor White

    Write-Host "`n  [+] SENTRY ACTIVE. Watching perimeter... (Press [Ctrl+C] or 'q' to stop)`n" -ForegroundColor Green

    $cycle = 0

    while ($true) {
        $cycle++
        $timestamp = (Get-Date).ToString("HH:mm:ss")
        $allThreats = @()

        $arpThreats = Test-ArpPoisoning -BaselineGatewayIP $baseGwIp -BaselineGatewayMAC $baseGwMac
        $allThreats += $arpThreats

        $scanThreats = Test-PortScanActivity
        $allThreats += $scanThreats

        $sensorThreats = Test-ActiveEavesdropping
        $allThreats += $sensorThreats

        $usbThreats = Test-UsbPerimeter -BaselineUsbSet $baseUsb
        $allThreats += $usbThreats

        $dnsThreats = Test-DnsHijack
        $allThreats += $dnsThreats

        $revThreats = Test-ReverseShellIntegrity
        $allThreats += $revThreats

        $wifiThreats = Test-WifiPerimeter -CurrentBssidRef $bssidRef
        $allThreats += $wifiThreats

        if ($allThreats.Count -gt 0) {
            Write-Host "`n  [$timestamp] [ALERT] $($allThreats.Count) DEFENSIVE TRIPWIRE(S) TRIGGERED!" -ForegroundColor Red
            foreach ($t in $allThreats) {
                $color = if ($t.Severity -eq "CRITICAL") { "Red" } else { "Yellow" }
                Write-Host ("  [{0,-8}] {1,-28} | {2}" -f $t.Severity, $t.Type, $t.Detail) -ForegroundColor $color
            }

            if ($AudioAlert -or $AutoPanic) {
                try { [Console]::Beep(2000, 250) } catch {}
            }

            if ($AutoPanic) {
                Invoke-SentryDefensiveAction -Threats $allThreats -AutoPanic:$true
                break
            }
        } else {
            $gwTag = if ($baseGwMac) { "$baseGwIp ($baseGwMac)" } else { "VPN/Isolated" }
            Write-Host ("`r  [{0}] [SECURE] GW: {1} | USB: {2} | Sockets: Clean | Sensors: Idle (Cycle #{3})" -f $timestamp, $gwTag, $baseUsb.Count, $cycle) -ForegroundColor DarkGray -NoNewline
        }

        if ($SinglePass) {
            Write-Host ""
            return $allThreats
        }

        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.KeyChar -eq 'q' -or $key.Key -eq [ConsoleKey]::Escape) {
                Write-Host "`n`n  [+] Sentry disarmed by operator." -ForegroundColor Gray
                break
            }
        }

        Start-Sleep -Seconds $IntervalSec
    }
}

Export-ModuleMember -Function Audit-SentryPosture, Invoke-SentryMonitor, Test-ArpPoisoning, Test-PortScanActivity, Test-ActiveEavesdropping, Test-UsbPerimeter, Test-DnsHijack, Test-ReverseShellIntegrity, Test-WifiPerimeter
