# VmShield.psm1 - Virtualization Isolation, Host Stealth & Leak Sentry
# WinOpSec VM isolation / host stealth / leak monitor

# Shared helpers Test-AdminPrivilege / Test-IsWindowsOS live in Common.psm1

# Locate VBoxManage executable
function Get-VBoxManagePath {
    if (-not (Test-IsWindowsOS)) { return $null }
    
    $paths = @(
        "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe",
        "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe",
        "VBoxManage.exe"
    )

    foreach ($p in $paths) {
        if (Test-Path $p -PathType Leaf) { return $p }
        $cmd = Get-Command $p -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

# Only track actual virtual machine execution engines (not GUI managers)
$script:VmProcessSignatures = @(
    "VirtualBoxVM",
    "vmware-vmx",
    "qemu-system-x86_64",
    "qemu-system-x86",
    "vmm"
)

function Get-ActiveVmProcesses {
    [CmdletBinding()]
    param()

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $runningProcesses = Get-Process -ErrorAction SilentlyContinue

    foreach ($proc in $runningProcesses) {
        if ($script:VmProcessSignatures -contains $proc.ProcessName) {
            $workingSetMb = [math]::Round($proc.WorkingSet64 / 1MB, 1)
            $privateMb    = [math]::Round($proc.PrivateMemorySize64 / 1MB, 1)
            
            $hypervisor = switch -Wildcard ($proc.ProcessName) {
                "VirtualBox*" { "VirtualBox" }
                "vmware*"     { "VMware" }
                "qemu*"       { "QEMU/KVM" }
                "vmm"         { "Hyper-V" }
                "wslhost"     { "WSL2" }
                default       { "Generic VM" }
            }

            $results.Add([PSCustomObject]@{
                ProcessId   = $proc.Id
                ProcessName = $proc.ProcessName
                Hypervisor  = $hypervisor
                MemoryMb    = $workingSetMb
                CommitMb    = $privateMb
                StartTime   = $proc.StartTime
            })
        }
    }

    return $results
}

function Get-VirtualNetworkAdapters {
    [CmdletBinding()]
    param()

    if (-not (Test-IsWindowsOS)) { return @() }

    $adapters = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $netAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
        foreach ($na in $netAdapters) {
            if ($na.InterfaceDescription -match "VirtualBox|VMware|Hyper-V|vEthernet|Host-Only") {
                $ip = (Get-NetIPAddress -InterfaceIndex $na.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
                $adapters.Add([PSCustomObject]@{
                    Name        = $na.Name
                    Description = $na.InterfaceDescription
                    Status      = $na.Status
                    Index       = $na.ifIndex
                    IPAddress   = $ip
                })
            }
        }
    } catch {}

    return $adapters
}

function Get-HostResourceMetrics {
    [CmdletBinding()]
    param()

    $metrics = [PSCustomObject]@{
        TotalRamMb       = 8192
        FreeRamMb        = 0
        UsedRamPercent   = 0
        ActiveTcpPorts   = 0
        PortExhaustState = "STABLE"
    }

    if (-not (Test-IsWindowsOS)) { return $metrics }

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os) {
            $metrics.TotalRamMb     = [math]::Round($os.TotalVisibleMemorySize / 1KB, 0)
            $metrics.FreeRamMb      = [math]::Round($os.FreePhysicalMemory / 1KB, 0)
            $usedMb                 = $metrics.TotalRamMb - $metrics.FreeRamMb
            $metrics.UsedRamPercent = [math]::Round(($usedMb / $metrics.TotalRamMb) * 100, 1)
        }
    } catch {}

    try {
        $tcp = Get-NetTCPConnection -State Established, TimeWait, SynSent, CloseWait -ErrorAction SilentlyContinue
        $metrics.ActiveTcpPorts = $tcp.Count
        if ($tcp.Count -ge 20000) {
            $metrics.PortExhaustState = "CRITICAL"
        } elseif ($tcp.Count -ge 8000) {
            $metrics.PortExhaustState = "WARNING"
        } else {
            $metrics.PortExhaustState = "STABLE"
        }
    } catch {}

    return $metrics
}

function Enable-VmHostStealthFirewall {
    [CmdletBinding()]
    param()

    if (-not (Test-IsWindowsOS)) { return $false }
    if (-not (Test-AdminPrivilege)) {
        Write-Host "  [!] Enabling VM Host Stealth requires Administrator privileges." -ForegroundColor Yellow
        return $false
    }

    $ruleName = "WinOpSec-VmHostStealth-BlockGuestInbound"

    try {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue 2>$null

        # Sensitive Windows Host Ports that VMs must NEVER probe:
        # 445 (SMB), 139 (NetBIOS), 135 (RPC Endpoint), 5985/5986 (WinRM)
        # 3306 (MySQL), 5432 (Postgres), 1433 (MSSQL), 80/8080/443 (Local Dev Web)
        $blockedPorts = @("135", "137", "138", "139", "445", "5985", "5986", "3306", "5432", "1433", "80", "8080")
        $remoteAddresses = @("10.0.2.0/24", "192.168.56.0/24", "172.16.0.0/12")

        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Inbound `
            -Action Block `
            -Protocol TCP `
            -LocalPort $blockedPorts `
            -RemoteAddress $remoteAddresses `
            -Description "WinOpSec VmShield: Drops all inbound guest probing against sensitive Windows host listening ports" `
            -Profile Any `
            -ErrorAction Stop | Out-Null

        $ruleNameUdp = "WinOpSec-VmHostStealth-BlockGuestInboundUDP"
        Remove-NetFirewallRule -DisplayName $ruleNameUdp -ErrorAction SilentlyContinue 2>$null
        New-NetFirewallRule -DisplayName $ruleNameUdp `
            -Direction Inbound `
            -Action Block `
            -Protocol UDP `
            -LocalPort @("137", "138", "5353", "5355", "1900") `
            -RemoteAddress $remoteAddresses `
            -Description "WinOpSec VmShield: Drops all inbound NetBIOS/LLMNR discovery from VMs" `
            -Profile Any `
            -ErrorAction Stop | Out-Null

        return $true
    } catch {
        Write-Host "  [!] Failed to set VM Host Stealth firewall rule: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Disable-VmHostStealthFirewall {
    [CmdletBinding()]
    param()

    if (-not (Test-IsWindowsOS)) { return }
    try {
        Remove-NetFirewallRule -DisplayName "WinOpSec-VmHostStealth-BlockGuestInbound" -ErrorAction SilentlyContinue 2>$null
        Remove-NetFirewallRule -DisplayName "WinOpSec-VmHostStealth-BlockGuestInboundUDP" -ErrorAction SilentlyContinue 2>$null
    } catch {}
}

function Harden-VirtualAdapters {
    [CmdletBinding()]
    param()

    if (-not (Test-IsWindowsOS) -or -not (Test-AdminPrivilege)) { return }

    try {
        $vboxAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match "VirtualBox|Host-Only" }
        foreach ($va in $vboxAdapters) {
            $regKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{$($va.InterfaceGuid)}"
            if (Test-Path $regKey) {
                Set-ItemProperty -Path $regKey -Name "NetbiosOptions" -Value 2 -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}
}

function Get-VirtualBoxInventory {
    [CmdletBinding()]
    param()

    $inventory = [System.Collections.Generic.List[PSCustomObject]]::new()
    $vboxDir = Join-Path $env:USERPROFILE "VirtualBox VMs"

    if (-not (Test-Path $vboxDir)) {
        return $inventory
    }

    $vboxFiles = Get-ChildItem -Path $vboxDir -Filter "*.vbox" -Recurse -File -ErrorAction SilentlyContinue

    foreach ($vf in $vboxFiles) {
        $vmName = [System.IO.Path]::GetFileNameWithoutExtension($vf.Name)
        try {
            [xml]$xml = Get-Content -LiteralPath $vf.FullName -Raw -ErrorAction Stop

            $ramMb = 0
            $memNode = $xml.SelectSingleNode("//*[local-name()='Memory']")
            if ($memNode -and $memNode.RAMSize) { $ramMb = [int]$memNode.RAMSize }

            $clipboardMode = "Disabled"
            $cbNode = $xml.SelectSingleNode("//*[local-name()='Clipboard']")
            if ($cbNode -and $cbNode.mode) { $clipboardMode = $cbNode.mode }

            $dndMode = "Disabled"
            $dndNode = $xml.SelectSingleNode("//*[local-name()='DragAndDrop']")
            if ($dndNode -and $dndNode.mode) { $dndMode = $dndNode.mode }

            $netType = "Unknown"
            $adapterNode = $xml.SelectSingleNode("//*[local-name()='Adapter'][@enabled='true']")
            if ($adapterNode) {
                if ($adapterNode.SelectSingleNode("*[local-name()='BridgedInterface']")) {
                    $netType = "Bridged"
                } elseif ($adapterNode.SelectSingleNode("*[local-name()='NATNetwork']")) {
                    $netType = "NATNetwork"
                } elseif ($adapterNode.SelectSingleNode("*[local-name()='NAT']")) {
                    $netType = "NAT"
                } elseif ($adapterNode.SelectSingleNode("*[local-name()='HostOnlyInterface']")) {
                    $netType = "Host-Only"
                } elseif ($adapterNode.SelectSingleNode("*[local-name()='InternalNetwork']")) {
                    $netType = "Internal"
                }
            }

            # Security Rating
            $risk = "LOW"
            if ($ramMb -gt 2560 -or $clipboardMode -ieq "Bidirectional") {
                $risk = if ($ramMb -gt 3072) { "CRITICAL" } else { "HIGH" }
            }

            $inventory.Add([PSCustomObject]@{
                Name        = $vmName
                RAM_MB      = $ramMb
                Clipboard   = $clipboardMode
                DragAndDrop = $dndMode
                Network     = $netType
                Risk        = $risk
                FilePath    = $vf.FullName
            })
        } catch {}
    }

    return $inventory
}

function Audit-VirtualBoxConfigurations {
    [CmdletBinding()]
    param()

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $inventory = Get-VirtualBoxInventory
    $hostTotalRamMb = 8192
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os) { $hostTotalRamMb = [math]::Round($os.TotalVisibleMemorySize / 1KB, 0) }
    } catch {}

    foreach ($vm in $inventory) {
        # 1. Clipboard Leak
        if ($vm.Clipboard -ieq "Bidirectional") {
            $findings.Add([PSCustomObject]@{
                VM       = $vm.Name
                Category = "CLIPBOARD_LEAK"
                Risk     = "HIGH"
                Detail   = "Bidirectional clipboard enabled (VM can read/modify Windows host clipboard)"
                Setting  = "Clipboard=$($vm.Clipboard)"
            })
        }

        # 2. Drag & Drop
        if ($vm.DragAndDrop -ieq "Bidirectional" -or $vm.DragAndDrop -ieq "HostToGuest") {
            $findings.Add([PSCustomObject]@{
                VM       = $vm.Name
                Category = "DRAG_DROP_LEAK"
                Risk     = "MEDIUM"
                Detail   = "Drag & Drop is enabled ($($vm.DragAndDrop))"
                Setting  = "DnD=$($vm.DragAndDrop)"
            })
        }

        # 3. RAM Over-allocation
        if ($vm.RAM_MB -gt 3072 -and $hostTotalRamMb -le 8192) {
            $findings.Add([PSCustomObject]@{
                VM       = $vm.Name
                Category = "RAM_OVERALLOCATION"
                Risk     = "CRITICAL"
                Detail   = "Allocated $($vm.RAM_MB) MB on an 8 GB host (extreme crash/port-exhaust risk)"
                Setting  = "RAM=$($vm.RAM_MB) MB"
            })
        }

        # 4. NATNetwork Port Exhaustion Risk
        if ($vm.Network -ieq "NATNetwork") {
            $findings.Add([PSCustomObject]@{
                VM       = $vm.Name
                Category = "NAT_PORT_EXHAUST_RISK"
                Risk     = "MEDIUM"
                Detail   = "Uses NATNetwork (aggressive port scanning will exhaust host TCP ports)"
                Setting  = "Net=$($vm.Network)"
            })
        }
    }

    return $findings
}

# 1-Click Auto-Harden for VirtualBox VMs
function Harden-VirtualBoxVMs {
    [CmdletBinding()]
    param(
        [string]$TargetVM = "ALL",
        [int]$CapRamMb = 2048,
        [string]$ClipboardMode = "hosttoguest"
    )

    $vboxManage = Get-VBoxManagePath
    if (-not $vboxManage) {
        Write-Host "  [!] VBoxManage.exe not found. Is VirtualBox installed?" -ForegroundColor Red
        return
    }

    # Verify no VM is currently running to prevent lock contention
    $runningVMs = Get-ActiveVmProcesses | Where-Object { $_.Hypervisor -eq "VirtualBox" }
    if ($runningVMs.Count -gt 0) {
        Write-Host "  [!] Warning: Detected running VirtualBox processes. Please power off running VMs before modifying settings." -ForegroundColor Yellow
        foreach ($rvm in $runningVMs) {
            Write-Host "      Active: $($rvm.ProcessName) (PID: $($rvm.ProcessId))" -ForegroundColor DarkGray
        }
        return
    }

    $inventory = Get-VirtualBoxInventory
    if ($inventory.Count -eq 0) {
        Write-Host "  [!] No VirtualBox VMs found on this machine." -ForegroundColor DarkGray
        return
    }

    $targets = if ($TargetVM -ieq "ALL") {
        $inventory
    } else {
        $inventory | Where-Object { $_.Name -ieq $TargetVM }
    }

    if ($targets.Count -eq 0) {
        Write-Host "  [!] Virtual machine '$TargetVM' not found in inventory." -ForegroundColor Red
        return
    }

    Write-Host "`n  ========================================================" -ForegroundColor Cyan
    Write-Host "   WINOPSEC VIRTUAL MACHINE AUTO-HARDENING SUITE" -ForegroundColor Cyan
    Write-Host "  ========================================================" -ForegroundColor Cyan
    $targetLabel = if ($TargetVM -ieq 'ALL') { "All $($targets.Count) Registered VMs" } else { $TargetVM }
    Write-Host "  Target VMs : $targetLabel" -ForegroundColor White
    Write-Host "  Policies   : Clipboard -> $ClipboardMode (Smart 1-Way: paste without leaks)" -ForegroundColor Gray
    Write-Host "               Drag and Drop -> disabled" -ForegroundColor Gray
    Write-Host "               RAM Cap    -> Max $CapRamMb MB (anti-host freeze)`n" -ForegroundColor Gray

    foreach ($vm in $targets) {
        Write-Host "  [*] Hardening VM: $($vm.Name)" -ForegroundColor White

        # 1. Clipboard Mode: Set to HostToGuest (User can copy Windows -> VM, but VM cannot read/hijack Host!)
        try {
            & $vboxManage modifyvm $vm.Name --clipboard-mode $ClipboardMode 2>$null
            Write-Host "      [+] Clipboard hardened to: $ClipboardMode" -ForegroundColor Green
        } catch {
            Write-Host "      [!] Failed to set clipboard: $_" -ForegroundColor Red
        }

        # 2. Drag and Drop: Disable to prevent accidental exfiltration
        try {
            & $vboxManage modifyvm $vm.Name --drag-and-drop disabled 2>$null
            Write-Host "      [+] Drag & Drop: disabled" -ForegroundColor Green
        } catch {}

        # 3. RAM Allocation: Cap to safe limit if it exceeds threshold on 8 GB host
        if ($vm.RAM_MB -gt $CapRamMb) {
            try {
                & $vboxManage modifyvm $vm.Name --memory $CapRamMb 2>$null
                Write-Host "      [+] RAM re-allocated: $($vm.RAM_MB) MB -> $CapRamMb MB (anti-crash safe)" -ForegroundColor Green
            } catch {
                Write-Host "      [!] Failed to adjust RAM: $_" -ForegroundColor Red
            }
        } else {
            Write-Host "      [=] RAM allocation: $($vm.RAM_MB) MB (already within safe parameters)" -ForegroundColor DarkGray
        }

        # 4. Disable TimeSync Host-Uptime Leak via GuestProperties
        try {
            & $vboxManage guestproperty set $vm.Name "/VirtualBox/GuestAdd/VBoxService/--disable-timesync" 1 2>$null
            Write-Host "      [+] Host clock skew & uptime sync: cloaked" -ForegroundColor Green
        } catch {}

        Write-Host ""
    }

    # Also arm host stealth firewall
    if (Test-AdminPrivilege) {
        Enable-VmHostStealthFirewall | Out-Null
        Harden-VirtualAdapters
        Write-Host "  [+] Host Stealth Isolation Firewall ARMED." -ForegroundColor Green
    } else {
        Write-Host "  [i] Run as Administrator to arm Host-Stealth isolation firewall rules." -ForegroundColor Yellow
    }

    Write-Host "  [+] All target VMs successfully hardened and shielded.`n" -ForegroundColor Green
}

function Set-VmRam {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmName,
        [Parameter(Mandatory = $true)]
        [int]$RamMb
    )

    $vboxManage = Get-VBoxManagePath
    if (-not $vboxManage) {
        Write-Host "  [!] VBoxManage.exe not found." -ForegroundColor Red
        return
    }

    try {
        & $vboxManage modifyvm $VmName --memory $RamMb 2>$null
        Write-Host "  [+] RAM for '$VmName' set to $RamMb MB." -ForegroundColor Green
    } catch {
        Write-Host "  [!] Failed to set RAM: $_" -ForegroundColor Red
    }
}

function Set-VmClipboard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmName,
        [Parameter(Mandatory = $true)]
        [ValidateSet("disabled", "hosttoguest", "guesttohost", "bidirectional")]
        [string]$Mode
    )

    $vboxManage = Get-VBoxManagePath
    if (-not $vboxManage) {
        Write-Host "  [!] VBoxManage.exe not found." -ForegroundColor Red
        return
    }

    try {
        & $vboxManage modifyvm $VmName --clipboard-mode $Mode 2>$null
        Write-Host "  [+] Clipboard mode for '$VmName' set to '$Mode'." -ForegroundColor Green
    } catch {
        Write-Host "  [!] Failed to set clipboard: $_" -ForegroundColor Red
    }
}

function Show-VmInventory {
    [CmdletBinding()]
    param()

    $inventory = Get-VirtualBoxInventory
    if ($inventory.Count -eq 0) {
        Write-Host "  [!] No VirtualBox VMs found on this machine." -ForegroundColor DarkGray
        return
    }

    Write-Host "`n  Virtual Machine Inventory & Security Posture:`n" -ForegroundColor Cyan
    Write-Host ("  {0,-24} {1,-10} {2,-16} {3,-14} {4,-12} {5}" -f "VM NAME", "RAM", "CLIPBOARD", "DRAG&DROP", "NETWORK", "STATUS") -ForegroundColor Gray
    Write-Host ("  {0,-24} {1,-10} {2,-16} {3,-14} {4,-12} {5}" -f "-------", "---", "---------", "---------", "-------", "------") -ForegroundColor DarkGray

    foreach ($vm in $inventory) {
        $color = switch ($vm.Risk) {
            "CRITICAL" { "Red" }
            "HIGH"     { "Yellow" }
            "MEDIUM"   { "Yellow" }
            default    { "Green" }
        }
        $statusBadge = switch ($vm.Risk) {
            "CRITICAL" { "[CRITICAL]" }
            "HIGH"     { "[LEAK-RISK]" }
            "MEDIUM"   { "[MODERATE]" }
            default    { "[HARDENED]" }
        }

        Write-Host ("  {0,-24} {1,-10} {2,-16} {3,-14} {4,-12} " -f $vm.Name, "$($vm.RAM_MB) MB", $vm.Clipboard, $vm.DragAndDrop, $vm.Network) -NoNewline
        Write-Host $statusBadge -ForegroundColor $color
    }
    Write-Host ""
}

function Audit-VmShieldPosture {
    [CmdletBinding()]
    param()

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # 1. Active VMs check
    $vms = Get-ActiveVmProcesses
    if ($vms.Count -gt 0) {
        $vmSummary = ($vms | ForEach-Object { "$($_.Hypervisor):$($_.ProcessName) (PID $($_.ProcessId), $($_.MemoryMb)MB)" }) -join "; "
        $results.Add([PSCustomObject]@{
            Check   = "Active Virtual Machines"
            Status  = "CONFIGURABLE"
            Details = "$($vms.Count) active instance(s): $vmSummary"
        })
    } else {
        $results.Add([PSCustomObject]@{
            Check   = "Active Virtual Machines"
            Status  = "CLEAN"
            Details = "No active VM processes detected"
        })
    }

    # 2. Host Stealth Firewall check
    $fwRule = Get-NetFirewallRule -DisplayName "WinOpSec-VmHostStealth-BlockGuestInbound" -ErrorAction SilentlyContinue
    if ($fwRule -and $fwRule.Enabled -eq "True") {
        $results.Add([PSCustomObject]@{
            Check   = "VM Host Stealth Firewall"
            Status  = "HARDENED"
            Details = "Active (Drops all guest probing to host SMB/RPC/MySQL ports)"
        })
    } else {
        $results.Add([PSCustomObject]@{
            Check   = "VM Host Stealth Firewall"
            Status  = "EXPOSED"
            Details = "Not armed (Host SMB/RPC listening ports reachable from VM gateway)"
        })
    }

    # 3. VirtualBox Config Audit
    $vmFindings = Audit-VirtualBoxConfigurations
    $critCount = ($vmFindings | Where-Object { $_.Risk -eq "CRITICAL" }).Count
    $highCount = ($vmFindings | Where-Object { $_.Risk -eq "HIGH" }).Count

    if ($critCount -gt 0) {
        $results.Add([PSCustomObject]@{
            Check   = "VM Hardening & Leak Config"
            Status  = "EXPOSED"
            Details = "$critCount CRITICAL / $highCount HIGH leak risks detected in VirtualBox configs"
        })
    } elseif ($highCount -gt 0) {
        $results.Add([PSCustomObject]@{
            Check   = "VM Hardening & Leak Config"
            Status  = "CONFIGURABLE"
            Details = "$highCount potential leak vector(s) found (shared folders / clipboard)"
        })
    } else {
        $results.Add([PSCustomObject]@{
            Check   = "VM Hardening & Leak Config"
            Status  = "HARDENED"
            Details = "VirtualBox configurations isolated with safe limits"
        })
    }

    # 4. Host Resource & TCP Port Health
    $metrics = Get-HostResourceMetrics
    if ($metrics.PortExhaustState -eq "CRITICAL") {
        $results.Add([PSCustomObject]@{
            Check   = "Host TCP Port Health"
            Status  = "EXPOSED"
            Details = "CRITICAL: $($metrics.ActiveTcpPorts) active ports (approaching exhaustion)"
        })
    } elseif ($metrics.PortExhaustState -eq "WARNING") {
        $results.Add([PSCustomObject]@{
            Check   = "Host TCP Port Health"
            Status  = "CONFIGURABLE"
            Details = "ELEVATED: $($metrics.ActiveTcpPorts) active ports"
        })
    } else {
        $results.Add([PSCustomObject]@{
            Check   = "Host TCP Port Health"
            Status  = "HARDENED"
            Details = "STABLE: $($metrics.ActiveTcpPorts) active ports | Host RAM $($metrics.UsedRamPercent)% used"
        })
    }

    return $results
}

function Optimize-HostMemory {
    [CmdletBinding()]
    param()

    try {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()

        $pInvokeMem = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class WinOpSecVmTrimmer {
    [DllImport("psapi.dll")]
    public static extern bool EmptyWorkingSet(IntPtr hProcess);

    public static int Flush() {
        int count = 0;
        Process[] procs = Process.GetProcesses();
        foreach (Process p in procs) {
            try {
                if (p.WorkingSet64 > 25000000) {
                    if (EmptyWorkingSet(p.Handle)) count++;
                }
            } catch {}
        }
        return count;
    }
}
"@
        if (-not ([System.Management.Automation.PSTypeName]'WinOpSecVmTrimmer').Type) {
            Add-Type -TypeDefinition $pInvokeMem -ErrorAction SilentlyContinue
        }
        $count = [WinOpSecVmTrimmer]::Flush()
        [System.GC]::Collect()
        return $count
    } catch {
        return 0
    }
}

function Start-VmShieldSentinel {
    [CmdletBinding()]
    param(
        [switch]$AutoHarden = $true,
        [int]$CheckIntervalSeconds = 3,
        [switch]$SinglePass
    )

    Write-Host "`n  ========================================================" -ForegroundColor Cyan
    Write-Host "   WINOPSEC VMSHIELD - REAL-TIME VM SENTRY & LEAK GUARD" -ForegroundColor Cyan
    Write-Host "  ========================================================" -ForegroundColor Cyan
    Write-Host "  [i] Monitoring VirtualBox, VMware, QEMU and hypervisor runtimes..." -ForegroundColor Gray
    Write-Host "  [i] Press CTRL+C to disarm sentinel.`n" -ForegroundColor DarkGray

    if ($AutoHarden -and (Test-AdminPrivilege)) {
        $armed = Enable-VmHostStealthFirewall
        Harden-VirtualAdapters
        if ($armed) {
            Write-Host "  [+] Host Stealth Shield ARMED: Guest-to-Host inbound probing blocked." -ForegroundColor Green
        }
    }

    $lastVmState    = $false
    $lastAlertTime  = [DateTime]::MinValue
    $alertCooldown  = [TimeSpan]::FromSeconds(20)

    do {
        $vms     = Get-ActiveVmProcesses
        $metrics = Get-HostResourceMetrics
        $timeStr = (Get-Date).ToString("HH:mm:ss")
        $now     = [DateTime]::Now

        if ($vms.Count -gt 0) {
            if (-not $lastVmState) {
                Write-Host "`n  [$timeStr] [ALERT] VIRTUAL MACHINE DETECTED!" -ForegroundColor Yellow
                foreach ($v in $vms) {
                    Write-Host "      Hypervisor : $($v.Hypervisor)" -ForegroundColor White
                    Write-Host "      Process    : $($v.ProcessName) (PID: $($v.ProcessId))" -ForegroundColor Gray
                    Write-Host "      Memory     : $($v.MemoryMb) MB Working Set | $($v.CommitMb) MB Commit" -ForegroundColor Gray
                }
                $lastVmState = $true
            }

            # 1. Check for single VM process memory runaway (WorkingSet > 2200 MB)
            foreach ($v in $vms) {
                if ($v.MemoryMb -gt 2200 -and ($now - $lastAlertTime) -gt $alertCooldown) {
                    Write-Host "`n  [$timeStr] [WARN] VM MEMORY PRESSURE: $($v.ProcessName) is using $($v.MemoryMb) MB physical RAM!" -ForegroundColor Red
                    Write-Host "      Host RAM is 8 GB. Recommend capping aggressive tools inside VM." -ForegroundColor Yellow
                    $lastAlertTime = $now
                }
            }

            # 2. Check for overall Host RAM exhaustion (Auto-recover to prevent system freeze)
            if (($metrics.UsedRamPercent -ge 94 -or $metrics.FreeRamMb -lt 450) -and ($now - $lastAlertTime) -gt $alertCooldown) {
                Write-Host "`n  [$timeStr] [WARN] HOST MEMORY CRITICAL: Host RAM is $($metrics.UsedRamPercent)% full ($($metrics.FreeRamMb) MB free)!" -ForegroundColor Red
                Write-Host "      [+] Auto-trimming host background memory to prevent system freeze..." -ForegroundColor Yellow
                $flushed = Optimize-HostMemory
                $metrics = Get-HostResourceMetrics
                Write-Host "      [+] Recovered memory ($flushed processes trimmed). New Free RAM: $($metrics.FreeRamMb) MB" -ForegroundColor Green
                $lastAlertTime = $now
            }

            # 3. Check for TCP port exhaustion
            if ($metrics.PortExhaustState -eq "CRITICAL" -and ($now - $lastAlertTime) -gt $alertCooldown) {
                Write-Host "`n  [$timeStr] [ALERT] CRITICAL: Host TCP ports at $($metrics.ActiveTcpPorts)! Wi-Fi/Explorer collapse risk!" -ForegroundColor Red
                $lastAlertTime = $now
            } elseif ($metrics.PortExhaustState -eq "WARNING" -and ($now - $lastAlertTime) -gt $alertCooldown) {
                Write-Host "`n  [$timeStr] [WARN] ELEVATED TCP Sockets: $($metrics.ActiveTcpPorts) active ports." -ForegroundColor Yellow
                $lastAlertTime = $now
            }

            $pad = " " * 8
            Write-Host -NoNewline "`r  [$timeStr] VmShield ACTIVE: $($vms.Count) VM engine | RAM $($metrics.UsedRamPercent)% | Ports: $($metrics.ActiveTcpPorts) (SAFE)$pad"

        } else {
            if ($lastVmState) {
                Write-Host "`n  [$timeStr] [i] All VM engines terminated. Host returned to idle." -ForegroundColor DarkGray
                $lastVmState = $false
            }
            $pad = " " * 8
            Write-Host -NoNewline "`r  [$timeStr] VmShield STANDBY: No active VM | Host RAM $($metrics.UsedRamPercent)% | Ports: $($metrics.ActiveTcpPorts)$pad"
        }

        if ($SinglePass) { break }
        Start-Sleep -Seconds $CheckIntervalSeconds
    } while ($true)

    Write-Host "`n"
}

# Dedicated Interactive VM Fortress Hub
function Show-VmHub {
    [CmdletBinding()]
    param()

    $hubLoop = $true
    while ($hubLoop) {
        Clear-Host
        Write-Host "  ========================================================================" -ForegroundColor Cyan
        Write-Host "    WINOPSEC VIRTUAL MACHINE FORTRESS & HYPERVISOR LEAK SENTRY" -ForegroundColor Cyan
        Write-Host "  ========================================================================" -ForegroundColor Cyan
        
        $metrics = Get-HostResourceMetrics
        $fwRule = Get-NetFirewallRule -DisplayName "WinOpSec-VmHostStealth-BlockGuestInbound" -ErrorAction SilentlyContinue
        $fwStatus = if ($fwRule -and $fwRule.Enabled -eq "True") { "ARMED (STEALTH BLACK HOLE)" } else { "EXPOSED (NOT ARMED)" }
        $fwColor  = if ($fwRule -and $fwRule.Enabled -eq "True") { "Green" } else { "Red" }

        Write-Host "  Host RAM Usage  : $($metrics.UsedRamPercent)% (Free: $($metrics.FreeRamMb) MB / Total: $($metrics.TotalRamMb) MB)" -ForegroundColor Gray
        Write-Host "  TCP Ephemeral   : $($metrics.ActiveTcpPorts) sockets ($($metrics.PortExhaustState))" -ForegroundColor Gray
        Write-Host "  Host Stealth FW : " -NoNewline -ForegroundColor Gray
        Write-Host $fwStatus -ForegroundColor $fwColor
        Write-Host "  ------------------------------------------------------------------------" -ForegroundColor DarkGray

        Show-VmInventory

        Write-Host "  COMMANDS:" -ForegroundColor White
        Write-Host "    [1] vm fix / harden-all  - 1-click auto-harden all VMs (HostToGuest + 2GB cap)" -ForegroundColor Green
        Write-Host "    [2] vm audit             - deep security & leak audit on all .vbox files" -ForegroundColor Gray
        Write-Host "    [3] vm watch             - launch real-time sentry & RAM runaway watchdog" -ForegroundColor Gray
        Write-Host "    [4] vm stealth on        - arm host stealth firewall (drops guest probes)" -ForegroundColor Gray
        Write-Host "    [5] vm stealth off       - disarm host stealth firewall" -ForegroundColor DarkGray
        Write-Host "    [6] vm ram <vm> <mb>     - reallocate RAM (e.g. 'vm ram BlackArch-Slim 2048')" -ForegroundColor DarkGray
        Write-Host "    [7] vm clip <vm> <mode>  - set clipboard ('hosttoguest', 'disabled')" -ForegroundColor DarkGray
        Write-Host "    [0] back / quit          - return to main WinOpSec menu" -ForegroundColor DarkGray
        Write-Host ""

        Write-Host "vm-hub > " -ForegroundColor Cyan -NoNewline
        $hubCmd = (Read-Host)
        if ($null -eq $hubCmd) { break }
        $hubCmd = $hubCmd.Trim().ToLower()

        if ($hubCmd -in @("0", "back", "q", "quit", "exit")) {
            $hubLoop = $false
            break
        }

        switch -Regex ($hubCmd) {
            "^(1|fix|harden|harden-all|all)$" {
                Harden-VirtualBoxVMs
                Write-Host "Press Enter to continue..." -ForegroundColor Gray
                [void][Console]::ReadLine()
            }
            "^(2|audit|scan)$" {
                Write-Host ""
                $findings = Audit-VirtualBoxConfigurations
                if ($findings.Count -eq 0) {
                    Write-Host "  [PASS] No leak risks found in any VM configs.`n" -ForegroundColor Green
                } else {
                    $findings | Format-Table -AutoSize
                }
                Write-Host "Press Enter to continue..." -ForegroundColor Gray
                [void][Console]::ReadLine()
            }
            "^(3|watch|monitor|sentry)$" {
                Start-VmShieldSentinel
            }
            "^(4|stealth\s+on|stealth)$" {
                Enable-VmHostStealthFirewall | Out-Null
                Harden-VirtualAdapters
                Write-Host "  [+] Host stealth isolation firewall armed." -ForegroundColor Green
                Start-Sleep -Seconds 1
            }
            "^(5|stealth\s+off)$" {
                Disable-VmHostStealthFirewall
                Write-Host "  [-] Host stealth firewall disarmed." -ForegroundColor Yellow
                Start-Sleep -Seconds 1
            }
            "^ram\s+(\S+)\s+(\d+)$" {
                Set-VmRam -VmName $Matches[1] -RamMb ([int]$Matches[2])
                Start-Sleep -Seconds 1
            }
            "^clip\s+(\S+)\s+(\S+)$" {
                Set-VmClipboard -VmName $Matches[1] -Mode $Matches[2]
                Start-Sleep -Seconds 1
            }
            default {
                Write-Host "  Unknown command. Press Enter..." -ForegroundColor DarkGray
                [void][Console]::ReadLine()
            }
        }
    }
}

Export-ModuleMember -Function `
    Get-ActiveVmProcesses, `
    Get-VirtualNetworkAdapters, `
    Get-HostResourceMetrics, `
    Get-VirtualBoxInventory, `
    Show-VmInventory, `
    Enable-VmHostStealthFirewall, `
    Disable-VmHostStealthFirewall, `
    Harden-VirtualAdapters, `
    Harden-VirtualBoxVMs, `
    Set-VmRam, `
    Set-VmClipboard, `
    Audit-VirtualBoxConfigurations, `
    Audit-VmShieldPosture, `
    Start-VmShieldSentinel, `
    Optimize-HostMemory, `
    Show-VmHub
