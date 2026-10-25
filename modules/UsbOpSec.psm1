# UsbOpSec.psm1 - USB-Driven Tactical Execution & Hardware Shielding
# WinOpSec Apex Operations Security Platform

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

function Get-RunningDriveContext {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Get-Location }

    $driveLetter = [System.IO.Path]::GetPathRoot($scriptRoot).TrimEnd('\')
    $isUsb = $false
    $driveType = "Fixed"

    try {
        $drive = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.Name.TrimEnd('\') -ieq $driveLetter }
        if ($drive) {
            $driveType = $drive.DriveType.ToString()
            $isUsb = ($driveType -eq "Removable")
        }
    } catch {}

    $tag = if ($isUsb) {
        "USB (AIR-GAPPED EPHEMERAL)"
    } else {
        "HOST ($driveLetter LOCAL - TYPE 'usb deploy' TO MIGRATE)"
    }

    return [PSCustomObject]@{
        DriveLetter = $driveLetter
        IsUsb       = $isUsb
        DriveType   = $driveType
        Label       = $tag
    }
}

function Get-UsbDrives {
    [CmdletBinding()]
    param()

    $results = @()
    if (-not (Test-IsWindowsOS)) { return $results }

    try {
        $removables = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType.ToString() -eq "Removable" -and $_.IsReady }
        foreach ($d in $removables) {
            $drvLetter = $d.Name.TrimEnd('\')
            $bitLockerStatus = "Disabled/Unencrypted"

            try {
                $bdeOut = manage-bde -status $drvLetter 2>$null
                if ($bdeOut -match "Protection On") {
                    $bitLockerStatus = "BitLocker Locked (Protected)"
                } elseif ($bdeOut -match "Protection Off") {
                    $bitLockerStatus = "BitLocker Off"
                }
            } catch {}

            $results += [PSCustomObject]@{
                DriveLetter = $drvLetter
                VolumeLabel = if ($d.VolumeLabel) { $d.VolumeLabel } else { "(No Label)" }
                FileSystem  = $d.DriveFormat
                FreeGB      = [math]::Round($d.AvailableFreeSpace / 1GB, 2)
                TotalGB     = [math]::Round($d.TotalSize / 1GB, 2)
                BitLocker   = $bitLockerStatus
            }
        }
    } catch {}

    return $results
}

function Show-UsbInventory {
    [CmdletBinding()]
    param()

    Write-Host "`n  -- usb hardware storage inventory -----------------------------" -ForegroundColor DarkGray
    $drives = Get-UsbDrives
    if ($drives.Count -eq 0) {
        Write-Host "  no removable usb flash drives detected." -ForegroundColor DarkGray
        Write-Host "  insert a usb flash drive and run 'usb list' again.`n" -ForegroundColor DarkGray
        return
    }

    Write-Host "  found $($drives.Count) connected removable drive(s):`n" -ForegroundColor Gray
    $drives | Format-Table -Property DriveLetter, VolumeLabel, FileSystem, FreeGB, TotalGB, BitLocker -AutoSize
}

function Deploy-UsbOpSec {
    [CmdletBinding()]
    param(
        [string]$TargetDrive
    )

    $parent = Split-Path -Parent $PSScriptRoot

    $drives = Get-UsbDrives
    if ($drives.Count -eq 0) {
        Write-Host "`n  [!] no removable usb drives detected." -ForegroundColor Yellow
        Write-Host "  please insert a usb flash drive and try again.`n" -ForegroundColor DarkGray
        return
    }

    $selectedDrive = $TargetDrive
    if (-not $selectedDrive) {
        Write-Host "`n  -- select target usb flash drive for deployment ---------------" -ForegroundColor DarkGray
        for ($i = 0; $i -lt $drives.Count; $i++) {
            $d = $drives[$i]
            Write-Host "  [$($i + 1)] $($d.DriveLetter) ($($d.VolumeLabel) - $($d.FreeGB) GB free / $($d.TotalGB) GB) [$($d.BitLocker)]" -ForegroundColor White
        }
        Write-Host "  [0] Cancel" -ForegroundColor DarkGray
        Write-Host "`n  select drive [1-$($drives.Count)] > " -ForegroundColor Cyan -NoNewline
        $choice = (Read-Host).Trim()
        if ($choice -eq "0" -or -not $choice) {
            Write-Host "  deployment cancelled.`n" -ForegroundColor DarkGray
            return
        }

        $idx = [int]$choice - 1
        if ($idx -ge 0 -and $idx -lt $drives.Count) {
            $selectedDrive = $drives[$idx].DriveLetter
        } else {
            Write-Host "  invalid selection.`n" -ForegroundColor Red
            return
        }
    }

    $targetRoot = $selectedDrive.TrimEnd('\') + "\"
    $destFolder = Join-Path $targetRoot "WinOpSec"

    Write-Host "`n  [*] deploying portable winopsec to $destFolder..." -ForegroundColor DarkGray

    try {
        if (-not (Test-Path $destFolder)) {
            New-Item -ItemType Directory -Path $destFolder -Force | Out-Null
        }

        # 1. Copy core scripts and documentation
        foreach ($file in @("WinOpSec.ps1", "run.bat", "README.md", "LICENSE", ".gitignore")) {
            $src = Join-Path $parent $file
            if (Test-Path $src) {
                Copy-Item -LiteralPath $src -Destination (Join-Path $destFolder $file) -Force
            }
        }

        # 2. Copy modules
        $srcModules = Join-Path $parent "modules"
        $destModules = Join-Path $destFolder "modules"
        if (Test-Path $srcModules) {
            if (-not (Test-Path $destModules)) { New-Item -ItemType Directory -Path $destModules -Force | Out-Null }
            Copy-Item -LiteralPath "$srcModules\*" -Destination $destModules -Recurse -Force
        }

        # 3. Copy audio assets
        $srcAssets = Join-Path $parent "assets"
        $destAssets = Join-Path $destFolder "assets"
        if (Test-Path $srcAssets) {
            if (-not (Test-Path $destAssets)) { New-Item -ItemType Directory -Path $destAssets -Force | Out-Null }
            Copy-Item -LiteralPath "$srcAssets\*" -Destination $destAssets -Recurse -Force
        }

        # 4. Create root launcher shortcut on USB root for convenient double-click
        $usbLauncher = Join-Path $targetRoot "Run-WinOpSec.bat"
        $launcherContent = "@echo off" + [System.Environment]::NewLine + 'cd /d "%~dp0WinOpSec"' + [System.Environment]::NewLine + "call run.bat" + [System.Environment]::NewLine
        Set-Content -LiteralPath $usbLauncher -Value $launcherContent -Encoding ASCII -Force

        # 5. USB Malware Immunization (Blocks autorun.inf infection)
        $autorunPath = Join-Path $targetRoot "autorun.inf"
        if (-not (Test-Path $autorunPath)) {
            New-Item -ItemType Directory -Path $autorunPath -Force | Out-Null
            # Set Hidden + System + Read-Only to block malware overwrites
            attrib +s +h +r "$autorunPath" 2>$null | Out-Null
        }

        Write-Host "  ok  winopsec portable suite deployed to $destFolder" -ForegroundColor Green
        Write-Host "  ok  root launcher created: $usbLauncher" -ForegroundColor Green
        Write-Host "  ok  usb root immunized against autorun.inf worms" -ForegroundColor Green
        Write-Host "`n  [+] PORTABLE OPSEC READY. You can now run WinOpSec entirely from $selectedDrive!" -ForegroundColor Green
        Write-Host "      Safely unplug when done -- leaves zero software footprint on host drive.`n" -ForegroundColor Gray
    } catch {
        Write-Host "  [!] usb deployment failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Set-UsbWriteProtect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("on", "off", "status", "enable", "disable")]
        [string]$Action
    )

    if (-not (Test-IsWindowsOS)) { return }
    if (-not (Test-AdminPrivilege)) {
        Write-Host "  [!] Toggling USB write protection requires administrator privileges." -ForegroundColor Yellow
        return
    }

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"

    if ($Action -in @("on", "enable")) {
        try {
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "WriteProtect" -Type DWord -Value 1 -Force
            Write-Host "  ok  usb hardware write protection = ENABLED" -ForegroundColor Green
            Write-Host "      All inserted USB flash drives are now READ-ONLY (anti-data-exfiltration)." -ForegroundColor Gray
        } catch {
            Write-Host "  [!] failed to set write protection: $($_.Exception.Message)" -ForegroundColor Red
        }
    } elseif ($Action -in @("off", "disable")) {
        try {
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name "WriteProtect" -Type DWord -Value 0 -Force
            }
            Write-Host "  ok  usb hardware write protection = DISABLED (normal read/write restored)" -ForegroundColor Green
        } catch {
            Write-Host "  [!] failed to disable write protection: $($_.Exception.Message)" -ForegroundColor Red
        }
    } elseif ($Action -eq "status") {
        $val = 0
        if (Test-Path $regPath) {
            $prop = Get-ItemProperty -Path $regPath -Name "WriteProtect" -ErrorAction SilentlyContinue
            if ($prop -and $prop.WriteProtect -eq 1) { $val = 1 }
        }
        $statusStr = if ($val -eq 1) { "ENABLED (READ-ONLY PORTS)" } else { "DISABLED (NORMAL READ/WRITE)" }
        $statusColor = if ($val -eq 1) { "Green" } else { "DarkGray" }
        Write-Host "  USB Storage Write Protection: $statusStr" -ForegroundColor $statusColor
    }
}

Export-ModuleMember -Function Get-RunningDriveContext, Get-UsbDrives, Show-UsbInventory, Deploy-UsbOpSec, Set-UsbWriteProtect
