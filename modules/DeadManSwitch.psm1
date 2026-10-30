# Shared helpers Test-AdminPrivilege / Test-IsWindowsOS live in Common.psm1

function Get-ConnectedUsbDrives {
    $drives = @()
    if (Test-IsWindowsOS) {
        try {
            $disks = Get-CimInstance -ClassName Win32_DiskDrive -Filter "InterfaceType='USB'" -ErrorAction SilentlyContinue
            foreach ($d in $disks) {
                $partitions = Get-CimAssociatedInstance -InputObject $d -ResultClassName Win32_DiskPartition -ErrorAction SilentlyContinue
                foreach ($p in $partitions) {
                    $logicals = Get-CimAssociatedInstance -InputObject $p -ResultClassName Win32_LogicalDisk -ErrorAction SilentlyContinue
                    foreach ($l in $logicals) {
                        $drives += [PSCustomObject]@{
                            DeviceID   = $d.DeviceID
                            Model      = $d.Model
                            DriveLetter= $l.DeviceID
                            VolumeName = $l.VolumeName
                            SizeGB     = if ($l.Size) { [math]::Round($l.Size / 1GB, 2) } else { 0 }
                        }
                    }
                }
            }
        } catch {}
        if ($drives.Count -eq 0) {
            try {
                $removables = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue
                foreach ($r in $removables) {
                    $drives += [PSCustomObject]@{
                        DeviceID   = $r.DeviceID
                        Model      = "Removable USB Disk"
                        DriveLetter= $r.DeviceID
                        VolumeName = $r.VolumeName
                        SizeGB     = if ($r.Size) { [math]::Round($r.Size / 1GB, 2) } else { 0 }
                    }
                }
            } catch {}
        }
        if ($drives.Count -eq 0) {
            # .NET DriveInfo fallback (works under all privilege levels)
            try {
                $ioDrives = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType.ToString() -eq "Removable" -and $_.IsReady }
                foreach ($iod in $ioDrives) {
                    $drives += [PSCustomObject]@{
                        DeviceID   = $iod.Name.TrimEnd("\")
                        Model      = "Removable USB Drive"
                        DriveLetter= $iod.Name.TrimEnd("\")
                        VolumeName = $iod.VolumeLabel
                        SizeGB     = [math]::Round($iod.TotalSize / 1GB, 2)
                    }
                }
            } catch {}
        }
    }
    return $drives
}

function Invoke-DeadManSwitch {
    param(
        [string]$DriveLetter,
        [switch]$PowerOff
    )

    if (-not (Test-IsWindowsOS)) {
        Write-Host "  [!] USB Dead Man's Switch is supported on Windows hosts." -ForegroundColor Yellow
        return
    }

    Write-Host "`n  [!] Arming USB Dead Man's Switch (Buskill hardware defense)..." -ForegroundColor Red
    Write-Host "  threat model: Anti-Seizure / Glen Park Library Snatch Countermeasure" -ForegroundColor DarkGray

    $usbs = Get-ConnectedUsbDrives
    $targetDrive = $null

    if ($DriveLetter) {
        $targetLetter = $DriveLetter.TrimEnd(":").ToUpper() + ":"
        $targetDrive = $usbs | Where-Object { $_.DriveLetter -eq $targetLetter } | Select-Object -First 1
        if (-not $targetDrive) {
            $targetDrive = [PSCustomObject]@{
                DriveLetter = $targetLetter
                Model       = "Specified Drive $targetLetter"
            }
        }
    } else {
        if ($usbs.Count -eq 0) {
            Write-Host "`n  [!] No USB flash drives detected!" -ForegroundColor Yellow
            Write-Host "  Attach a USB flash drive (wrist lanyard trigger) to arm the switch." -ForegroundColor Gray
            Write-Host "  tip: you can specify any drive letter to monitor: deadman -drive E:" -ForegroundColor DarkGray
            return
        } elseif ($usbs.Count -eq 1) {
            $targetDrive = $usbs[0]
        } else {
            Write-Host "`n  Detected USB drives:" -ForegroundColor Cyan
            for ($i = 0; $i -lt $usbs.Count; $i++) {
                Write-Host "    [$i] $($usbs[$i].DriveLetter) - $($usbs[$i].Model) ($($usbs[$i].SizeGB) GB)" -ForegroundColor White
            }
            Write-Host "opsec:deadman> Select drive index [0-$($usbs.Count - 1)]: " -ForegroundColor Cyan -NoNewline
            $choice = Read-Host
            $idx = 0
            if ([int]::TryParse($choice, [ref]$idx) -and $idx -ge 0 -and $idx -lt $usbs.Count) {
                $targetDrive = $usbs[$idx]
            } else {
                $targetDrive = $usbs[0]
            }
        }
    }

    $armedLetter = $targetDrive.DriveLetter
    Write-Host "`n  [+] ARMED TRIGGER: Drive $armedLetter ($($targetDrive.Model))" -ForegroundColor Green
    Write-Host "  [i] Keep this USB attached to your wrist lanyard." -ForegroundColor Yellow
    Write-Host "  [i] If the USB is physically removed or laptop is snatched -> PANIC TRIGGERS IMMEDIATELY." -ForegroundColor Red
    Write-Host "  [i] Press [Ctrl+C] to disarm safely." -ForegroundColor DarkGray
    Write-Host "`n  [ACTIVE] Monitoring hardware bus every 200ms...`n" -ForegroundColor Cyan

    while ($true) {
        Start-Sleep -Milliseconds 200
        $stillConnected = Test-Path $armedLetter -ErrorAction SilentlyContinue
        if (-not $stillConnected) {
            Write-Host "`n`n  [CRITICAL ALERT] USB DISCONNECTED! TRIGGERING EMERGENCY PANIC..." -ForegroundColor Red
            if (Get-Command Invoke-PanicProtocol -ErrorAction SilentlyContinue) {
                Invoke-PanicProtocol -PowerOff:$PowerOff
            } else {
                rundll32.exe user32.dll,LockWorkStation
            }
            break
        }
    }
}

Export-ModuleMember -Function Get-ConnectedUsbDrives, Invoke-DeadManSwitch
