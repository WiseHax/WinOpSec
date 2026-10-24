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

function Get-UserHome {
    if ($HOME) { return $HOME }
    if ($env:USERPROFILE) { return $env:USERPROFILE }
    return [Environment]::GetFolderPath("UserProfile")
}

function Get-PSHistoryFile {
    if (Test-IsWindowsOS) {
        return "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    }
    $uHome = Get-UserHome
    return Join-Path $uHome ".local/share/powershell/PSReadLine/ConsoleHost_history.txt"
}

function Audit-Traces {
    $results = @()
    $psHistoryPath = Get-PSHistoryFile
    $psCount = 0
    if (Test-Path $psHistoryPath -ErrorAction SilentlyContinue) {
        $lines = Get-Content $psHistoryPath -ErrorAction SilentlyContinue
        if ($lines) { $psCount = @($lines).Count }
    }
    $results += [PSCustomObject]@{
        Artifact = "PSReadLine History"
        Location = $psHistoryPath
        Count    = "$psCount lines"
        Status   = if ($psCount -eq 0) { "CLEAN" } else { "EXPOSED" }
    }

    if (Test-IsWindowsOS) {
        $runMruCount = 0
        if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") {
            $props = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue
            if ($props) {
                $runMruCount = ($props.PSObject.Properties | Where-Object { $_.Name -match "^[a-z]$" }).Count
            }
        }
        $results += [PSCustomObject]@{
            Artifact = "Explorer RunMRU"
            Location = "HKCU:\...\Explorer\RunMRU"
            Count    = "$runMruCount entries"
            Status   = if ($runMruCount -eq 0) { "CLEAN" } else { "EXPOSED" }
        }

        $autoDest = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
        $custDest = "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
        $jumpCount = 0
        if (Test-Path $autoDest -ErrorAction SilentlyContinue) { $jumpCount += @(Get-ChildItem -Path $autoDest -Force -ErrorAction SilentlyContinue).Count }
        if (Test-Path $custDest -ErrorAction SilentlyContinue) { $jumpCount += @(Get-ChildItem -Path $custDest -Force -ErrorAction SilentlyContinue).Count }
        $results += [PSCustomObject]@{
            Artifact = "Explorer JumpLists"
            Location = "$env:APPDATA\...\Recent"
            Count    = "$jumpCount files"
            Status   = if ($jumpCount -eq 0) { "CLEAN" } else { "EXPOSED" }
        }

        $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
        $recentCount = 0
        if (Test-Path $recentPath -ErrorAction SilentlyContinue) {
            $recentCount = @(Get-ChildItem -Path $recentPath -Filter "*.lnk" -Force -ErrorAction SilentlyContinue).Count
        }
        $results += [PSCustomObject]@{
            Artifact = "Recent Docs (.lnk)"
            Location = $recentPath
            Count    = "$recentCount links"
            Status   = if ($recentCount -eq 0) { "CLEAN" } else { "EXPOSED" }
        }

        $dumpCount = 0
        foreach ($dp in @("$env:LOCALAPPDATA\CrashDumps", "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportArchive", "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportQueue")) {
            if (Test-Path $dp -ErrorAction SilentlyContinue) {
                $dumpCount += @(Get-ChildItem -Path $dp -Force -Recurse -File -ErrorAction SilentlyContinue).Count
            }
        }
        $results += [PSCustomObject]@{
            Artifact = "WER & Crash Dumps"
            Location = "$env:LOCALAPPDATA\CrashDumps"
            Count    = "$dumpCount files"
            Status   = if ($dumpCount -eq 0) { "CLEAN" } else { "EXPOSED" }
        }

        # Program Compatibility Assistant (PCA) Plaintext Execution Log
        $pcaDic = "C:\Windows\appcompat\pca\PcaAppLaunchDic.txt"
        $pcaCount = 0
        if (Test-Path $pcaDic -ErrorAction SilentlyContinue) {
            $pcaLines = Get-Content $pcaDic -ErrorAction SilentlyContinue
            if ($pcaLines) { $pcaCount = @($pcaLines).Count }
        }
        $results += [PSCustomObject]@{
            Artifact = "PCA App Execution Log"
            Location = "C:\Windows\appcompat\pca\..."
            Count    = "$pcaCount entries"
            Status   = if ($pcaCount -eq 0) { "CLEAN" } else { "EXPOSED" }
        }

        # Explorer ShellBags (Folder Navigation Archaeology)
        $sbCount = 0
        foreach ($sbKey in @(
            "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
            "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"
        )) {
            if (Test-Path $sbKey) {
                $sbCount += @(Get-ChildItem -Path $sbKey -Recurse -ErrorAction SilentlyContinue).Count
            }
        }
        $results += [PSCustomObject]@{
            Artifact = "Explorer ShellBags"
            Location = "HKCU:\...\Shell\BagMRU"
            Count    = "$sbCount records"
            Status   = if ($sbCount -eq 0) { "CLEAN" } else { "EXPOSED" }
        }

        # Event ID 1102 Anti-Forensics Audit (Log Clearing Proof)
        $clearedProofCount = 0
        try {
            $ev1102 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 5 -ErrorAction SilentlyContinue
            if ($ev1102) { $clearedProofCount = @($ev1102).Count }
        } catch {}
        $results += [PSCustomObject]@{
            Artifact = "EventLog Tamper Proof (1102)"
            Location = "Security Log (Event 1102)"
            Count    = if ($clearedProofCount -gt 0) { "$clearedProofCount log-wipe events" } else { "0 events (clean)" }
            Status   = if ($clearedProofCount -eq 0) { "CLEAN" } else { "EXPOSED" }
        }

        # Registry Transaction Journals (.LOG1, .LOG2, .regtrans-ms)
        $regLogSize = 0
        $regLogs = @(Get-ChildItem "$env:USERPROFILE", "$env:LOCALAPPDATA\Microsoft\Windows" -Filter "*.LOG*" -Force -ErrorAction SilentlyContinue)
        if ($regLogs.Count -gt 0) {
            $regLogSize = [math]::Round(($regLogs | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
        }
        $results += [PSCustomObject]@{
            Artifact = "Registry Transaction Logs"
            Location = "NTUSER.DAT / UsrClass .LOG*"
            Count    = "$regLogSize MB ($($regLogs.Count) journals)"
            Status   = if ($regLogSize -eq 0) { "CLEAN" } else { "EXPOSED" }
        }
    } else {
        $uHome = Get-UserHome
        foreach ($shFile in @(".bash_history", ".zsh_history", ".python_history", ".lesshst")) {
            $p = Join-Path $uHome $shFile
            $cnt = 0
            if (Test-Path $p -ErrorAction SilentlyContinue) {
                $l = Get-Content $p -ErrorAction SilentlyContinue
                if ($l) { $cnt = @($l).Count }
            }
            $results += [PSCustomObject]@{
                Artifact = $shFile
                Location = $p
                Count    = "$cnt lines"
                Status   = if ($cnt -eq 0) { "CLEAN" } else { "EXPOSED" }
            }
        }
    }

    return $results
}

function Shred-FileSecurely {
    param([string]$FilePath)
    if (Test-Path $FilePath -ErrorAction SilentlyContinue) {
        try {
            $len = (Get-Item $FilePath -Force -ErrorAction Stop).Length
            if ($len -gt 0 -and $len -lt 50MB) {
                $zeroes = [byte[]]::new($len)
                [System.IO.File]::WriteAllBytes($FilePath, $zeroes)
            }
            Remove-Item -Path $FilePath -Force -ErrorAction Stop
            return $true
        } catch {
            return $false
        }
    }
    return $false
}

function Shred-PowerShellHistory {
    try {
        Set-PSReadLineOption -HistorySaveStyle SaveNothing -ErrorAction SilentlyContinue
        [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
    } catch {}

    $psHistoryPath = Get-PSHistoryFile
    if (Test-Path $psHistoryPath -ErrorAction SilentlyContinue) {
        if (Shred-FileSecurely -FilePath $psHistoryPath) {
            Write-Host "  ok  shredded $psHistoryPath" -ForegroundColor Green
        } else {
            Write-Host "  !!  failed to shred $psHistoryPath" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  ok  psreadline history clean (disk logging disabled)" -ForegroundColor Green
    }

    $uHome = Get-UserHome
    foreach ($shFile in @(".bash_history", ".zsh_history", ".python_history", ".node_repl_history", ".lesshst", ".viminfo", ".wget-hsts")) {
        $p = Join-Path $uHome $shFile
        if (Test-Path $p -ErrorAction SilentlyContinue) {
            if (Shred-FileSecurely -FilePath $p) {
                Write-Host "  ok  shredded $p" -ForegroundColor Green
            }
        }
    }
}

function Clear-ExplorerTraces {
    if (Test-IsWindowsOS) {
        $runMruPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        if (Test-Path $runMruPath) {
            Get-ItemProperty -Path $runMruPath | ForEach-Object {
                $props = $_.PSObject.Properties | Where-Object { $_.Name -match "^[a-z]$" -or $_.Name -eq "MRUList" }
                foreach ($p in $props) {
                    Remove-ItemProperty -Path $runMruPath -Name $p.Name -ErrorAction SilentlyContinue
                }
            }
            Write-Host "  ok  cleared Explorer\RunMRU" -ForegroundColor Green
        }

        foreach ($regSub in @("TypedPaths", "WordWheelQuery", "RecentDocs", "ComDlg32\OpenSavePidlMRU", "ComDlg32\LastVisitedPidlMRU")) {
            $fullReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\$regSub"
            if (Test-Path $fullReg) {
                Remove-Item -Path $fullReg -Recurse -Force -ErrorAction SilentlyContinue
                New-Item -Path $fullReg -Force | Out-Null
            }
        }

        # Wipe UserAssist ROT13 execution history
        $uaPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        if (Test-Path $uaPath) {
            Get-ChildItem -Path $uaPath -ErrorAction SilentlyContinue | ForEach-Object {
                $countKey = Join-Path $_.PSPath "Count"
                if (Test-Path $countKey) {
                    Remove-Item -Path $countKey -Recurse -Force -ErrorAction SilentlyContinue
                    New-Item -Path $countKey -Force | Out-Null
                }
            }
        }
        Write-Host "  ok  cleared TypedPaths, SearchMRU, ComDlg32 & UserAssist ROT13 logs" -ForegroundColor Green

        # Wipe Explorer JumpLists (handling hidden/system file attributes)
        foreach ($folder in @("AutomaticDestinations", "CustomDestinations")) {
            $destPath = Join-Path $env:APPDATA "Microsoft\Windows\Recent\$folder"
            if (Test-Path $destPath) {
                Get-ChildItem -Path $destPath -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        $_.Attributes = [System.IO.FileAttributes]::Normal
                        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                    } catch {}
                }
            }
        }
        Write-Host "  ok  wiped Explorer JumpLists" -ForegroundColor Green

        # Wipe Recent Items (.lnk shortcuts)
        $recentDir = "$env:APPDATA\Microsoft\Windows\Recent"
        if (Test-Path $recentDir) {
            Get-ChildItem -Path $recentDir -Filter "*.lnk" -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $_.Attributes = [System.IO.FileAttributes]::Normal
                    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                } catch {}
            }
        }
        Write-Host "  ok  wiped Recent Items (.lnk)" -ForegroundColor Green

        # Permanently disable Windows from tracking & recording future JumpLists & Recent Docs
        $expPolicy = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $expPolicy)) { New-Item -Path $expPolicy -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $expPolicy -Name "NoRecentDocsHistory" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $expPolicy -Name "ClearRecentDocsOnExit" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue

        $expAdv = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        if (-not (Test-Path $expAdv)) { New-Item -Path $expAdv -Force -ErrorAction SilentlyContinue | Out-Null }
        Set-ItemProperty -Path $expAdv -Name "Start_TrackDocs" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $expAdv -Name "Start_TrackProgs" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue

        # Purge Windows Prefetch execution logs
        $prefetchDir = "C:\Windows\Prefetch"
        if (Test-Path $prefetchDir) {
            Get-ChildItem -Path $prefetchDir -Filter "*.pf" -Force -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
            }
            Write-Host "  ok  purged Windows Prefetch execution history (*.pf)" -ForegroundColor Green
        }

        # Purge Windows Timeline ActivitiesCache
        $cdpDir = "$env:LOCALAPPDATA\ConnectedDevicesPlatform"
        if (Test-Path $cdpDir) {
            Get-ChildItem -Path $cdpDir -Filter "ActivitiesCache.db*" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
            }
            Write-Host "  ok  purged Windows Timeline ActivitiesCache.db" -ForegroundColor Green
        }

        # Purge Windows 11 Program Compatibility Assistant (PCA) plaintext execution logs
        Invoke-PcaWipe

        # Purge Explorer ShellBags (BagMRU & Bags folder navigation histories)
        Invoke-ShellBagsSanitize

        # Clear Kernel ShimCache (AppCompatCache) & BAM (Background Activity Moderator)
        try {
            $shimKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
            if (Test-Path $shimKey) {
                Set-ItemProperty -Path $shimKey -Name "AppCompatCache" -Value ([byte[]]@()) -ErrorAction SilentlyContinue
                Write-Host "  ok  cleared kernel AppCompatCache (ShimCache)" -ForegroundColor Green
            }
        } catch {}

        try {
            $bamKey = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
            if (Test-Path $bamKey) {
                Get-ChildItem -Path $bamKey -ErrorAction SilentlyContinue | ForEach-Object {
                    $props = (Get-ItemProperty -Path $_.PSPath).PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
                    foreach ($pr in $props) {
                        Remove-ItemProperty -Path $_.PSPath -Name $pr.Name -ErrorAction SilentlyContinue
                    }
                }
                Write-Host "  ok  cleared BAM (Background Activity Moderator) process history" -ForegroundColor Green
            }
        } catch {}

        foreach ($dp in @("$env:LOCALAPPDATA\CrashDumps", "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportArchive", "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportQueue", "$env:ProgramData\Microsoft\Windows\WER\ReportArchive", "$env:ProgramData\Microsoft\Windows\WER\ReportQueue")) {
            if (Test-Path $dp -ErrorAction SilentlyContinue) {
                Get-ChildItem -Path $dp -Force -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                    Shred-FileSecurely -FilePath $_.FullName | Out-Null
                }
            }
        }
        Write-Host "  ok  shredded WER reports & user crash dumps" -ForegroundColor Green

        # Purge Windows Snipping Tool & ScreenSketch image caches
        Invoke-ScreenshotCacheWipe

        # Strip NTFS Zone.Identifier ADS (download origin URLs) from Downloads & Desktop
        $uHome = Get-UserHome
        $adsCount = 0
        foreach ($dir in @((Join-Path $uHome "Downloads"), (Join-Path $uHome "Desktop"))) {
            if (Test-Path $dir -ErrorAction SilentlyContinue) {
                Get-ChildItem -Path $dir -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        if (Get-Item -Path $_.FullName -Stream "Zone.Identifier" -ErrorAction SilentlyContinue) {
                            Remove-Item -Path $_.FullName -Stream "Zone.Identifier" -Force -ErrorAction Stop
                            $adsCount++
                        }
                    } catch {}
                }
            }
        }
        Write-Host "  ok  stripped $adsCount NTFS Zone.Identifier origin streams" -ForegroundColor Green

        try {
            Set-Clipboard -Value $null -ErrorAction SilentlyContinue
            Write-Host "  ok  flushed clipboard memory buffer" -ForegroundColor Green
        } catch {}

        try {
            if (Get-Command Clear-DnsClientCache -ErrorAction SilentlyContinue) {
                Clear-DnsClientCache -ErrorAction SilentlyContinue
            }
            nbtstat -R 2>$null | Out-Null
            Write-Host "  ok  flushed DNS & NetBIOS resolver caches" -ForegroundColor Green
        } catch {}
    } else {
        $uHome = Get-UserHome
        $recentXbel = Join-Path $uHome ".local/share/recently-used.xbel"
        if (Test-Path $recentXbel -ErrorAction SilentlyContinue) {
            Shred-FileSecurely -FilePath $recentXbel | Out-Null
            Write-Host "  ok  shredded $recentXbel" -ForegroundColor Green
        }
        if ($IsMacOS) {
            "" | pbcopy 2>$null
            dscacheutil -flushcache 2>$null
            Write-Host "  ok  flushed pbcopy & dscacheutil" -ForegroundColor Green
        } else {
            resolvectl flush-caches 2>$null
            Write-Host "  ok  flushed local resolver cache" -ForegroundColor Green
        }
    }
}

function Invoke-PcaWipe {
    if (-not (Test-IsWindowsOS)) { return }
    try {
        # Stop and disable PcaSvc service
        sc.exe stop PcaSvc 2>$null | Out-Null
        $pcaKey = "HKLM:\SYSTEM\CurrentControlSet\Services\PcaSvc"
        if (Test-Path $pcaKey) {
            Set-ItemProperty -Path $pcaKey -Name "Start" -Type DWord -Value 4 -Force -ErrorAction SilentlyContinue
        }

        # Shred plaintext execution logs
        $pcaDir = "C:\Windows\appcompat\pca"
        if (Test-Path $pcaDir) {
            foreach ($pcaFile in @("PcaAppLaunchDic.txt", "PcaGeneralDb0.txt", "PcaGeneralDb1.txt")) {
                $fullPath = Join-Path $pcaDir $pcaFile
                if (Test-Path $fullPath) {
                    try {
                        [System.IO.File]::WriteAllBytes($fullPath, [byte[]]@())
                        Remove-Item -Path $fullPath -Force -ErrorAction SilentlyContinue
                    } catch {}
                    # Recreate as locked 0-byte dummy file
                    try {
                        New-Item -Path $fullPath -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
                        Set-ItemProperty -Path $fullPath -Name Attributes -Value ([System.IO.FileAttributes]::ReadOnly) -ErrorAction SilentlyContinue
                    } catch {}
                }
            }
            Write-Host "  ok  purged PCA plaintext launch dictionaries & enforced zero-byte lockdown" -ForegroundColor Green
        }
    } catch {
        Write-Host "  !!  pca purge failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Invoke-ShellBagsSanitize {
    if (-not (Test-IsWindowsOS)) { return }
    $shellBagPaths = @(
        "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
        "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
        "HKCU:\Software\Microsoft\Windows\Shell\BagMRU",
        "HKCU:\Software\Microsoft\Windows\Shell\Bags"
    )
    foreach ($sb in $shellBagPaths) {
        if (Test-Path $sb) {
            try {
                Remove-Item -Path $sb -Recurse -Force -ErrorAction SilentlyContinue
                New-Item -Path $sb -Force -ErrorAction SilentlyContinue | Out-Null
            } catch {}
        }
    }
    Write-Host "  ok  purged Explorer ShellBags (BagMRU & Bags folder navigation histories)" -ForegroundColor Green
}

function Invoke-SrumNeutralize {
    if (-not (Test-IsWindowsOS)) { return }
    if (-not (Test-AdminPrivilege)) {
        Write-Host "  [!] SRUM neutralization requires administrator privileges." -ForegroundColor Yellow
        return
    }
    Write-Host "  -- neutralizing System Resource Usage Monitor (SRUM)..." -ForegroundColor Cyan
    try {
        sc.exe stop DPS 2>$null | Out-Null
        $dpsKey = "HKLM:\SYSTEM\CurrentControlSet\Services\DPS"
        if (Test-Path $dpsKey) {
            Set-ItemProperty -Path $dpsKey -Name "Start" -Type DWord -Value 4 -Force -ErrorAction SilentlyContinue
        }

        $sruDir = "C:\Windows\System32\sru"
        if (Test-Path $sruDir) {
            Get-ChildItem -Path $sruDir -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    [System.IO.File]::WriteAllBytes($_.FullName, [byte[]]@())
                    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                } catch {}
            }
            Write-Host "  ok  purged SRUM database (SRUDB.dat) & transaction logs (network/app execution telemetry)" -ForegroundColor Green
        }
    } catch {
        Write-Host "  !!  SRUM neutralization failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Invoke-SearchIndexWipe {
    if (-not (Test-IsWindowsOS)) { return }
    if (-not (Test-AdminPrivilege)) {
        Write-Host "  [!] Search index wiping requires administrator privileges." -ForegroundColor Yellow
        return
    }
    Write-Host "  -- purging Windows Search database (Windows.edb)..." -ForegroundColor Cyan
    try {
        sc.exe stop WSearch 2>$null | Out-Null
        $edbPath = "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"
        if (Test-Path $edbPath) {
            try {
                [System.IO.File]::WriteAllBytes($edbPath, [byte[]]@())
                Remove-Item -Path $edbPath -Force -ErrorAction SilentlyContinue
            } catch {}
            Write-Host "  ok  purged Windows.edb search index (deleted file carving defense)" -ForegroundColor Green
        }
    } catch {
        Write-Host "  !!  Search index purge failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Invoke-MetadataScrub {
    param([string]$TargetPath)
    if (-not $TargetPath -or -not (Test-Path $TargetPath)) {
        Write-Host "  usage: scrub <file_or_directory_path>" -ForegroundColor Yellow
        return
    }

    $items = if ((Get-Item $TargetPath).PSIsContainer) {
        Get-ChildItem -Path $TargetPath -File -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        @(Get-Item $TargetPath -Force)
    }

    $uniformTime = [DateTime]::new(2025, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    $scrubbed = 0

    foreach ($file in $items) {
        try {
            # 1. Strip NTFS Alternate Data Streams (Zone.Identifier, etc.)
            if (Test-IsWindowsOS) {
                Remove-Item -Path $file.FullName -Stream "Zone.Identifier" -Force -ErrorAction SilentlyContinue
            }

            # 2. Strip EXIF properties from JPEG/PNG via clean bitmap re-encode
            if ($file.Extension -match "^\.(jpg|jpeg|png)$") {
                try {
                    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
                    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
                    $msIn = New-Object System.IO.MemoryStream(,$bytes)
                    $img = [System.Drawing.Image]::FromStream($msIn)
                    $cleanBmp = New-Object System.Drawing.Bitmap($img.Width, $img.Height, $img.PixelFormat)
                    $g = [System.Drawing.Graphics]::FromImage($cleanBmp)
                    $g.DrawImage($img, 0, 0, $img.Width, $img.Height)
                    $g.Dispose()
                    $img.Dispose()
                    $msIn.Dispose()

                    $fmt = if ($file.Extension -match "png") { [System.Drawing.Imaging.ImageFormat]::Png } else { [System.Drawing.Imaging.ImageFormat]::Jpeg }
                    $cleanBmp.Save($file.FullName, $fmt)
                    $cleanBmp.Dispose()
                } catch {}
            }

            # 3. Normalize MACB timestamps (defeats timeline correlation)
            $file.CreationTimeUtc   = $uniformTime
            $file.LastWriteTimeUtc  = $uniformTime
            $file.LastAccessTimeUtc = $uniformTime
            $scrubbed++
        } catch {}
    }

    Write-Host "  ok  scrubbed metadata/ADS & normalized timestamps on $scrubbed file(s)." -ForegroundColor Green
}

function Clear-WindowsEventLogs {
    if (-not (Test-AdminPrivilege)) {
        Write-Host "  [!] Clearing Windows Event Logs requires administrator privileges." -ForegroundColor Yellow
        return
    }
    Write-Host "  -- clearing all Windows event log channels (wevtutil)..." -ForegroundColor Cyan
    try {
        $logs = @(wevtutil el 2>$null)
        $cleared = 0
        foreach ($l in $logs) {
            if ($l) {
                wevtutil cl "$l" 2>$null
                $cleared++
            }
        }
        Write-Host "  ok  purged $cleared Windows event log channels (Security, System, App, ScriptBlock, Network)" -ForegroundColor Green
    } catch {}
}

function Invoke-StealthEventLogBlind {
    if (-not (Test-AdminPrivilege)) {
        Write-Host "  [!] Stealth event log blinding requires administrator privileges." -ForegroundColor Yellow
        return
    }
    Write-Host "  -- configuring stealth circular log aging (defeats Event ID 1102 smoking gun)..." -ForegroundColor Cyan
    try {
        $channels = @("Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-WLAN-AutoConfig/Operational")
        $configured = 0
        foreach ($ch in $channels) {
            wevtutil sl "$ch" /ms:1048576 /rt:false /ab:true 2>$null | Out-Null
            $configured++
        }
        Write-Host "  ok  locked $configured core event log buffers to 1MB circular aging (traces overwrite without generating 1102)" -ForegroundColor Green
    } catch {
        Write-Host "  !!  log blinding failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Invoke-TokenSanitize {
    param([switch]$Total)
    Write-Host "  -- neutralizing desktop messenger & communication auth sessions..." -ForegroundColor Cyan

    $targets = @(
        @{ Name = "Telegram Desktop (tdata)"; Path = "$env:APPDATA\Telegram Desktop\tdata" },
        @{ Name = "Discord Session Storage"; Path = "$env:APPDATA\discord\Session Storage" },
        @{ Name = "Discord Local Storage"; Path = "$env:APPDATA\discord\Local Storage\leveldb" },
        @{ Name = "Signal Auth Storage"; Path = "$env:APPDATA\Signal\sql" },
        @{ Name = "Slack Session Storage"; Path = "$env:APPDATA\Slack\Local Storage" }
    )

    $purged = 0
    foreach ($t in $targets) {
        if (Test-Path $t.Path) {
            try {
                if ($t.Name -match "Telegram") {
                    # Shred Telegram auth session files (D877F783D5D3EF8C*, user_data*, key_datas*)
                    Get-ChildItem -Path $t.Path -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^(D877|user_data|key_datas)" } | ForEach-Object {
                        [System.IO.File]::WriteAllBytes($_.FullName, [byte[]]@())
                        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                    }
                } else {
                    Get-ChildItem -Path $t.Path -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        [System.IO.File]::WriteAllBytes($_.FullName, [byte[]]@())
                        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
                Write-Host "  ok  purged $($t.Name)" -ForegroundColor Green
                $purged++
            } catch {}
        }
    }

    if ($purged -eq 0) {
        Write-Host "  ok  no active messenger auth sessions detected on host" -ForegroundColor Green
    } else {
        Write-Host "  ok  neutralized $purged communication session stores (defeats post-seizure chat hijack)" -ForegroundColor Green
    }
}

function Invoke-ScreenshotCacheWipe {
    Write-Host "  -- scrubbing Windows Snipping Tool & ScreenSketch temporary buffers..." -ForegroundColor Cyan

    $scrPaths = @(
        "$env:LOCALAPPDATA\Packages\Microsoft.ScreenSketch_8wekyb3d8bbwe\TempState",
        "$env:LOCALAPPDATA\Packages\Microsoft.Windows.SnippingTool_8wekyb3d8bbwe\TempState"
    )

    $scrubbed = 0
    foreach ($sp in $scrPaths) {
        if (Test-Path $sp -ErrorAction SilentlyContinue) {
            Get-ChildItem -Path $sp -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    [System.IO.File]::WriteAllBytes($_.FullName, [byte[]]@())
                    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                    $scrubbed++
                } catch {}
            }
        }
    }

    Write-Host "  ok  shredded $scrubbed cached screenshot buffers (defeats Acropalypse image carving)" -ForegroundColor Green
}

function Invoke-RegistryLogSanitize {
    if (-not (Test-IsWindowsOS)) { return }
    Write-Host "  -- committing registry hives & flushing transaction journals..." -ForegroundColor Cyan
    try {
        [Microsoft.Win32.Registry]::CurrentUser.Flush()
        if (Test-AdminPrivilege) {
            [Microsoft.Win32.Registry]::LocalMachine.Flush()
        }

        # Purge orphan transaction containers (*.regtrans-ms)
        $orphanLogs = @(Get-ChildItem "$env:USERPROFILE", "$env:LOCALAPPDATA\Microsoft\Windows" -Filter "*.regtrans-ms" -Force -ErrorAction SilentlyContinue)
        $purgedCount = 0
        foreach ($ol in $orphanLogs) {
            try {
                [System.IO.File]::WriteAllBytes($ol.FullName, [byte[]]@())
                Remove-Item -Path $ol.FullName -Force -ErrorAction SilentlyContinue
                $purgedCount++
            } catch {}
        }
        Write-Host "  ok  flushed active registry transaction state & purged $purgedCount journal containers" -ForegroundColor Green
    } catch {
        Write-Host "  !!  registry log sanitize failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Invoke-PanicProtocol {
    param([switch]$PowerOff)
    Write-Host "`n  ================================================================" -ForegroundColor Red
    Write-Host "  [!] EXECUTING EMERGENCY DURESS / PANIC OBLITERATION PROTOCOL..." -ForegroundColor Red
    Write-Host "  ================================================================" -ForegroundColor Red

    if (Test-IsWindowsOS) {
        # 1. Terminate all browser, communication, and sensitive developer processes
        $killList = @(
            "mullvadbrowser", "chrome", "brave", "msedge", "firefox", "tor", "opera", "vivaldi",
            "telegram", "signal", "discord", "element", "keepass", "keepassxc", "bitwarden", "1password",
            "code", "idea64", "git", "openvpn", "wireguard"
        )
        foreach ($proc in $killList) {
            taskkill.exe /F /IM "$proc.exe" 2>$null | Out-Null
        }
        Write-Host "  ok  terminated all browsers, messengers, and password vaults" -ForegroundColor Green

        # 2. Instant Network Severance
        try {
            mullvad set-lockdown-mode on 2>$null | Out-Null
            mullvad disconnect 2>$null | Out-Null
            netsh wlan disconnect 2>$null | Out-Null
        } catch {}
        route -f 2>$null | Out-Null
        ipconfig /flushdns 2>$null | Out-Null
        arp -d * 2>$null | Out-Null
        Write-Host "  ok  severed Wi-Fi, engaged Mullvad lockdown, and flushed ARP/DNS/routes" -ForegroundColor Green

        # 3. Obliterate runtime artifacts & execution logs
        Shred-PowerShellHistory
        Clear-ExplorerTraces
        Invoke-ShellBagsSanitize
        Invoke-PcaWipe

        # 4. Deep low-level filesystem sanitization
        try {
            vssadmin delete shadows /all /quiet 2>$null | Out-Null
            fsutil usn deletejournal /D C: 2>$null | Out-Null
        } catch {}

        # 5. Flush clipboard and event logs
        try { Set-Clipboard -Value $null -ErrorAction SilentlyContinue } catch {}
        if (Test-AdminPrivilege) {
            Clear-WindowsEventLogs
        }

        Write-Host "  ok  forensic execution traces obliterated & memory sanitized." -ForegroundColor Green

        # 6. Immediate Lock or Emergency PowerOff
        if ($PowerOff) {
            Write-Host "  [!] INITIATING HARD EMERGENCY POWEROFF..." -ForegroundColor Red
            shutdown.exe /s /f /t 0
        } else {
            rundll32.exe user32.dll,LockWorkStation 2>$null
            Write-Host "  ok  workstation locked securely." -ForegroundColor Green
        }
    } elseif ($IsMacOS) {
        pmset displaysleepnow 2>$null
    } else {
        loginctl lock-session 2>$null
    }
}

function Audit-DeletedFootprint {
    Write-Host "  -- forensic inspection of pre-deleted artifacts" -ForegroundColor Cyan
    
    if (Test-IsWindowsOS) {
        # 1. Volume Shadow Copies (can contain past deleted profiles/files)
        $vssCount = 0
        $vssDetails = "none / clean"
        try {
            $shadows = (vssadmin list shadows 2>&1 | Out-String)
            if ($shadows -match "Contents of shadow copy set ID") {
                $vssCount = ([regex]::Matches($shadows, "Shadow Copy ID:")).Count
                $vssDetails = "$vssCount past volume snapshots (may contain deleted profiles)"
            }
        } catch {}
        $vssBadge = if ($vssCount -eq 0) { "PASS" } else { "WARN" }
        $vssColor = if ($vssCount -eq 0) { "Green" } else { "Yellow" }
        Write-Host ("  [{0}] {1,-34} {2}" -f $vssBadge, "Volume Shadow Snapshots (VSS)", $vssDetails) -ForegroundColor $vssColor

        # 2. NTFS USN Journal (logs deletion history of file paths)
        $usnDetails = "clean / inactive"
        $usnActive = $false
        try {
            $usn = (fsutil usn queryjournal C: 2>&1 | Out-String)
            if ($usn -match "Usn Journal ID") {
                $usnActive = $true
                $matchSize = [regex]::Match($usn, "Maximum Size\s+:\s+(0x[0-9a-fA-F]+\s+\([^)]+\))")
                $szStr = if ($matchSize.Success) { $matchSize.Groups[1].Value } else { "active" }
                $usnDetails = "logging file deletions ($szStr)"
            }
        } catch {}
        $usnBadge = if (-not $usnActive) { "PASS" } else { "INFO" }
        $usnColor = if (-not $usnActive) { "Green" } else { "Gray" }
        Write-Host ("  [{0}] {1,-34} {2}" -f $usnBadge, "NTFS USN Change Journal", $usnDetails) -ForegroundColor $usnColor

        # 3. Explorer Thumbnail Cache (retains thumbnails of visited sites & opened pictures)
        $tcFiles = @(Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer" -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue)
        $tcSize = 0
        if ($tcFiles.Count -gt 0) {
            $tcSize = [math]::Round(($tcFiles | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
        }
        $tcBadge = if ($tcSize -eq 0) { "PASS" } else { "WARN" }
        $tcColor = if ($tcSize -eq 0) { "Green" } else { "Yellow" }
        Write-Host ("  [{0}] {1,-34} {2}" -f $tcBadge, "Explorer Thumbnail Caches", "$($tcFiles.Count) DBs ($tcSize MB cached images)") -ForegroundColor $tcColor

        # 4. Windows Timeline ActivitiesCache
        $cdpPath = "$env:LOCALAPPDATA\ConnectedDevicesPlatform"
        $actExists = $false
        if (Test-Path $cdpPath -ErrorAction SilentlyContinue) {
            $actFiles = @(Get-ChildItem -Path $cdpPath -Filter "ActivitiesCache.db" -Recurse -Force -ErrorAction SilentlyContinue)
            $actExists = ($actFiles.Count -gt 0)
        }
        $actBadge = if (-not $actExists) { "PASS" } else { "WARN" }
        $actColor = if (-not $actExists) { "Green" } else { "Yellow" }
        Write-Host ("  [{0}] {1,-34} {2}" -f $actBadge, "Windows Timeline (ActivitiesCache)", $(if ($actExists) { "tracks past app & web sessions" } else { "clean" })) -ForegroundColor $actColor

        # 5. SRUM (System Resource Usage Monitor) ESE Database
        $srumPath = "C:\Windows\System32\sru\SRUDB.dat"
        $srumExists = Test-Path $srumPath -ErrorAction SilentlyContinue
        $srumBadge = if (-not $srumExists) { "PASS" } else { "WARN" }
        $srumColor = if (-not $srumExists) { "Green" } else { "Yellow" }
        Write-Host ("  [{0}] {1,-34} {2}" -f $srumBadge, "SRUM Network/Process ESE DB", $(if ($srumExists) { "tracks 30-day process execution & egress bytes" } else { "clean / unlinked" })) -ForegroundColor $srumColor

        # 6. Windows Search Index Database (Windows.edb)
        $edbPath = "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"
        $edbSize = 0
        if (Test-Path $edbPath -ErrorAction SilentlyContinue) {
            $edbSize = [math]::Round((Get-Item $edbPath -Force -ErrorAction SilentlyContinue).Length / 1MB, 2)
        }
        $edbBadge = if ($edbSize -eq 0) { "PASS" } else { "WARN" }
        $edbColor = if ($edbSize -eq 0) { "Green" } else { "Yellow" }
        Write-Host ("  [{0}] {1,-34} {2}" -f $edbBadge, "Windows Search Index (Windows.edb)", $(if ($edbSize -gt 0) { "$edbSize MB (caches deleted files & message bodies)" } else { "clean / disabled" })) -ForegroundColor $edbColor

        # 7. Unallocated Slack Space (Deallocated sectors)
        Write-Host "  [INFO] Drive C: Unallocated Slack Space   raw sectors of past deleted files can be carved until zero-filled" -ForegroundColor Gray
        Write-Host "`n  tip: run 'wipe-deleted' to purge VSS shadows, reset USN deletion logs, and re-trim SSD blocks." -ForegroundColor DarkGray
    } else {
        Write-Host "  --  forensic footprint audit: Linux/macOS caches and journalctl logs" -ForegroundColor DarkGray
    }
}

function Invoke-DeepSanitize {
    param([switch]$FullCipher)

    if (-not (Test-AdminPrivilege)) {
        Write-Host "  [!] Deep forensic sanitization requires administrator privileges." -ForegroundColor Yellow
        return
    }

    Write-Host "  -- executing deep forensic sanitization of past deleted items..." -ForegroundColor Cyan

    if (Test-IsWindowsOS) {
        # 1. Purge Volume Shadow Copies (deletes any past restore snapshots containing deleted files)
        try {
            vssadmin delete shadows /all /quiet 2>$null | Out-Null
            Write-Host "  ok  purged all Volume Shadow Copies (VSS restore snapshots)" -ForegroundColor Green
        } catch {}

        # 2. Reset / Delete NTFS USN Journal on C: (wipes historical logs of deleted file names)
        try {
            fsutil usn deletejournal /D C: 2>$null | Out-Null
            Write-Host "  ok  purged NTFS USN change journal (wiped deletion logs)" -ForegroundColor Green
        } catch {}

        # 3. Wipe Explorer Thumbnail Caches
        try {
            Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer" -Filter "thumbcache_*.db" -Force -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-FileWithZeroOverwrite -FilePath $_.FullName | Out-Null
            }
            Write-Host "  ok  purged Explorer thumbnail caches (thumbcache_*.db)" -ForegroundColor Green
        } catch {}

        # 4. Wipe Windows Timeline ActivitiesCache
        try {
            $cdpPath = "$env:LOCALAPPDATA\ConnectedDevicesPlatform"
            if (Test-Path $cdpPath -ErrorAction SilentlyContinue) {
                Get-ChildItem -Path $cdpPath -Filter "ActivitiesCache*" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    Remove-FileWithZeroOverwrite -FilePath $_.FullName | Out-Null
                }
                Write-Host "  ok  purged Windows Timeline ActivitiesCache.db" -ForegroundColor Green
            }
        } catch {}

        # 5. Neutralize SRUM (System Resource Usage Monitor)
        Invoke-SrumNeutralize

        # 6. Purge Windows Search Indexer Database
        Invoke-SearchIndexWipe

        # 7. Issue SSD ReTrim so SSD controller immediately discards deleted sector blocks
        try {
            Optimize-Volume -DriveLetter C -ReTrim -Verbose:$false -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  ok  issued SSD ReTrim on Drive C: (controller garbage-collection)" -ForegroundColor Green
        } catch {}

        # 6. Optional full 3-pass cipher overwrite of free disk space
        if ($FullCipher) {
            Write-Host "  [*] executing 3-pass cipher zero-fill on unallocated free disk space (cipher /w:C:)..." -ForegroundColor Yellow
            cipher.exe /w:C:
            Write-Host "  ok  unallocated disk sectors 3-pass zero-overwritten." -ForegroundColor Green
        } else {
            Write-Host "  [TIP] To zero-overwrite ALL free space on drive C: to defeat raw sector carving, run 'wipe-deleted -cipher'." -ForegroundColor DarkGray
        }
    } else {
        fstrim -av 2>$null
        journalctl --vacuum-time=1s 2>$null
        Write-Host "  ok  trimmed filesystems & purged systemd journals" -ForegroundColor Green
    }
}

Export-ModuleMember -Function Audit-Traces, Shred-PowerShellHistory, Clear-ExplorerTraces, Invoke-MetadataScrub, Invoke-PanicProtocol, Audit-DeletedFootprint, Invoke-DeepSanitize, Clear-WindowsEventLogs, Invoke-PcaWipe, Invoke-ShellBagsSanitize, Invoke-SrumNeutralize, Invoke-SearchIndexWipe, Invoke-StealthEventLogBlind, Invoke-TokenSanitize, Invoke-ScreenshotCacheWipe, Invoke-RegistryLogSanitize

