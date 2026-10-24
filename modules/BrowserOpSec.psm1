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

function Remove-FileWithZeroOverwrite {
    param([string]$FilePath)
    if (Test-Path $FilePath -ErrorAction SilentlyContinue) {
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                $item = Get-Item $FilePath -Force -ErrorAction Stop
                if ($item.Attributes -match "ReadOnly|Hidden") {
                    $item.Attributes = [System.IO.FileAttributes]::Normal
                }
                if (-not $item.PSIsContainer) {
                    $len = $item.Length
                    if ($len -gt 0 -and $len -lt 200MB) {
                        $zeroes = [byte[]]::new($len)
                        [System.IO.File]::WriteAllBytes($FilePath, $zeroes)
                    }
                }
                Remove-Item -Path $FilePath -Force -Recurse -ErrorAction Stop
                return $true
            } catch {
                if ($attempt -lt 3) {
                    Start-Sleep -Milliseconds 250
                } else {
                    return $false
                }
            }
        }
    }
    return $false
}

function Get-InstalledBrowsers {
    $uHome = Get-UserHome
    $browsers = @()

    if (Test-IsWindowsOS) {
        $mvExe = $null
        foreach ($mx in @(
            "$uHome\Desktop\Mullvad Browser\Browser\mullvadbrowser.exe",
            "$env:LOCALAPPDATA\Mullvad\MullvadBrowser\Release\mullvadbrowser.exe",
            "C:\Program Files\Mullvad Browser\mullvadbrowser.exe",
            "C:\Program Files\Mullvad\MullvadBrowser\Browser\mullvadbrowser.exe",
            "C:\Program Files\Mullvad\MullvadBrowser\Release\mullvadbrowser.exe",
            "$env:LOCALAPPDATA\Programs\MullvadBrowser\mullvadbrowser.exe",
            "$env:LOCALAPPDATA\MullvadBrowser\Browser\mullvadbrowser.exe",
            "$uHome\Downloads\MullvadBrowser\Browser\mullvadbrowser.exe"
        )) {
            if (Test-Path $mx -ErrorAction SilentlyContinue) { $mvExe = $mx; break }
        }

        $candidates = @(
            @{ Name = "Mullvad Browser"; Engine = "Gecko";    Exe = $mvExe; AltExe = "$env:LOCALAPPDATA\Mullvad\MullvadBrowser\Release\mullvadbrowser.exe"; DataDir = "$uHome\Desktop\Mullvad Browser\Browser\TorBrowser\Data\Browser" },
            @{ Name = "Tor Browser";     Engine = "Gecko";    Exe = "$uHome\Desktop\Tor Browser\Browser\firefox.exe";                      AltExe = "$env:LOCALAPPDATA\Tor Browser\Browser\firefox.exe";                  DataDir = "$uHome\Desktop\Tor Browser\Browser\TorBrowser\Data\Browser" },
            @{ Name = "Brave";           Engine = "Chromium"; Exe = "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe";  AltExe = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe"; DataDir = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" },
            @{ Name = "Chrome";          Engine = "Chromium"; Exe = "C:\Program Files\Google\Chrome\Application\chrome.exe";               AltExe = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe";        DataDir = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
            @{ Name = "Edge";            Engine = "Chromium"; Exe = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";        AltExe = "C:\Program Files\Microsoft\Edge\Application\msedge.exe";             DataDir = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
            @{ Name = "Vivaldi";         Engine = "Chromium"; Exe = "$env:LOCALAPPDATA\Vivaldi\Application\vivaldi.exe";                   AltExe = "C:\Program Files\Vivaldi\Application\vivaldi.exe";                   DataDir = "$env:LOCALAPPDATA\Vivaldi\User Data" },
            @{ Name = "Opera";           Engine = "Chromium"; Exe = "$env:LOCALAPPDATA\Programs\Opera\opera.exe";                          AltExe = "C:\Program Files\Opera\opera.exe";                                   DataDir = "$env:APPDATA\Opera Software\Opera Stable" },
            @{ Name = "Chromium";        Engine = "Chromium"; Exe = "$env:LOCALAPPDATA\Chromium\Application\chrome.exe";                   AltExe = "C:\Program Files\Chromium\Application\chrome.exe";                   DataDir = "$env:LOCALAPPDATA\Chromium\User Data" },
            @{ Name = "Firefox";         Engine = "Gecko";    Exe = "C:\Program Files\Mozilla Firefox\firefox.exe";                        AltExe = "C:\Program Files (x86)\Mozilla Firefox\firefox.exe";                 DataDir = "$env:APPDATA\Mozilla\Firefox\Profiles" },
            @{ Name = "LibreWolf";       Engine = "Gecko";    Exe = "C:\Program Files\LibreWolf\librewolf.exe";                            AltExe = "$env:LOCALAPPDATA\Programs\LibreWolf\librewolf.exe";                 DataDir = "$env:APPDATA\librewolf\Profiles" }
        )
        foreach ($c in $candidates) {
            $exePath = if ($c.Exe -and (Test-Path $c.Exe -ErrorAction SilentlyContinue)) { $c.Exe } elseif ($c.AltExe -and (Test-Path $c.AltExe -ErrorAction SilentlyContinue)) { $c.AltExe } else { $null }
            $hasData = ($c.DataDir -and (Test-Path $c.DataDir -ErrorAction SilentlyContinue))
            if ($exePath -or $hasData) {
                $browsers += [PSCustomObject]@{
                    Name    = $c.Name
                    Engine  = $c.Engine
                    Exe     = $exePath
                    DataDir = $c.DataDir
                }
            }
        }
    } else {
        $unixCandidates = @(
            @{ Name = "Mullvad Browser"; Bin = "mullvad-browser"; Engine = "Gecko";    DataDir = "$uHome/.mullvad-browser" },
            @{ Name = "Brave";           Bin = "brave-browser";   Engine = "Chromium"; DataDir = "$uHome/.config/BraveSoftware/Brave-Browser" },
            @{ Name = "Chrome";          Bin = "google-chrome";   Engine = "Chromium"; DataDir = "$uHome/.config/google-chrome" },
            @{ Name = "Chromium";        Bin = "chromium";        Engine = "Chromium"; DataDir = "$uHome/.config/chromium" },
            @{ Name = "Firefox";         Bin = "firefox";         Engine = "Gecko";    DataDir = "$uHome/.mozilla/firefox" },
            @{ Name = "LibreWolf";       Bin = "librewolf";       Engine = "Gecko";    DataDir = "$uHome/.librewolf" }
        )
        foreach ($uc in $unixCandidates) {
            $cmd = Get-Command $uc.Bin -ErrorAction SilentlyContinue
            $hasData = Test-Path $uc.DataDir
            if ($cmd -or $hasData) {
                $browsers += [PSCustomObject]@{
                    Name    = $uc.Name
                    Engine  = $uc.Engine
                    Exe     = if ($cmd) { $cmd.Source } else { $null }
                    DataDir = if ($hasData) { $uc.DataDir } else { $null }
                }
            }
        }
    }
    return $browsers
}

function Get-BrowserProfiles {
    $browsers = Get-InstalledBrowsers
    $profiles = @()

    foreach ($b in $browsers) {
        if (-not $b.DataDir -or -not (Test-Path $b.DataDir -ErrorAction SilentlyContinue)) { continue }

        if ($b.Engine -eq "Chromium") {
            # Parse Local State info_cache for account emails & profile names
            $localStateFile = Join-Path $b.DataDir "Local State"
            $infoCache = $null
            if (Test-Path $localStateFile) {
                try {
                    $lsJson = Get-Content $localStateFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue | ConvertFrom-Json
                    if ($lsJson.profile -and $lsJson.profile.info_cache) {
                        $infoCache = $lsJson.profile.info_cache
                    }
                } catch {}
            }

            $profDirs = Get-ChildItem -Path $b.DataDir -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile \d+$" }

            foreach ($pd in $profDirs) {
                $profName = $pd.Name
                $displayName = $pd.Name
                $accountEmail = "local / unlinked"

                $gaiaName = ""
                if ($infoCache -and $infoCache.PSObject.Properties[$profName]) {
                    $entry = $infoCache.PSObject.Properties[$profName].Value
                    if ($entry.name) { $displayName = $entry.name }
                    if ($entry.gaia_name) { $gaiaName = $entry.gaia_name }
                    if ($entry.user_name) {
                        $accountEmail = if ($entry.gaia_name) { "$($entry.user_name) ($($entry.gaia_name))" } else { $entry.user_name }
                    } elseif ($entry.gaia_name) {
                        $accountEmail = $entry.gaia_name
                    }
                }

                # Check Preferences JSON if account_info has more details
                $prefFile = Join-Path $pd.FullName "Preferences"
                if (Test-Path $prefFile) {
                    try {
                        $pJson = Get-Content $prefFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue | ConvertFrom-Json
                        if ($pJson.account_info -and $pJson.account_info.Count -gt 0) {
                            $emails = @($pJson.account_info | ForEach-Object { $_.email } | Where-Object { $_ })
                            if ($emails.Count -gt 0) { $accountEmail = $emails -join ", " }
                        }
                        if ($displayName -eq $profName -and $pJson.profile -and $pJson.profile.name) {
                            $displayName = $pJson.profile.name
                        }
                    } catch {}
                }

                # Deep web-account scan for Brave and unlinked profiles
                if ($accountEmail -eq "local / unlinked" -or -not $accountEmail) {
                    if (Test-Path $prefFile -ErrorAction SilentlyContinue) {
                        $prefRaw = Get-Content $prefFile -Raw -ErrorAction SilentlyContinue
                        if ($prefRaw) {
                            $emailMatch = [regex]::Matches($prefRaw, "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
                            if ($emailMatch.Count -gt 0) {
                                $uniqueEmails = @($emailMatch | ForEach-Object { $_.Value } | Where-Object { $_ -notmatch "example|chromium|google\.com$" } | Select-Object -Unique)
                                if ($uniqueEmails.Count -gt 0) {
                                    $accountEmail = "$($uniqueEmails[0]) (web login)"
                                }
                            }
                        }
                    }
                    $webDataFile = Join-Path $pd.FullName "Web Data"
                    if (($accountEmail -eq "local / unlinked" -or -not $accountEmail) -and (Test-Path $webDataFile -ErrorAction SilentlyContinue)) {
                        $wdRaw = Get-Content $webDataFile -Raw -ErrorAction SilentlyContinue
                        if ($wdRaw) {
                            $wdMatch = [regex]::Matches($wdRaw, "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
                            if ($wdMatch.Count -gt 0) {
                                $uniqueWd = @($wdMatch | ForEach-Object { $_.Value } | Where-Object { $_ -notmatch "example" } | Select-Object -Unique)
                                if ($uniqueWd.Count -gt 0) {
                                    $accountEmail = "$($uniqueWd[0]) (saved login)"
                                }
                            }
                        }
                    }
                }

                if ($b.Name -eq "Brave") {
                    if ($displayName -eq "Default" -or $displayName -eq "Personal") {
                        $displayName = "Personal (Brave Local)"
                    }
                    if ($accountEmail -eq "local / unlinked") {
                        $accountEmail = "isolated / no Google sync"
                    }
                }

                $hasHistory = (Test-Path (Join-Path $pd.FullName "History")) -or (Test-Path (Join-Path $pd.FullName "History-wal"))
                $hasCookies = (Test-Path (Join-Path $pd.FullName "Network\Cookies")) -or (Test-Path (Join-Path $pd.FullName "Cookies"))
                $hasLogins  = Test-Path (Join-Path $pd.FullName "Login Data")

                $artifacts = @()
                if ($hasHistory) { $artifacts += "history" }
                if ($hasCookies) { $artifacts += "cookies" }
                if ($hasLogins)  { $artifacts += "saved_logins" }

                $profiles += [PSCustomObject]@{
                    Browser      = $b.Name
                    Engine       = "Chromium"
                    Folder       = $profName
                    DisplayName  = $displayName
                    GaiaName     = $gaiaName
                    Account      = $accountEmail
                    Path         = $pd.FullName
                    Artifacts    = if ($artifacts.Count -gt 0) { $artifacts -join "," } else { "clean" }
                }
            }
        } elseif ($b.Engine -eq "Gecko") {
            $profDirs = Get-ChildItem -Path $b.DataDir -Directory -ErrorAction SilentlyContinue
            foreach ($pd in $profDirs) {
                $hasPlaces  = Test-Path (Join-Path $pd.FullName "places.sqlite")
                $hasCookies = Test-Path (Join-Path $pd.FullName "cookies.sqlite")
                $hasLogins  = Test-Path (Join-Path $pd.FullName "logins.json")

                $artifacts = @()
                if ($hasPlaces)  { $artifacts += "history" }
                if ($hasCookies) { $artifacts += "cookies" }
                if ($hasLogins)  { $artifacts += "saved_logins" }

                $profiles += [PSCustomObject]@{
                    Browser      = $b.Name
                    Engine       = "Gecko"
                    Folder       = $pd.Name
                    DisplayName  = $pd.Name
                    Account      = "local profile"
                    Path         = $pd.FullName
                    Artifacts    = if ($artifacts.Count -gt 0) { $artifacts -join "," } else { "clean" }
                }
            }
        }
    }

    return $profiles
}

function Show-BrowserInventory {
    Write-Host "  -- detected browsers" -ForegroundColor Cyan
    $browsers = Get-InstalledBrowsers
    if ($browsers.Count -eq 0) {
        Write-Host "  none detected." -ForegroundColor DarkGray
        return
    }
    foreach ($b in $browsers) {
        Write-Host ("  [{0,-8}] {1,-18} {2}" -f $b.Engine, $b.Name, $(if ($b.Exe) { $b.Exe } else { $b.DataDir })) -ForegroundColor Gray
    }

    Write-Host "`n  -- browser profiles & saved accounts" -ForegroundColor Cyan
    $profiles = Get-BrowserProfiles
    if ($profiles.Count -eq 0) {
        Write-Host "  no browser profiles found." -ForegroundColor DarkGray
        return
    }
    $idx = 1
    foreach ($p in $profiles) {
        $artColor = if ($p.Artifacts -eq "clean") { "Green" } else { "Yellow" }
        Write-Host ("  #{0,-2} {1,-15} [{2}] name:{3,-16} acct:{4,-26} " -f $idx, $p.Browser, $p.Folder, $p.DisplayName, $p.Account) -ForegroundColor Gray -NoNewline
        Write-Host "($($p.Artifacts))" -ForegroundColor $artColor
        $idx++
    }
    Write-Host "`n  tip: use 'browser clean <name/folder>' to wipe history/sessions, or 'browser remove <account/name/#>' to shred an account profile." -ForegroundColor DarkGray
}

function Stop-BrowserProcesses {
    param([string]$BrowserName)
    $procMap = @{
        "Brave"           = @("brave")
        "Chrome"          = @("chrome")
        "Edge"            = @("msedge")
        "Vivaldi"         = @("vivaldi")
        "Opera"           = @("opera")
        "Chromium"        = @("chrome", "chromium")
        "Firefox"         = @("firefox")
        "LibreWolf"       = @("librewolf")
        "Mullvad Browser" = @("mullvadbrowser", "mullvad-browser")
        "Tor Browser"     = @("firefox")
    }
    $targets = if ($BrowserName -and $procMap.ContainsKey($BrowserName)) {
        $procMap[$BrowserName]
    } else {
        @("brave", "chrome", "msedge", "vivaldi", "opera", "firefox", "librewolf", "mullvadbrowser")
    }
    foreach ($t in $targets) {
        if (Test-IsWindowsOS) {
            taskkill.exe /F /T /IM "$t.exe" 2>$null | Out-Null
        }
        Get-Process -Name $t -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 400
}

function Clear-BrowserHistoryAndTraces {
    param([string]$Filter)

    $isTotal = $false
    if ($Filter -match "(-total|total|-deep|deep|-all|all)") {
        $isTotal = $true
        $Filter = ($Filter -replace "(-total|total|-deep|deep|-all|all)", "").Trim()
    }

    $profiles = Get-BrowserProfiles
    if ($Filter) {
        $profiles = @($profiles | Where-Object {
            $_.Browser -match [regex]::Escape($Filter) -or
            $_.Folder -match [regex]::Escape($Filter) -or
            $_.DisplayName -match [regex]::Escape($Filter) -or
            $_.Account -match [regex]::Escape($Filter)
        })
    }

    if ($profiles.Count -eq 0) {
        Write-Host "  [!] no matching browser profiles found for '$Filter'." -ForegroundColor Yellow
        return
    }

    if ($isTotal) {
        Write-Host "  -- [TOTAL-WIPE] shredding history, autofill, cloud-sync caches & session tokens..." -ForegroundColor Cyan
    }

    foreach ($p in $profiles) {
        Stop-BrowserProcesses -BrowserName $p.Browser
        $count = 0

        if ($p.Engine -eq "Chromium") {
            # Deep history, session, autocomplete, and forensic artifact files inside Chromium profile
            $historyPatterns = @(
                "History*",
                "Archived History*",
                "Favicons*",
                "Top Sites*",
                "Shortcuts*",
                "Visited Links*",
                "Network Action Predictor*",
                "Media History*",
                "DownloadMetadata*",
                "Reporting and Nel*",
                "HeavyAdIntervention*",
                "SegmentedDictionary*",
                "History Provider Cache*",
                "Affiliation Database*",
                "Web Data*"
            )

            if ($isTotal) {
                # In total mode: wipe cookies, profile icons & token trackers to stop cloud sync resurrection
                $historyPatterns += @("Cookies*", "Google Profile.ico", "AccountTracker*")
            }

            foreach ($pat in $historyPatterns) {
                Get-ChildItem -Path $p.Path -Filter $pat -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    if (Remove-FileWithZeroOverwrite -FilePath $_.FullName) { $count++ }
                }
            }

            # Purge Sessions, Caches, and Sync Data (Sync Data stores synced history that re-downloads old history!)
            $dirsToPurge = @(
                "Sessions", "Session Storage", "Cache", "Code Cache", "GPUCache",
                "ShaderCache", "GrShaderCache", "Service Worker\CacheStorage", "Crashpad\reports",
                "jumpListIcons", "jumpListIconsOld", "File System",
                "Sync Data", "Sync App Settings", "GCM Store"
            )

            if ($isTotal) {
                $dirsToPurge += @("Network", "Local Storage", "IndexedDB", "Accounts")
            }

            foreach ($d in $dirsToPurge) {
                $dp = Join-Path $p.Path $d
                if (Test-Path $dp -ErrorAction SilentlyContinue) {
                    Get-ChildItem -Path $dp -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        Remove-FileWithZeroOverwrite -FilePath $_.FullName | Out-Null
                    }
                    Remove-Item -Path "$dp\*" -Recurse -Force -ErrorAction SilentlyContinue
                    $count++
                }
            }

            # If total mode: purge sync setup in Preferences so Chrome does not pull old history from Google servers upon restart
            if ($isTotal) {
                $prefFile = Join-Path $p.Path "Preferences"
                if (Test-Path $prefFile -ErrorAction SilentlyContinue) {
                    try {
                        $pRaw = Get-Content $prefFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                        if ($pRaw) {
                            $pJson = $pRaw | ConvertFrom-Json
                            if ($pJson.sync) { $pJson.PSObject.Properties.Remove('sync') }
                            if ($pJson.account_info) { $pJson.PSObject.Properties.Remove('account_info') }
                            $newJson = $pJson | ConvertTo-Json -Depth 32
                            [System.IO.File]::WriteAllText($prefFile, $newJson, [System.Text.Encoding]::UTF8)
                        }
                    } catch {}
                }
            }
        } elseif ($p.Engine -eq "Gecko") {
            $geckoFiles = @(
                "places.sqlite", "places.sqlite-wal", "places.sqlite-shm",
                "favicons.sqlite", "favicons.sqlite-wal", "favicons.sqlite-shm",
                "formhistory.sqlite", "sessionstore.jsonlz4", "sessionCheckpoints.json"
            )
            if ($isTotal) {
                $geckoFiles += @("cookies.sqlite", "cookies.sqlite-wal", "cookies.sqlite-shm", "logins.json", "key4.db")
            }
            foreach ($gf in $geckoFiles) {
                $fp = Join-Path $p.Path $gf
                if (Remove-FileWithZeroOverwrite -FilePath $fp) { $count++ }
            }
            $geckoDirs = @("sessionstore-backups", "cache2", "startupCache", "jumpListCache", "datareporting", "crashes")
            if ($isTotal) {
                $geckoDirs += @("storage", "weave")
            }
            foreach ($gd in $geckoDirs) {
                $dp = Join-Path $p.Path $gd
                if (Test-Path $dp) {
                    Remove-Item -Path "$dp\*" -Recurse -Force -ErrorAction SilentlyContinue
                    $count++
                }
            }
        }

        $tag = if ($isTotal) { " [TOTAL WIPED + SYNC SEVERED]" } else { "" }
        Write-Host "  ok  shredded history, sessions & caches for $($p.Browser) [$($p.Folder) / $($p.DisplayName)]$tag ($count artifacts)" -ForegroundColor Green
    }
}

function Clear-BrowserAutofill {
    param([string]$Filter)

    $profiles = Get-BrowserProfiles
    if ($Filter) {
        $profiles = @($profiles | Where-Object {
            $_.Browser -match [regex]::Escape($Filter) -or
            $_.Folder -match [regex]::Escape($Filter) -or
            $_.DisplayName -match [regex]::Escape($Filter) -or
            $_.Account -match [regex]::Escape($Filter)
        })
    }

    if ($profiles.Count -eq 0) {
        Write-Host "  [!] no matching browser profiles found for '$Filter'." -ForegroundColor Yellow
        return
    }

    Write-Host "  -- shredding form autofill, emails & search suggestions..." -ForegroundColor Cyan

    foreach ($p in $profiles) {
        Stop-BrowserProcesses -BrowserName $p.Browser
        $count = 0

        if ($p.Engine -eq "Chromium") {
            foreach ($pat in @("Web Data*")) {
                Get-ChildItem -Path $p.Path -Filter $pat -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    if (Remove-FileWithZeroOverwrite -FilePath $_.FullName) { $count++ }
                }
            }
        } elseif ($p.Engine -eq "Gecko") {
            foreach ($gf in @("formhistory.sqlite", "formhistory.sqlite-wal", "formhistory.sqlite-shm")) {
                $fp = Join-Path $p.Path $gf
                if (Remove-FileWithZeroOverwrite -FilePath $fp) { $count++ }
            }
        }

        Write-Host "  ok  purged autofill & form email suggestions for $($p.Browser) [$($p.Folder) / $($p.DisplayName)] ($count artifacts)" -ForegroundColor Green
    }
}

function Remove-BrowserAccountTraces {
    param([string]$Target)

    if (-not $Target) {
        Write-Host "  usage: browser remove <profile_# | email | profile_name | folder>" -ForegroundColor Yellow
        return
    }

    $allProfiles = @(Get-BrowserProfiles)
    $matched = @()

    if ($Target -match "^\d+$") {
        $idx = [int]$Target - 1
        if ($idx -ge 0 -and $idx -lt $allProfiles.Count) {
            $matched += $allProfiles[$idx]
        }
    } else {
        $matched = @($allProfiles | Where-Object {
            $_.Account -match [regex]::Escape($Target) -or
            $_.DisplayName -match [regex]::Escape($Target) -or
            ($_.GaiaName -and $_.GaiaName -match [regex]::Escape($Target)) -or
            $_.Folder -ieq $Target -or
            $_.Browser -ieq $Target
        })
    }

    if ($matched.Count -eq 0) {
        Write-Host "  [!] no browser profile/account matched '$Target'. Run 'browser list' to view profiles." -ForegroundColor Yellow
        return
    }

    foreach ($p in $matched) {
        Stop-BrowserProcesses -BrowserName $p.Browser
        Write-Host "  shredding account & credential traces in $($p.Browser) [$($p.Folder) | $($p.Account)]..." -ForegroundColor Cyan

        if ($p.Engine -eq "Chromium") {
            # Shred all account, login, token, cookie, sync, and history databases (including WAL, SHM, and journal files)
            $accountPatterns = @(
                "Login Data*",
                "Web Data*",
                "Cookies*",
                "History*",
                "Favicons*",
                "Top Sites*",
                "Shortcuts*",
                "Visited Links*",
                "Network Action Predictor*",
                "Media History*",
                "Google Profile.ico",
                "AccountTracker*"
            )
            foreach ($pat in $accountPatterns) {
                Get-ChildItem -Path $p.Path -Filter $pat -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    Remove-FileWithZeroOverwrite -FilePath $_.FullName | Out-Null
                }
            }

            $netDir = Join-Path $p.Path "Network"
            if (Test-Path $netDir -ErrorAction SilentlyContinue) {
                Get-ChildItem -Path $netDir -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    Remove-FileWithZeroOverwrite -FilePath $_.FullName | Out-Null
                }
            }

            foreach ($ad in @("Sync Data", "Sync App Settings", "Local Storage", "Session Storage", "IndexedDB", "Sessions", "Accounts", "GCM Store")) {
                $dp = Join-Path $p.Path $ad
                if (Test-Path $dp) {
                    Get-ChildItem -Path $dp -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        Remove-FileWithZeroOverwrite -FilePath $_.FullName | Out-Null
                    }
                    Remove-Item -Path $dp -Recurse -Force -ErrorAction SilentlyContinue
                }
            }

            # Strip account_info & google services username from Preferences JSON
            $prefFile = Join-Path $p.Path "Preferences"
            if (Test-Path $prefFile) {
                try {
                    $pJson = Get-Content $prefFile -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
                    if ($pJson.PSObject.Properties["account_info"]) {
                        $pJson.account_info = @()
                    }
                    if ($pJson.PSObject.Properties["google"] -and $pJson.google.PSObject.Properties["services"]) {
                        $pJson.google.services = @{}
                    }
                    $outJson = $pJson | ConvertTo-Json -Depth 10 -Compress
                    Set-Content -Path $prefFile -Value $outJson -Encoding UTF8 -Force
                } catch {}
            }

            # Strip profile from Local State completely so the card disappears from Chrome's profile picker
            $browserRoot = Split-Path -Parent $p.Path
            $localStateFile = Join-Path $browserRoot "Local State"
            if (Test-Path $localStateFile) {
                try {
                    $lsJson = Get-Content $localStateFile -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
                    if ($lsJson.profile -and $lsJson.profile.info_cache) {
                        # Remove profile entry from info_cache
                        if ($lsJson.profile.info_cache.PSObject.Properties[$p.Folder]) {
                            $lsJson.profile.info_cache.PSObject.Properties.Remove($p.Folder)
                        }
                    }
                    if ($lsJson.profile -and $lsJson.profile.profiles_order) {
                        $lsJson.profile.profiles_order = @($lsJson.profile.profiles_order | Where-Object { $_ -ne $p.Folder })
                    }
                    if ($lsJson.profile -and $lsJson.profile.last_active_profiles) {
                        $lsJson.profile.last_active_profiles = @($lsJson.profile.last_active_profiles | Where-Object { $_ -ne $p.Folder })
                    }
                    $lsOut = $lsJson | ConvertTo-Json -Depth 10 -Compress
                    Set-Content -Path $localStateFile -Value $lsOut -Encoding UTF8 -Force
                } catch {}
            }

            # If it's a secondary profile (e.g. Profile 1, Profile 2), zero-shred and remove the entire folder
            if ($p.Folder -ne "Default") {
                Get-ChildItem -Path $p.Path -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    Remove-FileWithZeroOverwrite -FilePath $_.FullName | Out-Null
                }
                Remove-Item -Path $p.Path -Recurse -Force -ErrorAction SilentlyContinue
            }
        } elseif ($p.Engine -eq "Gecko") {
            foreach ($gf in @("logins.json", "key4.db", "cert9.db", "cookies.sqlite", "places.sqlite", "formhistory.sqlite", "signedInUser.json", "sessionstore.jsonlz4")) {
                $fp = Join-Path $p.Path $gf
                Remove-FileWithZeroOverwrite -FilePath $fp | Out-Null
            }
            foreach ($gd in @("storage", "sessionstore-backups")) {
                $dp = Join-Path $p.Path $gd
                if (Test-Path $dp) {
                    Get-ChildItem -Path $dp -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        Remove-FileWithZeroOverwrite -FilePath $_.FullName | Out-Null
                    }
                    Remove-Item -Path $dp -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }

        Write-Host "  ok  completely wiped account, logins, cookies, sessions & history for $($p.Browser) [$($p.Folder)]" -ForegroundColor Green
    }
}

function Audit-BrowserOpSec {
    $results = @()

    if (Test-IsWindowsOS) {
        # 1. WebRTC IP Leak Prevention Policy across Chromium/Firefox
        $webrtcHardened = $false
        foreach ($polPath in @(
            "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
            "HKLM:\SOFTWARE\Policies\Google\Chrome",
            "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
            "HKCU:\Software\Policies\BraveSoftware\Brave",
            "HKCU:\Software\Policies\Google\Chrome",
            "HKCU:\Software\Policies\Microsoft\Edge"
        )) {
            if (Test-Path $polPath) {
                $val = (Get-ItemProperty -Path $polPath -Name "WebRtcIPHandlingPolicy" -ErrorAction SilentlyContinue).WebRtcIPHandlingPolicy
                if ($val -eq "disable_non_proxied_udp" -or $val -eq "default_public_interface_only") {
                    $webrtcHardened = $true
                    break
                }
            }
        }
        $results += [PSCustomObject]@{
            Category = "Browser"
            Check    = "Browser WebRTC Leak Policy"
            Status   = if ($webrtcHardened) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($webrtcHardened) { "disable_non_proxied_udp (VPN-safe)" } else { "unrestricted STUN/UDP (IP leak risk)" }
        }

        # 2. Browser Credential Store Lock (Anti-Infostealer Password Manager Disable)
        $pwdLocked = $false
        foreach ($polPath in @(
            "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
            "HKLM:\SOFTWARE\Policies\Google\Chrome",
            "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
            "HKCU:\Software\Policies\BraveSoftware\Brave",
            "HKCU:\Software\Policies\Google\Chrome",
            "HKCU:\Software\Policies\Microsoft\Edge"
        )) {
            if (Test-Path $polPath) {
                $val = (Get-ItemProperty -Path $polPath -Name "PasswordManagerEnabled" -ErrorAction SilentlyContinue).PasswordManagerEnabled
                if ($val -eq 0) {
                    $pwdLocked = $true
                    break
                }
            }
        }
        $results += [PSCustomObject]@{
            Category = "Browser"
            Check    = "Browser Password Vault Lock"
            Status   = if ($pwdLocked) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($pwdLocked) { "disabled (immune to SQLite stealer)" } else { "plaintext SQLite vault enabled" }
        }

        # 3. Browser DoH (Mullvad Encrypted DNS)
        $dohLocked = $false
        foreach ($polPath in @(
            "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
            "HKLM:\SOFTWARE\Policies\Google\Chrome",
            "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
            "HKCU:\Software\Policies\BraveSoftware\Brave",
            "HKCU:\Software\Policies\Google\Chrome",
            "HKCU:\Software\Policies\Microsoft\Edge"
        )) {
            if (Test-Path $polPath) {
                $val = (Get-ItemProperty -Path $polPath -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue).DnsOverHttpsMode
                if ($val -in @("secure", "automatic")) {
                    $dohLocked = $true
                    break
                }
            }
        }
        $results += [PSCustomObject]@{
            Category = "Browser"
            Check    = "Browser Encrypted DNS (DoH)"
            Status   = if ($dohLocked) { "HARDENED" } else { "EXPOSED" }
            Details  = if ($dohLocked) { "Mullvad DoH enforced" } else { "default browser DNS" }
        }

        # 4. Mullvad Browser Anti-Fingerprinting Engine
        $installedBrowsers = Get-InstalledBrowsers
        $hasMullvadBrowser = ($installedBrowsers | Where-Object { $_.Name -eq "Mullvad Browser" -and $_.Exe })
        $results += [PSCustomObject]@{
            Category = "Browser"
            Check    = "Mullvad Browser (Anti-Fingerprint)"
            Status   = if ($hasMullvadBrowser) { "HARDENED" } else { "CONFIGURABLE" }
            Details  = if ($hasMullvadBrowser) { "ready ($($hasMullvadBrowser[0].Exe)) - RFP, letterboxing, zero-disk cache" } else { "available for install (partner browser)" }
        }
    } else {
        $installed = Get-InstalledBrowsers
        $hasMullvadOrLibrewolf = ($installed.Name -match "Mullvad|LibreWolf")
        $results += [PSCustomObject]@{
            Category = "Browser"
            Check    = "Hardened Browser Presence"
            Status   = if ($hasMullvadOrLibrewolf) { "HARDENED" } else { "CONFIGURABLE" }
            Details  = if ($installed) { ($installed.Name -join ", ") } else { "none detected" }
        }
    }

    return $results
}

function Harden-Browsers {
    $isAdmin = Test-AdminPrivilege

    if (Test-IsWindowsOS) {
        $roots = @("HKCU:\Software\Policies")
        if ($isAdmin) { $roots += "HKLM:\SOFTWARE\Policies" }

        $chromiumVendors = @(
            "Google\Chrome",
            "BraveSoftware\Brave",
            "Microsoft\Edge",
            "Chromium",
            "Vivaldi"
        )

        foreach ($root in $roots) {
            foreach ($vendor in $chromiumVendors) {
                $p = "$root\$vendor"
                if (-not (Test-Path $p)) { New-Item -Path $p -Force -ErrorAction SilentlyContinue | Out-Null }

                Set-ItemProperty -Path $p -Name "WebRtcIPHandlingPolicy" -Type String -Value "disable_non_proxied_udp" -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $p -Name "PasswordManagerEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $p -Name "AutofillAddressEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $p -Name "AutofillCreditCardEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $p -Name "SearchSuggestEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $p -Name "DnsOverHttpsMode" -Type String -Value "automatic" -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $p -Name "DnsOverHttpsTemplates" -Type String -Value "https://base.dns.mullvad.net/dns-query" -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $p -Name "BlockThirdPartyCookies" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $p -Name "MetricsReportingEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $p -Name "PrivacySandboxAdTopicsEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $p -Name "PrivacySandboxSiteEnabledAdsEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $p -Name "BackgroundModeEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $p -Name "PromotionalTabsEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
            }

            $ffPath = "$root\Mozilla\Firefox"
            if (-not (Test-Path $ffPath)) { New-Item -Path $ffPath -Force -ErrorAction SilentlyContinue | Out-Null }
            Set-ItemProperty -Path $ffPath -Name "DisableTelemetry" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $ffPath -Name "DisableFirefoxStudies" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $ffPath -Name "OfferToSaveLogins" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $ffPath -Name "PasswordManagerEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
        }

        if (-not $isAdmin) {
            Write-Host "  --  note: browser enterprise policies (HKLM\SOFTWARE\Policies) require Administrator rights" -ForegroundColor DarkYellow
        } else {
            Write-Host "  ok  browser webrtc_leak_protection = disable_non_proxied_udp" -ForegroundColor Green
            Write-Host "  ok  browser password_vault & autofill = disabled (anti-infostealer)" -ForegroundColor Green
            Write-Host "  ok  browser doh_resolver = https://base.dns.mullvad.net/dns-query" -ForegroundColor Green
            Write-Host "  ok  browser telemetry, ad_topics & 3p_cookies = blocked" -ForegroundColor Green
        }
    } else {
        Write-Host "  --  browser policy registry targets Windows; use 'browser launch' for hardened flags on Unix" -ForegroundColor DarkGray
    }
}

function Clear-BrowserTraces {
    Clear-BrowserHistoryAndTraces
}

function Start-HardenedBrowser {
    param([string]$TargetBrowser)

    $browsers = Get-InstalledBrowsers
    $withExe = @($browsers | Where-Object { $_.Exe -and (Test-Path $_.Exe) })
    if ($withExe.Count -eq 0) {
        Write-Host "  [!] no supported browser executable found." -ForegroundColor Yellow
        return
    }

    $preferred = $null
    if ($TargetBrowser) {
        $preferred = $withExe | Where-Object { $_.Name -match [regex]::Escape($TargetBrowser) } | Select-Object -First 1
    }
    if (-not $preferred) {
        $preferred = $withExe | Select-Object -First 1
    }

    Write-Host "  launching $($preferred.Name) in hardened ephemeral OpSec mode..." -ForegroundColor Cyan

    if ($preferred.Engine -eq "Gecko") {
        Start-Process -FilePath $preferred.Exe -ArgumentList "-private-window"
    } else {
        $tempProfile = Join-Path ([System.IO.Path]::GetTempPath()) ("winopsec_ephemeral_" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
        $argsList = @(
            "--incognito",
            "--user-data-dir=`"$tempProfile`"",
            "--no-first-run",
            "--no-default-browser-check",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-translate",
            "--disable-features=OptimizationHints,MediaRouter,DialMediaRouteProvider,Translate"
        )
        Start-Process -FilePath $preferred.Exe -ArgumentList $argsList
    }
    Write-Host "  ok  $($preferred.Name) launched (WebRTC UDP blocked, isolated session)" -ForegroundColor Green
}

Export-ModuleMember -Function Get-InstalledBrowsers, Get-BrowserProfiles, Show-BrowserInventory, Audit-BrowserOpSec, Harden-Browsers, Clear-BrowserTraces, Clear-BrowserHistoryAndTraces, Remove-BrowserAccountTraces, Start-HardenedBrowser, Clear-BrowserAutofill
