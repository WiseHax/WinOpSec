# Shared helper Test-IsWindowsOS lives in Common.psm1

function Get-DecoyDocumentDirectory {
    $docDir = [Environment]::GetFolderPath("MyDocuments")
    if (-not $docDir -or -not (Test-Path $docDir)) {
        $docDir = Join-Path $env:USERPROFILE "Documents"
    }
    return $docDir
}

function Audit-ChameleonState {
    $results = @()
    if (-not (Test-IsWindowsOS)) { return $results }

    $docDir = Get-DecoyDocumentDirectory
    $decoys = @(Get-ChildItem -Path $docDir -Filter "*_decoy.*" -Force -ErrorAction SilentlyContinue)
    $recentLinks = @(Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Recent" -Filter "*_decoy*.lnk" -Force -ErrorAction SilentlyContinue)

    $hasNoise = ($decoys.Count -gt 0)
    $results += [PSCustomObject]@{
        Profile  = "Chameleon Plausible Deniability"
        Decoys   = "$($decoys.Count) decoy documents"
        Recent   = "$($recentLinks.Count) synthetic links"
        Posture  = if ($hasNoise) { "CIVILIAN_CAMOUFLAGE" } else { "NAKED_ZERO" }
    }
    return $results
}

function Invoke-ChameleonNoise {
    param([switch]$Purge)

    if (-not (Test-IsWindowsOS)) {
        Write-Host "  [!] Forensic Chameleon is supported on Windows hosts." -ForegroundColor Yellow
        return
    }

    $docDir = Get-DecoyDocumentDirectory
    if (-not (Test-Path $docDir)) { New-Item -Path $docDir -ItemType Directory -Force | Out-Null }

    if ($Purge) {
        Write-Host "  -- removing synthetic chameleon camouflage..." -ForegroundColor Cyan
        Get-ChildItem -Path $docDir -Filter "*_decoy.*" -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Recent" -Filter "*_decoy*.lnk" -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Host "  ok  synthetic camouflage purged (reverted to zero-state)" -ForegroundColor Green
        return
    }

    Write-Host "`n  [+] Injecting Forensic Chameleon plausible deniability noise..." -ForegroundColor Cyan
    Write-Host "  defense: Defeats SANS FOR500 'Too Clean Machine' / Evidence of Absence doctrine" -ForegroundColor DarkGray

    # 1. Generate realistic civilian document payloads
    $decoyTemplates = @(
        @{ Name = "Household_Budget_2026_decoy.txt"; Content = "# Personal Monthly Expenses 2026`nRent: `$1,200`nUtilities: `$180`nGroceries: `$450`nInternet: `$75`nSavings Target: `$500/mo" },
        @{ Name = "Italian_Pasta_Recipes_decoy.txt"; Content = "Classic Carbonara:`n- 400g Spaghetti`n- 150g Guanciale or Pancetta`n- 4 large egg yolks`n- 100g Pecorino Romano`n- Freshly cracked black pepper" },
        @{ Name = "Home_Renovation_Notes_decoy.txt"; Content = "Kitchen Remodel Tasklist:`n1. Measure countertop dimensions`n2. Inspect plumbing fittings under sink`n3. Pick ceramic tile backsplash`n4. Request quote from contractor" },
        @{ Name = "Fitness_Weekly_Routine_decoy.txt"; Content = "Weekly Training Schedule:`nMon: Upper Body Strength (Push)`nTue: 5km Cardio Zone 2`nWed: Lower Body & Core`nThu: Rest & Mobility`nFri: Full Body Circuit" },
        @{ Name = "College_Reading_List_decoy.txt"; Content = "Selected Readings - Spring Semester:`n- Chapter 4: Microeconomic Foundations`n- Chapter 7: Statistical Analysis & Probability`n- Modern World History Review Questions" }
    )

    $createdDecoys = @()
    foreach ($item in $decoyTemplates) {
        $filePath = Join-Path $docDir $item.Name
        try {
            Set-Content -Path $filePath -Value $item.Content -Force
            # Stagger realistic historical timestamps (2 to 14 days ago)
            $pastDays = Get-Random -Minimum 2 -Maximum 15
            $fakeTime = (Get-Date).AddDays(-$pastDays).AddMinutes((Get-Random -Minimum 10 -Maximum 500))
            (Get-Item $filePath).CreationTime   = $fakeTime
            (Get-Item $filePath).LastWriteTime  = $fakeTime
            (Get-Item $filePath).LastAccessTime = (Get-Date).AddHours(-(Get-Random -Minimum 1 -Maximum 12))
            $createdDecoys += $filePath
        } catch {}
    }
    Write-Host "  ok  planted $($createdDecoys.Count) benign civilian documents in Documents" -ForegroundColor Green

    # 2. Register synthetic Recent Document (.lnk) shortcuts
    $recentDir = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recentDir) {
        $wsh = New-Object -ComObject WScript.Shell
        foreach ($cd in $createdDecoys) {
            $baseName = [System.IO.Path]::GetFileName($cd)
            $lnkPath = Join-Path $recentDir "$baseName.lnk"
            try {
                $sc = $wsh.CreateShortcut($lnkPath)
                $sc.TargetPath = $cd
                $sc.WorkingDirectory = $docDir
                $sc.Save()
            } catch {}
        }
        Write-Host "  ok  seeded realistic Recent Docs shortcuts (.lnk) with historical timestamps" -ForegroundColor Green
    }

    # 3. Seed benign TypedPaths in Explorer
    try {
        $typedPathKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
        if (-not (Test-Path $typedPathKey)) { New-Item -Path $typedPathKey -Force | Out-Null }
        Set-ItemProperty -Path $typedPathKey -Name "url1" -Value "C:\Users\$env:USERNAME\Documents" -Force
        Set-ItemProperty -Path $typedPathKey -Name "url2" -Value "C:\Users\$env:USERNAME\Downloads" -Force
        Set-ItemProperty -Path $typedPathKey -Name "url3" -Value "C:\Program Files" -Force
        Write-Host "  ok  seeded plausible civilian Explorer TypedPaths" -ForegroundColor Green
    } catch {}

    # 4. Seed benign WordWheelQuery search MRU
    try {
        $wwqKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
        if (-not (Test-Path $wwqKey)) { New-Item -Path $wwqKey -Force | Out-Null }
        Set-ItemProperty -Path $wwqKey -Name "0" -Value ([System.Text.Encoding]::Unicode.GetBytes("budget`0")) -Force
        Set-ItemProperty -Path $wwqKey -Name "MRUListEx" -Value ([byte[]]@(0,0,0,0,255,255,255,255)) -Force
        Write-Host "  ok  seeded ordinary Explorer desktop searches ('budget')" -ForegroundColor Green
    } catch {}

    Write-Host "`n  [+] CIVILIAN PROFILE ACTIVE: Machine presents natural civilian timeline to DFIR examiners." -ForegroundColor Green
    Write-Host "  tip: use 'chameleon -purge' anytime to remove synthetic camouflage.`n" -ForegroundColor DarkGray
}

Export-ModuleMember -Function Audit-ChameleonState, Invoke-ChameleonNoise
