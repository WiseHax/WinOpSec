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

function Audit-HardwareIdentity {
    $results = @()
    if (-not (Test-IsWindowsOS)) {
        return $results
    }

    # 1. Cryptography MachineGuid
    $cryptoKey = "HKLM:\SOFTWARE\Microsoft\Cryptography"
    $machineGuid = "unknown"
    if (Test-Path $cryptoKey) {
        $prop = Get-ItemProperty -Path $cryptoKey -Name "MachineGuid" -ErrorAction SilentlyContinue
        if ($prop -and $prop.MachineGuid) { $machineGuid = $prop.MachineGuid }
    }
    $results += [PSCustomObject]@{
        Category = "HardwareIdentity"
        Artifact = "Crypto MachineGuid"
        Value    = $machineGuid
        Risk     = "high"
        Status   = "TRACKABLE"
    }

    # 2. SQM Client MachineId
    $sqmKey = "HKLM:\SOFTWARE\Microsoft\SQMClient"
    $sqmId = "none"
    if (Test-Path $sqmKey) {
        $prop = Get-ItemProperty -Path $sqmKey -Name "MachineId" -ErrorAction SilentlyContinue
        if ($prop -and $prop.MachineId) { $sqmId = $prop.MachineId }
    }
    $results += [PSCustomObject]@{
        Category = "HardwareIdentity"
        Artifact = "SQM MachineId"
        Value    = $sqmId
        Risk     = "med"
        Status   = if ($sqmId -eq "none") { "CLEAN" } else { "TRACKABLE" }
    }

    # 3. Windows NT BuildGUID & ProductId
    $ntKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $buildGuid = "none"
    $productId = "none"
    if (Test-Path $ntKey) {
        $prop = Get-ItemProperty -Path $ntKey -ErrorAction SilentlyContinue
        if ($prop) {
            if ($prop.BuildGUID) { $buildGuid = $prop.BuildGUID }
            if ($prop.ProductId) { $productId = $prop.ProductId }
        }
    }
    $results += [PSCustomObject]@{
        Category = "HardwareIdentity"
        Artifact = "BuildGUID"
        Value    = $buildGuid
        Risk     = "low"
        Status   = "TRACKABLE"
    }
    $results += [PSCustomObject]@{
        Category = "HardwareIdentity"
        Artifact = "Windows ProductId"
        Value    = $productId
        Risk     = "med"
        Status   = "TRACKABLE"
    }

    return $results
}

function Invoke-HwIdRandomize {
    if (-not (Test-IsWindowsOS)) {
        Write-Host "  [!] Hardware ID randomization is supported on Windows hosts only." -ForegroundColor Yellow
        return
    }

    if (-not (Test-AdminPrivilege)) {
        Write-Host "  [!] Randomizing hardware and machine GUIDs requires administrator privileges." -ForegroundColor Yellow
        return
    }

    Write-Host "  -- generating cryptographically random hardware identifiers..." -ForegroundColor Cyan

    try {
        # 1. Randomize Cryptography MachineGuid
        $newMachineGuid = [Guid]::NewGuid().ToString()
        $cryptoKey = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        if (-not (Test-Path $cryptoKey)) { New-Item -Path $cryptoKey -Force | Out-Null }
        Set-ItemProperty -Path $cryptoKey -Name "MachineGuid" -Type String -Value $newMachineGuid -Force
        Write-Host "  ok  MachineGuid -> $newMachineGuid" -ForegroundColor Green

        # 2. Randomize SQMClient MachineId
        $newSqmId = "{" + [Guid]::NewGuid().ToString().ToUpper() + "}"
        $sqmKey = "HKLM:\SOFTWARE\Microsoft\SQMClient"
        if (-not (Test-Path $sqmKey)) { New-Item -Path $sqmKey -Force | Out-Null }
        Set-ItemProperty -Path $sqmKey -Name "MachineId" -Type String -Value $newSqmId -Force
        Write-Host "  ok  SQM MachineId -> $newSqmId" -ForegroundColor Green

        # 3. Randomize Windows BuildGUID
        $newBuildGuid = [Guid]::NewGuid().ToString()
        $ntKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        if (Test-Path $ntKey) {
            Set-ItemProperty -Path $ntKey -Name "BuildGUID" -Type String -Value $newBuildGuid -Force -ErrorAction SilentlyContinue
            Write-Host "  ok  BuildGUID -> $newBuildGuid" -ForegroundColor Green
        }

        Write-Host "  ok  hardware identity anchors randomized (defeats persistent device fingerprinting)." -ForegroundColor Green
    } catch {
        Write-Host "  !!  hardware randomization failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Export-ModuleMember -Function Audit-HardwareIdentity, Invoke-HwIdRandomize
