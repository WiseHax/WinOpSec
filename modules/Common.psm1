# Common.psm1 - Shared helpers used across WinOpSec modules.
# Kept in one place so privilege/OS detection stays consistent everywhere.
# Imported first by WinOpSec.ps1; functions resolve from any module via global scope.

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

# Set a registry value and VERIFY it by reading it back. Returns a result
# object instead of blindly printing "ok", so callers can report honestly.
function Set-HardenedValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord','String','QWord','Binary','MultiString','ExpandString')][string]$Type = 'DWord',
        [string]$Label
    )
    $r = [PSCustomObject]@{
        Setting = $(if ($Label) { $Label } else { $Name })
        Path    = $Path
        Name    = $Name
        Desired = $Value
        Actual  = $null
        Applied = $false
        Error   = $null
    }
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
        $r.Actual = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        $r.Applied = ("$($r.Actual)" -eq "$Value")
        if (-not $r.Applied) { $r.Error = "readback mismatch (got '$($r.Actual)')" }
    } catch {
        $r.Error = $_.Exception.Message
    }
    return $r
}

# Stop + disable a service and verify it actually ended up disabled.
# An absent service counts as hardened (nothing to run).
function Set-ServiceDisabled {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    $r = [PSCustomObject]@{
        Setting = "service/$Name"; Desired = 'Disabled'; Actual = $null; Applied = $false; Error = $null
    }
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { $r.Applied = $true; $r.Actual = 'absent'; return $r }
    try {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
        $svc2 = Get-Service -Name $Name -ErrorAction SilentlyContinue
        $r.Actual   = if ($svc2) { "$($svc2.StartType)" } else { 'absent' }
        $r.Applied  = ($r.Actual -eq 'Disabled' -or $r.Actual -eq 'absent')
        if (-not $r.Applied) { $r.Error = "startup still $($r.Actual)" }
    } catch {
        $r.Error = $_.Exception.Message
    }
    return $r
}

# Print one honest summary line for a group of Set-HardenedValue /
# Set-ServiceDisabled results: green when all verified, else list failures.
function Write-HardenGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Results
    )
    $ok = @($Results | Where-Object { $_.Applied }).Count
    $total = $Results.Count
    $failed = @($Results | Where-Object { -not $_.Applied })
    if ($total -eq 0) {
        Write-Host ("  --   {0} (nothing to apply)" -f $Label) -ForegroundColor DarkGray
    } elseif ($failed.Count -eq 0) {
        Write-Host ("  ok   {0} ({1}/{2} applied & verified)" -f $Label, $ok, $total) -ForegroundColor Green
    } else {
        Write-Host ("  WARN {0} ({1}/{2} applied, {3} failed):" -f $Label, $ok, $total, $failed.Count) -ForegroundColor Yellow
        foreach ($f in $failed) {
            $why = if ($f.Error) { $f.Error } else { 'not applied' }
            Write-Host ("       x {0} -> {1}" -f $f.Setting, $why) -ForegroundColor Red
        }
    }
}
