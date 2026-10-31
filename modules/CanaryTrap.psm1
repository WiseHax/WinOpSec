# CanaryTrap.psm1 - High-Value Honeytoken Breach Tripwire
# WinOpSec Defensive Suite

function Test-SafePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        return (Test-Path -LiteralPath $Path -ErrorAction Stop)
    } catch {
        return $false
    }
}

function Get-KnownUserDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FolderName,
        [System.Environment+SpecialFolder]$SpecialFolder
    )

    $resolved = ""
    try {
        if ($SpecialFolder) {
            $resolved = [Environment]::GetFolderPath($SpecialFolder)
        }
    } catch {}

    if ([string]::IsNullOrWhiteSpace($resolved) -or -not (Test-SafePath $resolved)) {
        $base = if ($env:USERPROFILE -and (Test-SafePath $env:USERPROFILE)) {
            $env:USERPROFILE
        } elseif ($HOME -and (Test-SafePath $HOME)) {
            $HOME
        } else {
            "C:\Users\$env:USERNAME"
        }

        # Check OneDrive folder redirection first
        $oneDrivePath = Join-Path $base "OneDrive\$FolderName"
        if (Test-SafePath $oneDrivePath) {
            $resolved = $oneDrivePath
        } else {
            $resolved = Join-Path $base $FolderName
        }
    }

    return $resolved
}

function Get-CanaryBaitPaths {
    $desktopDir = Get-KnownUserDirectory -FolderName "Desktop" -SpecialFolder ([System.Environment+SpecialFolder]::Desktop)
    $docsDir    = Get-KnownUserDirectory -FolderName "Documents" -SpecialFolder ([System.Environment+SpecialFolder]::Personal)
    $dlDir      = Get-KnownUserDirectory -FolderName "Downloads"

    return @(
        @{
            Path        = Join-Path $desktopDir "aws_vault_backup.env"
            Description = "Cloud Credentials Honeytoken"
            Content     = "# AWS PRODUCTION CREDENTIALS BACKUP`nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`nAWS_DEFAULT_REGION=us-east-1`n"
        },
        @{
            Path        = Join-Path $docsDir "wallet_recovery_phrase.txt"
            Description = "Cryptographic Seed Honeytoken"
            Content     = "RECOVERY SEED PHRASE - KEEP OFFLINE`n1. abandon  2. ability  3. able  4. about`n5. above    6. absent   7. absorb 8. abstract`n9. absurd   10. abuse   11. access 12. accident`n"
        },
        @{
            Path        = Join-Path $dlDir "finance_passwords.kdbx"
            Description = "Encrypted Vault Honeytoken"
            # Standard KeePass KDBX4 magic bytes: 0x03 0xD9 0xA2 0x9A, 0x67 0xFB 0x4B 0xB5
            Bytes       = [byte[]]@(0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00)
        }
    )
}

function Get-CanaryManifestPath {
    $parent = Split-Path -Parent $PSScriptRoot
    $backupDir = Join-Path $parent "backups"
    if (-not (Test-SafePath $backupDir)) {
        try { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null } catch {}
    }
    return (Join-Path $backupDir "canary_manifest.json")
}

function Install-CanaryTraps {
    [CmdletBinding()]
    param([switch]$Silent)

    $baits = Get-CanaryBaitPaths
    $deployed = 0

    if (-not $Silent) {
        Write-Host "`n  deploying canary honeytoken breach traps..." -ForegroundColor Cyan
        Write-Host "  planting realistic decoy secrets in Desktop, Documents, Downloads..." -ForegroundColor Gray
    }

    foreach ($b in $baits) {
        try {
            $dir = Split-Path $b.Path -Parent
            if (-not (Test-SafePath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

            if ($b.Bytes) {
                [System.IO.File]::WriteAllBytes($b.Path, $b.Bytes)
            } else {
                Set-Content -LiteralPath $b.Path -Value $b.Content -Force -Encoding UTF8
            }

            # Set Not Content Indexed attribute so Windows Search Indexer does not crawl the decoy
            attrib +i "$($b.Path)" 2>$null | Out-Null

            # Set realistic natural timestamp (14 days ago)
            $item = Get-Item -LiteralPath $b.Path -Force
            $item.CreationTime   = (Get-Date).AddDays(-14).AddHours(-3)
            $item.LastWriteTime  = (Get-Date).AddDays(-14).AddHours(-2)
            $item.LastAccessTime = (Get-Date).AddDays(-14).AddHours(-1)

            $deployed++
            if (-not $Silent) {
                Write-Host "  [+] armed : $($b.Path)" -ForegroundColor DarkGray
            }
        } catch {
            if (-not $Silent) {
                Write-Host "  [!] failed to plant $($b.Path): $_" -ForegroundColor DarkGray
            }
        }
    }

    # Record post-deployment baseline manifest so background scanners don't self-trip
    $manifest = @{}
    foreach ($b in $baits) {
        if (Test-SafePath $b.Path) {
            try {
                $item = Get-Item -LiteralPath $b.Path -Force -ErrorAction Stop
                $manifest[$b.Path] = @{
                    AccessTime = $item.LastAccessTime.ToString("o")
                    WriteTime  = $item.LastWriteTime.ToString("o")
                    Length     = $item.Length
                    DeployTime = (Get-Date).ToString("o")
                }
            } catch {}
        }
    }

    try {
        $mPath = Get-CanaryManifestPath
        $manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $mPath -Force
    } catch {}

    if (-not $Silent) {
        Write-Host "  ok  $deployed honeytoken breach traps active. Sentry will monitor accesses.`n" -ForegroundColor Green
    }
    return $deployed
}

function Get-CanaryTrapState {
    $baits = Get-CanaryBaitPaths
    $results = @()
    $manifest = $null
    $mPath = Get-CanaryManifestPath
    if (Test-SafePath $mPath) {
        try {
            $rawJson = Get-Content -LiteralPath $mPath -Raw -ErrorAction SilentlyContinue
            if ($rawJson) {
                $manifest = $rawJson | ConvertFrom-Json
            }
        } catch {}
    }

    foreach ($b in $baits) {
        $p = $b.Path
        $exists = Test-SafePath $p
        
        $state = "MISSING"
        $detail = "Trap not deployed"

        if ($exists) {
            try {
                $item = Get-Item -LiteralPath $p -Force -ErrorAction Stop
                $isTripped = $false

                if ($manifest -and $manifest.PSObject.Properties[$p]) {
                    $entry = $manifest.PSObject.Properties[$p].Value
                    $baseWrite  = [DateTime]$entry.WriteTime
                    $baseLen    = [int64]$entry.Length
                    $deployTime = if ($entry.DeployTime) { [DateTime]$entry.DeployTime } else { [DateTime]$entry.AccessTime }

                    # A real breach occurs if the honeytoken was read after deployment (with 30s grace window) or modified/resized
                    if ($item.LastAccessTime -gt $deployTime.AddSeconds(30)) {
                        $isTripped = $true
                        $detail = "UNAUTHORIZED READ: Opened at $($item.LastAccessTime.ToString('HH:mm:ss'))"
                    } elseif ($item.LastWriteTime -ne $baseWrite -or $item.Length -ne $baseLen) {
                        $isTripped = $true
                        $detail = "UNAUTHORIZED TAMPER: Modified at $($item.LastWriteTime.ToString('HH:mm:ss'))"
                    }
                } else {
                    if (($item.LastAccessTime -gt (Get-Date).AddMinutes(-60)) -and ($item.LastAccessTime -gt $item.LastWriteTime.AddMinutes(5))) {
                        $isTripped = $true
                        $detail = "UNAUTHORIZED ACCESS: Accessed at $($item.LastAccessTime.ToString('HH:mm:ss'))"
                    }
                }

                if ($isTripped) {
                    $state = "TRIPPED"
                } else {
                    $state = "ARMED"
                    $detail = "Active & untouched ($($item.Length) bytes)"
                }
            } catch {
                $state = "LOCKED"
                $detail = "File exists (access restricted)"
            }
        }

        $results += [PSCustomObject]@{
            Trap        = (Split-Path $b.Path -Leaf)
            Description = $b.Description
            State       = $state
            Details     = $detail
            Path        = $b.Path
        }
    }

    return $results
}

function Test-CanaryTrip {
    $traps = Get-CanaryTrapState
    $tripped = @($traps | Where-Object { $_.State -eq "TRIPPED" })
    return $tripped
}

function Remove-CanaryTraps {
    [CmdletBinding()]
    param()

    Write-Host "`n  purging canary honeytoken traps..." -ForegroundColor Cyan
    $baits = Get-CanaryBaitPaths
    $purged = 0

    foreach ($b in $baits) {
        if (Test-Path -LiteralPath $b.Path) {
            try {
                # Zero overwrite before delete
                $len = (Get-Item -LiteralPath $b.Path -Force).Length
                if ($len -gt 0) {
                    $zeroes = New-Object byte[] $len
                    [System.IO.File]::WriteAllBytes($b.Path, $zeroes)
                }
                Remove-Item -LiteralPath $b.Path -Force -ErrorAction SilentlyContinue
                Write-Host "  ok  purged: $($b.Path)" -ForegroundColor Gray
                $purged++
            } catch {}
        }
    }

    $mPath = Get-CanaryManifestPath
    if (Test-SafePath $mPath) {
        try { Remove-Item -LiteralPath $mPath -Force -ErrorAction SilentlyContinue } catch {}
    }

    Write-Host "  ok  $purged canary traps removed.`n" -ForegroundColor Green
}

Export-ModuleMember -Function Get-CanaryBaitPaths, Install-CanaryTraps, Get-CanaryTrapState, Test-CanaryTrip, Remove-CanaryTraps
