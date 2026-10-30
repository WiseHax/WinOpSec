# Shared helper Test-IsWindowsOS lives in Common.psm1

function Get-UserHome {
    if ($HOME) { return $HOME }
    if ($env:USERPROFILE) { return $env:USERPROFILE }
    return [Environment]::GetFolderPath("UserProfile")
}

function Audit-DiskEncryption {
    if (Test-IsWindowsOS) {
        $bitlocker = $null
        try {
            if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
                $sysDrive = if ($env:SystemDrive) { $env:SystemDrive } else { "C:" }
                $bl = Get-BitLockerVolume -MountPoint $sysDrive -ErrorAction SilentlyContinue
                if ($bl) {
                    $bitlocker = $bl.ProtectionStatus.ToString()
                }
            }
        } catch {}

        return [PSCustomObject]@{
            Target  = "System Volume ($($env:SystemDrive))"
            Status  = if ($bitlocker -eq "On") { "ENCRYPTED" } else { "CONFIGURABLE" }
            Details = if ($bitlocker -eq "On") { "BitLocker: On" } else { "BitLocker: Off (manual FDE setup recommended)" }
        }
    } elseif ($IsMacOS) {
        $fv = (fdesetup status 2>$null)
        $isOn = ($fv -match "FileVault is On")
        return [PSCustomObject]@{
            Target  = "Root Volume (/)"
            Status  = if ($isOn) { "ENCRYPTED" } else { "CONFIGURABLE" }
            Details = if ($fv) { $fv.Trim() } else { "FileVault status unknown" }
        }
    } else {
        $lsblk = (lsblk -o TYPE 2>$null)
        $hasCrypt = ($lsblk -match "crypt")
        return [PSCustomObject]@{
            Target  = "Block Devices"
            Status  = if ($hasCrypt) { "ENCRYPTED" } else { "CONFIGURABLE" }
            Details = if ($hasCrypt) { "dm-crypt/LUKS active" } else { "no active crypt targets detected" }
        }
    }
}

function Scan-ExposedSecrets {
    param (
        [string[]]$ScanPaths
    )

    $uHome = Get-UserHome
    if (-not $ScanPaths) {
        $ScanPaths = @(
            (Join-Path $uHome "Desktop"),
            (Join-Path $uHome "Documents"),
            (Join-Path $uHome ".ssh"),
            (Join-Path $uHome ".aws"),
            (Join-Path $uHome ".kube"),
            (Join-Path $uHome ".config")
        )
    }

    $findings = @()

    $sensitivePatterns = @(
        "id_rsa", "id_ed25519", "id_ecdsa", "*.pem", "*.key", "*.ppk", "*.pfx", "*.p12",
        ".env", ".env.local", ".env.production",
        ".git-credentials", ".netrc", ".npmrc", ".pypirc",
        "*credential*", "*password*.txt", "*secret*.txt", "*seed*.txt", "*recovery*.txt"
    )

    foreach ($path in $ScanPaths) {
        if (-not (Test-Path $path)) { continue }
        Write-Host "  scanning $path" -ForegroundColor DarkGray

        foreach ($pattern in $sensitivePatterns) {
            $matches = Get-ChildItem -Path $path -Filter $pattern -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.FullName -notmatch "node_modules|\.git\\|AppData|venv|\.rustup|\.cache|\.cargo" -and
                    $_.Name -notin @("aws_vault_backup.env", "wallet_recovery_phrase.txt", "finance_passwords.kdbx") -and
                    $_.Name -notmatch "_decoy\."
                }

            foreach ($file in $matches) {
                $findings += [PSCustomObject]@{
                    File = $file.FullName
                    Type = "file:$pattern"
                    Risk = "high"
                }
            }
        }
    }

    $regexList = @{
        "aws_access_key"  = "AKIA[0-9A-Z]{16}"
        "github_token"    = "(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}"
        "slack_token"     = "xox[baprs]-[0-9A-Za-z]{10,48}"
        "openai_api_key"  = "sk-(proj-)?[A-Za-z0-9_-]{32,}"
        "google_api_key"  = "AIza[0-9A-Za-z\-_]{35}"
        "stripe_live_key" = "sk_live_[0-9a-zA-Z]{24,}"
        "discord_token"   = "[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}"
        "private_key"     = "-----BEGIN [A-Z ]*PRIVATE KEY-----"
    }

    $docPaths = @((Join-Path $uHome "Desktop"), (Join-Path $uHome "Documents")) | Where-Object { Test-Path $_ }
    if ($docPaths.Count -gt 0) {
        $textFiles = Get-ChildItem -Path $docPaths -Include "*.txt", "*.env*", "*.json", "*.yml", "*.yaml", "*.conf", "*.ini" -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Length -lt 1MB -and
                $_.FullName -notmatch "node_modules|\.git|\.vscode" -and
                $_.Name -notin @("aws_vault_backup.env", "wallet_recovery_phrase.txt", "finance_passwords.kdbx") -and
                $_.Name -notmatch "_decoy\."
            }

        foreach ($file in $textFiles) {
            try {
                $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    foreach ($key in $regexList.Keys) {
                        if ($content -match $regexList[$key]) {
                            $findings += [PSCustomObject]@{
                                File = $file.FullName
                                Type = "regex:$key"
                                Risk = "crit"
                            }
                        }
                    }
                }
            } catch {}
        }
    }

    return $findings
}

Export-ModuleMember -Function Audit-DiskEncryption, Scan-ExposedSecrets
