# IntegrityGuard.psm1 - detect tampering of WinOpSec's own code.
# A security tool must be able to prove it has not been modified by a
# supply-chain attacker. New-IntegrityBaseline records SHA-256 hashes of every
# script/module; Test-ModuleIntegrity re-verifies them. Read-only except for the
# explicit baseline write.

function Get-IntegrityManifestPath {
    $parent = Split-Path -Parent $PSScriptRoot
    $backupDir = Join-Path $parent "backups"
    if (-not (Test-Path $backupDir)) {
        try { New-Item -ItemType Directory -Path $backupDir -Force -ErrorAction Stop | Out-Null } catch { return $null }
    }
    return (Join-Path $backupDir "integrity_manifest.json")
}

function Get-IntegrityTargets {
    $root = Split-Path -Parent $PSScriptRoot
    $files = @()
    $files += Get-ChildItem -Path (Join-Path $root 'modules') -Filter '*.psm1' -File -ErrorAction SilentlyContinue
    foreach ($n in @('WinOpSec.ps1','WinOpSec.psd1')) {
        $p = Join-Path $root $n
        if (Test-Path $p) { $files += Get-Item $p }
    }
    return $files
}

function New-IntegrityBaseline {
    $path = Get-IntegrityManifestPath
    if (-not $path) { Write-Host "  [!] cannot write baseline (no backups dir)" -ForegroundColor Red; return }
    $root = Split-Path -Parent $PSScriptRoot
    $map = @{}
    foreach ($f in (Get-IntegrityTargets)) {
        $rel = $f.FullName.Substring($root.Length).TrimStart('\','/')
        $map[$rel] = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash
    }
    $manifest = [PSCustomObject]@{
        Generated = (Get-Date).ToString('o')
        Algorithm = 'SHA256'
        Files     = $map
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8
    Write-Host ("  ok   integrity baseline recorded ({0} files) -> {1}" -f $map.Count, (Split-Path $path -Leaf)) -ForegroundColor Green
}

function Test-ModuleIntegrity {
    $results = @()
    $path = Get-IntegrityManifestPath
    $root = Split-Path -Parent $PSScriptRoot

    $baseline = $null
    if ($path -and (Test-Path $path)) {
        try { $baseline = Get-Content $path -Raw | ConvertFrom-Json } catch {}
    }
    if (-not $baseline) {
        $results += [PSCustomObject]@{ File = '(no baseline)'; Status = 'CONFIGURABLE'; Details = "run 'integrity baseline' to record trusted hashes" }
        return $results
    }

    $seen = @{}
    foreach ($f in (Get-IntegrityTargets)) {
        $rel = $f.FullName.Substring($root.Length).TrimStart('\','/')
        $seen[$rel] = $true
        $actual = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash
        $expected = $baseline.Files.$rel
        if (-not $expected) {
            $results += [PSCustomObject]@{ File = $rel; Status = 'EXPOSED'; Details = 'NEW file not in baseline' }
        } elseif ($expected -eq $actual) {
            $results += [PSCustomObject]@{ File = $rel; Status = 'CLEAN'; Details = 'verified (SHA256 match)' }
        } else {
            $results += [PSCustomObject]@{ File = $rel; Status = 'FAIL'; Details = 'MODIFIED since baseline!' }
        }
    }
    foreach ($rel in $baseline.Files.PSObject.Properties.Name) {
        if (-not $seen.ContainsKey($rel)) {
            $results += [PSCustomObject]@{ File = $rel; Status = 'FAIL'; Details = 'MISSING (was in baseline)' }
        }
    }
    return $results
}

Export-ModuleMember -Function New-IntegrityBaseline, Test-ModuleIntegrity, Get-IntegrityManifestPath
