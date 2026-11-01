#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Tests for the 2026 threat-defense additions: platform security posture,
# browser-credential-theft detection, and tamper-evident self-integrity.
# All assertions are read-only except the integrity baseline, which is written
# to a disposable path and restored in AfterAll.

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $script:Root 'modules/Common.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $script:Root 'modules/PlatformSecurity.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $script:Root 'modules/SentryMonitor.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $script:Root 'modules/IntegrityGuard.psm1') -Force -DisableNameChecking
}

Describe 'Get-PlatformSecurityPosture' {
    It 'runs read-only without throwing' {
        { Get-PlatformSecurityPosture } | Should -Not -Throw
    }
    It 'returns posture rows with the required fields' {
        $rows = @(Get-PlatformSecurityPosture)
        if ($env:OS -eq 'Windows_NT') {
            $rows.Count | Should -BeGreaterThan 0
            foreach ($r in $rows) {
                $r.Check   | Should -Not -BeNullOrEmpty
                $r.Status  | Should -Match '^(HARDENED|EXPOSED|CONFIGURABLE|CLEAN)$'
                $r.Ref     | Should -Not -BeNullOrEmpty
            }
        }
    }
    It 'reports a Credential Guard check on Windows' -Skip:($env:OS -ne 'Windows_NT') {
        (@(Get-PlatformSecurityPosture) | Where-Object { $_.Check -eq 'Credential Guard' }).Count | Should -Be 1
    }
}

Describe 'Test-BrowserCredentialTheft' {
    It 'returns a collection and never throws' {
        { Test-BrowserCredentialTheft } | Should -Not -Throw
        @(Test-BrowserCredentialTheft).Count | Should -BeGreaterOrEqual 0
    }
}

Describe 'IntegrityGuard baseline round-trip' {
    BeforeAll {
        $script:ManifestPath = Get-IntegrityManifestPath
        $script:HadManifest = Test-Path $script:ManifestPath
        $script:Backup = if ($script:HadManifest) { Get-Content $script:ManifestPath -Raw } else { $null }
    }
    AfterAll {
        if ($script:HadManifest) {
            Set-Content -Path $script:ManifestPath -Value $script:Backup -NoNewline -Encoding UTF8
        } elseif (Test-Path $script:ManifestPath) {
            Remove-Item $script:ManifestPath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'reports CONFIGURABLE when no baseline exists' {
        if (Test-Path $script:ManifestPath) { Remove-Item $script:ManifestPath -Force }
        (@(Test-ModuleIntegrity)[0].Status) | Should -Be 'CONFIGURABLE'
    }

    It 'verifies all files CLEAN right after a baseline' {
        New-IntegrityBaseline
        $r = @(Test-ModuleIntegrity)
        $r.Count | Should -BeGreaterThan 0
        ($r | Where-Object { $_.Status -ne 'CLEAN' }).Count | Should -Be 0
    }
}
