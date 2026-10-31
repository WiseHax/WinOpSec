#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Unit tests for modules/Common.psm1 — the shared verify-by-readback helpers.
# These are deliberately side-effect-free: registry writes target a disposable
# HKCU test key that is removed in AfterAll. No admin rights required.

BeforeAll {
    $script:ModulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'modules/Common.psm1'
    Import-Module $script:ModulePath -Force -DisableNameChecking
    $script:TestKey = 'HKCU:\Software\WinOpSecTests'
}

AfterAll {
    if (Test-Path $script:TestKey) {
        Remove-Item $script:TestKey -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Test-IsWindowsOS' {
    It 'returns a boolean' {
        (Test-IsWindowsOS) | Should -BeOfType [bool]
    }
    It 'is true on a Windows host' -Skip:(-not $env:OS) {
        Test-IsWindowsOS | Should -BeTrue
    }
}

Describe 'Test-AdminPrivilege' {
    It 'returns a boolean without throwing' {
        { Test-AdminPrivilege } | Should -Not -Throw
        (Test-AdminPrivilege) | Should -BeOfType [bool]
    }
}

Describe 'Test-MullvadTunnel' {
    It 'returns a boolean and never throws' {
        { Test-MullvadTunnel } | Should -Not -Throw
        (Test-MullvadTunnel) | Should -BeOfType [bool]
    }
}

Describe 'Set-HardenedValue' {
    It 'writes a DWORD and reports Applied when readback matches' {
        $r = Set-HardenedValue -Path $script:TestKey -Name 'Flag' -Value 1 -Label 'test_flag'
        $r.Applied | Should -BeTrue
        $r.Actual  | Should -Be 1
        $r.Error   | Should -BeNullOrEmpty
        $r.Setting | Should -Be 'test_flag'
    }

    It 'creates the key path if it does not exist' {
        $sub = Join-Path $script:TestKey 'Nested'
        $r = Set-HardenedValue -Path $sub -Name 'X' -Value 7
        $r.Applied | Should -BeTrue
        Test-Path $sub | Should -BeTrue
    }

    It 'round-trips a string value' {
        $r = Set-HardenedValue -Path $script:TestKey -Name 'Name' -Value 'alpha' -Type String
        $r.Applied | Should -BeTrue
        $r.Actual  | Should -Be 'alpha'
    }

    It 'falls back to Name when no Label is given' {
        $r = Set-HardenedValue -Path $script:TestKey -Name 'Unlabeled' -Value 1
        $r.Setting | Should -Be 'Unlabeled'
    }
}

Describe 'Write-HardenGroup' {
    It 'does not throw on an all-applied result set' {
        $results = @(
            [PSCustomObject]@{ Setting = 'a'; Applied = $true;  Error = $null }
            [PSCustomObject]@{ Setting = 'b'; Applied = $true;  Error = $null }
        )
        { Write-HardenGroup -Label 'ok group' -Results $results } | Should -Not -Throw
    }

    It 'does not throw when some entries failed' {
        $results = @(
            [PSCustomObject]@{ Setting = 'a'; Applied = $true;  Error = $null }
            [PSCustomObject]@{ Setting = 'b'; Applied = $false; Error = 'readback mismatch' }
        )
        { Write-HardenGroup -Label 'mixed group' -Results $results } | Should -Not -Throw
    }

    It 'does not throw on an empty result set' {
        { Write-HardenGroup -Label 'empty' -Results @() } | Should -Not -Throw
    }
}
