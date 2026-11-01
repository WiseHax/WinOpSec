# PlatformSecurity.psm1 - modern Windows platform defenses that matter most
# against the 2026 threat landscape: virtualization-based security (Credential
# Guard / HVCI), Attack Surface Reduction rules, TPM, Secure Boot, and outbound
# NTLM/SMB exposure (e.g. CVE-2026-32202 Windows Shell coercion -> Net-NTLMv2 leak).
#
# Audits are read-only. Hardening writes are verified by readback where possible.
# Shared helpers (Test-AdminPrivilege / Set-HardenedValue / Write-HardenGroup)
# live in Common.psm1.

# Curated, high-value ASR rules. GUIDs are Microsoft's stable rule identifiers.
$script:AsrRules = [ordered]@{
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email/webmail'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office apps creating child processes'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office apps creating executable content'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations from PSExec/WMI'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted/unsigned processes from USB'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence via WMI event subscription'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JS/VBS from launching downloaded content'
}

function Get-PlatformSecurityPosture {
    $results = @()
    if (-not (Test-IsWindowsOS)) { return $results }

    # --- Virtualization-Based Security / Credential Guard / HVCI ---
    $dg = $null
    try { $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop } catch {}
    $vbsRunning = ($dg -and $dg.VirtualizationBasedSecurityStatus -eq 2)
    $svcRunning = @(); if ($dg -and $dg.SecurityServicesRunning) { $svcRunning = @($dg.SecurityServicesRunning) }
    $results += [PSCustomObject]@{
        Category = 'Platform'; Check = 'Virtualization-Based Security (VBS)'
        Status  = if ($vbsRunning) { 'HARDENED' } else { 'EXPOSED' }
        Details = if ($vbsRunning) { 'running' } elseif ($dg) { 'configured but not running' } else { 'unavailable/off' }
        Ref     = 'CIS 18.9.x; MITRE M1026'
    }
    $results += [PSCustomObject]@{
        Category = 'Platform'; Check = 'Credential Guard'
        Status  = if ($svcRunning -contains 1) { 'HARDENED' } else { 'EXPOSED' }
        Details = if ($svcRunning -contains 1) { 'running (LSA isolated)' } else { 'off (LSASS not VBS-isolated)' }
        Ref     = 'CIS 18.9.x; MITRE T1003.001'
    }
    $results += [PSCustomObject]@{
        Category = 'Platform'; Check = 'Memory Integrity (HVCI)'
        Status  = if ($svcRunning -contains 2) { 'HARDENED' } else { 'EXPOSED' }
        Details = if ($svcRunning -contains 2) { 'running' } else { 'off' }
        Ref     = 'CIS 18.9.x'
    }

    # --- Attack Surface Reduction rules ---
    $mp = $null
    if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
        try { $mp = Get-MpPreference -ErrorAction Stop } catch {}
    }
    if ($mp) {
        $ids = @(); $acts = @()
        if ($mp.AttackSurfaceReductionRules_Ids)     { $ids  = @($mp.AttackSurfaceReductionRules_Ids) }
        if ($mp.AttackSurfaceReductionRules_Actions) { $acts = @($mp.AttackSurfaceReductionRules_Actions) }
        $enabled = 0
        for ($i = 0; $i -lt $ids.Count; $i++) {
            if ($script:AsrRules.Contains($ids[$i]) -and "$($acts[$i])" -eq '1') { $enabled++ }
        }
        $want = $script:AsrRules.Count
        $results += [PSCustomObject]@{
            Category = 'Platform'; Check = 'Attack Surface Reduction (ASR)'
            Status  = if ($enabled -ge $want) { 'HARDENED' } elseif ($enabled -gt 0) { 'CONFIGURABLE' } else { 'EXPOSED' }
            Details = "$enabled/$want curated rules enforced"
            Ref     = 'MITRE M1042; MS ASR'
        }
    } else {
        $results += [PSCustomObject]@{
            Category = 'Platform'; Check = 'Attack Surface Reduction (ASR)'
            Status  = 'CONFIGURABLE'; Details = 'Defender ASR unavailable (3rd-party AV?)'; Ref = 'MS ASR'
        }
    }

    # --- TPM ---
    $tpm = $null
    if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
        try { $tpm = Get-Tpm -ErrorAction Stop } catch {}
    }
    $results += [PSCustomObject]@{
        Category = 'Platform'; Check = 'TPM 2.0'
        Status  = if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) { 'HARDENED' } elseif ($tpm -and $tpm.TpmPresent) { 'CONFIGURABLE' } else { 'EXPOSED' }
        Details = if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) { 'present & ready' } elseif ($tpm -and $tpm.TpmPresent) { 'present, not ready' } else { 'absent/unavailable' }
        Ref     = 'CIS 18.x'
    }

    # --- Secure Boot ---
    $sb = $null
    try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sb = $null }
    $results += [PSCustomObject]@{
        Category = 'Platform'; Check = 'Secure Boot'
        Status  = if ($sb -eq $true) { 'HARDENED' } elseif ($sb -eq $false) { 'EXPOSED' } else { 'CONFIGURABLE' }
        Details = if ($sb -eq $true) { 'enabled' } elseif ($sb -eq $false) { 'disabled' } else { 'legacy BIOS / not determinable' }
        Ref     = 'CIS 18.x; MITRE M1046'
    }

    # --- Outbound NTLM exposure (CVE-2026-32202 class: coercion -> Net-NTLMv2 leak) ---
    $ntlm = $null
    $lsaMsv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    if (Test-Path $lsaMsv) {
        $p = Get-ItemProperty -Path $lsaMsv -Name 'RestrictSendingNTLMTraffic' -ErrorAction SilentlyContinue
        if ($p) { $ntlm = $p.RestrictSendingNTLMTraffic }
    }
    $results += [PSCustomObject]@{
        Category = 'Platform'; Check = 'Outbound NTLM Restriction'
        Status  = if ($ntlm -ge 1) { 'HARDENED' } else { 'EXPOSED' }
        Details = switch ($ntlm) { 2 { 'deny all outbound NTLM' } 1 { 'audit outbound NTLM' } default { 'unrestricted (hash-leak risk)' } }
        Ref     = 'MITRE T1187; CVE-2026-32202'
    }

    # --- Outbound SMB (445) firewall block ---
    $smbRule = $null
    try { $smbRule = Get-NetFirewallRule -DisplayName 'WinOpSec-Block-Outbound-SMB' -ErrorAction SilentlyContinue } catch {}
    $results += [PSCustomObject]@{
        Category = 'Platform'; Check = 'Outbound SMB (445) Block'
        Status  = if ($smbRule -and $smbRule.Enabled -eq 'True') { 'HARDENED' } else { 'EXPOSED' }
        Details = if ($smbRule) { 'blocked outbound' } else { 'allowed (coercion/relay exposure)' }
        Ref     = 'MITRE T1187; CVE-2026-32202'
    }

    return $results
}

function Protect-PlatformSecurity {
    if (-not (Test-IsWindowsOS)) {
        Write-Host "  --   platform security hardening is Windows-only" -ForegroundColor DarkGray
        return
    }
    if (-not (Test-AdminPrivilege)) {
        Write-Host "  --   skipped platform hardening (requires admin)" -ForegroundColor DarkYellow
        return
    }

    # ASR rules (verified by readback against Get-MpPreference).
    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
        $asrRes = @()
        foreach ($id in $script:AsrRules.Keys) {
            $r = [PSCustomObject]@{ Setting = $script:AsrRules[$id]; Applied = $false; Error = $null }
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
                $mp = Get-MpPreference -ErrorAction Stop
                $ids = @($mp.AttackSurfaceReductionRules_Ids); $acts = @($mp.AttackSurfaceReductionRules_Actions)
                for ($i = 0; $i -lt $ids.Count; $i++) {
                    if ($ids[$i] -eq $id) { $r.Applied = ("$($acts[$i])" -eq '1'); break }
                }
                if (-not $r.Applied) { $r.Error = 'not enforced after set' }
            } catch { $r.Error = $_.Exception.Message }
            $asrRes += $r
        }
        Write-HardenGroup -Label 'attack surface reduction rules' -Results $asrRes
    } else {
        Write-Host "  --   ASR unavailable (Defender not present / 3rd-party AV)" -ForegroundColor DarkGray
    }

    # Outbound NTLM: audit by default (value 1) — non-breaking; set 2 manually to deny all.
    $ntlmRes = @()
    $ntlmRes += Set-HardenedValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic' -Value 1 -Label 'outbound_ntlm_audit'
    Write-HardenGroup -Label 'outbound NTLM restriction' -Results $ntlmRes

    # Outbound SMB(445) block — reversible named firewall rule.
    if (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue) {
        try {
            Get-NetFirewallRule -DisplayName 'WinOpSec-Block-Outbound-SMB' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName 'WinOpSec-Block-Outbound-SMB' -Direction Outbound -Action Block `
                -Protocol TCP -RemotePort 445 -Profile Any -ErrorAction Stop | Out-Null
            $rule = Get-NetFirewallRule -DisplayName 'WinOpSec-Block-Outbound-SMB' -ErrorAction SilentlyContinue
            if ($rule -and $rule.Enabled -eq 'True') {
                Write-Host "  ok   outbound SMB (445) blocked (anti-coercion / NTLM-leak)" -ForegroundColor Green
            } else {
                Write-Host "  WARN outbound SMB block rule not confirmed" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  WARN outbound SMB block failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

Export-ModuleMember -Function Get-PlatformSecurityPosture, Protect-PlatformSecurity
