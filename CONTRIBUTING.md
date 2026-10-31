# Contributing to WinOpSec

Thanks for your interest in improving WinOpSec. This is a defensive Windows
OpSec toolkit; contributions should keep that scope and the project's "report
honestly, never fake a PASS" philosophy.

## Project layout

```
WinOpSec.ps1        Entry point: arg parsing, interactive REPL, HUD, menu
modules/            One .psm1 per capability, imported by WinOpSec.ps1
  Common.psm1         Shared helpers (privilege/OS detection, verified writes)
  Telemetry.psm1      OS telemetry + credential/memory hardening
  Anonymity.psm1      Geolocation/sensor kill, MAC randomization
  NetworkOpSec.psm1   LLMNR/mDNS/NetBIOS/SMB hardening
  EgressRecon.psm1    VPN/Mullvad state, egress firewall, recon
  BrowserOpSec.psm1   Browser anti-leak / trace cleanup
  AntiForensics.psm1  Trace wiping, panic, self-destruct
  SentryMonitor.psm1  Real-time intrusion tripwire
  ...                 (see each file header)
tests/              Pester 5 unit tests
docs/               Architecture notes
assets/audio/       Optional narration clips (graceful SAPI fallback)
backups/            Runtime state snapshots (gitignored)
```

## Coding conventions

- **PowerShell, 4-space indent, UTF-8, CRLF** line endings (enforced by
  `.gitattributes` / `.editorconfig`).
- **Use approved verbs.** Function names follow `Verb-Noun` with a verb from
  `Get-Verb` (e.g. `Get-`, `Set-`, `Test-`, `Protect-`, `Clear-`, `Remove-`,
  `Invoke-`, `Install-`, `Find-`). CI fails on `PSUseApprovedVerbs` errors.
- **Audit functions return objects, hardening functions apply + verify.**
  Read registry/service state into a `[PSCustomObject]` with `Status`/`Details`;
  do not print from deep in the logic where it can be reused. Prefer
  `Set-HardenedValue` / `Set-ServiceDisabled` from `Common.psm1` so every write
  is confirmed by readback instead of assumed.
- **Never report a PASS you did not verify.** If a value can't be read or a
  write can't be confirmed, surface it as EXPOSED/WARN with the reason.
- **Guard destructive actions.** Anything that wipes, shreds, powers off, or
  self-destructs must require explicit confirmation (see the `NUKE` prompt in
  `Invoke-SelfDestruct`).
- Export the public surface with `Export-ModuleMember`; keep internal helpers
  unexported.

## Before opening a PR

```powershell
# 1. All modules import cleanly
Get-ChildItem modules/*.psm1 | ForEach-Object { Import-Module $_.FullName -Force -DisableNameChecking }

# 2. Static analysis is clean of errors
Install-Module PSScriptAnalyzer -Scope CurrentUser   # once
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning,Error

# 3. Tests pass (needs Pester 5)
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser   # once
Invoke-Pester ./tests
```

CI runs the same three steps on `windows-latest` for every push and PR.

## Commit style

Conventional commits are used in history (`fix(sentry): ...`,
`refactor(core): ...`). Please keep that style. One logical change per commit.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
