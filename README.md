# winopsec v3.8

Cross-platform operations security, Mullvad VPN partner integration, browser anti-leak/anti-infostealer shield, kernel memory protection, and state-level anti-forensics utility.

## Supported Operating Systems

- **Tier 1 (Flagship / Fully Weaponized):** Windows 10 & Windows 11 (21H2, 22H2, 23H2, 24H2+, Windows Server — all editions, x64 & ARM64)
  - Full support for deep low-level kernel memory guards, PCA/BAM/SRUM neutralizers, WFP Mullvad killswitch, LSASS RunAsPPL, ShellBags sanitization, and hardware GUID randomization.
- **Tier 2 (Experimental Stubs / Roadmap):** Linux & macOS
  - Basic cross-platform stubs (shell history shredder, basic network reconnaissance, journal vacuuming). Full feature parity in active development.

## Usage

### Interactive REPL
```sh
# Windows
.\run.bat
# or any OS
powershell ./WinOpSec.ps1
```

Commands inside `opsec>` prompt (accepts number or command name):
- `1` / `audit` — full posture check (telemetry, LSASS/NTLM shield, kernel memory guard, sensors, network leaks, Mullvad/VPN tunnel, browser OpSec, PCA/ShellBags traces, FDE)
- `2` / `telemetry` — disable OS telemetry, crash reporting, WDigest cleartext, anonymous SAM + enforce LSASS `RunAsPPL`, NTLMv2-only, `DisablePagingExecutive`, and destroy `hiberfil.sys`
- `3` / `anon` — VPN-compatible geolocation kill (kills `lfsvc` & cloud location provider while muting Windows 11 24H2 WLAN popups for Mullvad & Proton VPN), blocks Recall/Copilot AI, locks Webcam/Mic, and enables Wi-Fi MAC randomization
- `4` / `net` — disable LLMNR, mDNS (UDP 5353), NetBIOS, Teredo, WPAD, ICMP redirects + enforce SMB signing & outbound telemetry firewall blocks
- `5` / `harden-all` — apply all host, kernel, network, Mullvad & browser hardening modules with automatic JSON state snapshot
- `6` / `wipe` — zero-overwrite shell histories, UserAssist ROT13 execution logs, ComDlg32/RunMRU, JumpLists, NTFS `Zone.Identifier` streams, WER crash dumps, browser caches, clipboard, and DNS/NetBIOS caches
- `7` / `secrets` — scan user directories for private keys, `.env`, `.git-credentials`, `.kube`, and API tokens
- `8` / `recon` — live VPN tunnel & DNS leak verification, exposed listening ports (`0.0.0.0`/`::`), and active external TCP sockets
- `9` / `mac` — on-demand hardware MAC address spoofer for active physical network interfaces (`mac reset` to restore factory MAC)
- `hwid` — inspect persistent cryptographic machine identifiers (`MachineGuid`, SQM `MachineId`, `BuildGUID`, `ProductId`)
  - `hwid randomize` — generate cryptographically random hardware GUIDs to defeat cross-session device attribution
- `mullvad` — query Mullvad CLI state & cryptographic exit API (`am.i.mullvad.net/json`)
  - `mullvad harden` — state-level lockdown: enforce WFP killswitch (`lockdown-mode on`), Kyber-1024 Quantum-Resistant tunnel, Maybenot DAITA (Anti-AI traffic shaping), WireGuard multihop (dual-country bounce), LAN isolation & IPv6 leak lock
  - `mullvad rotate` — instantly generate & rotate WireGuard public/private keys
  - `mullvad daita [on|off]` — toggle AI traffic analysis defense padding
  - `mullvad multihop [on|off]` — toggle multi-hop relay routing
- `browser list` — auto-detect all installed browsers (Mullvad Browser, Brave, Chrome, Edge, Firefox), active profiles & accounts
- `browser clean [-total]` — zero-overwrite browsing history, download logs, visited links, top sites, favicons & session caches (use `-total` to sever Google Cloud Sync, wipe autofill & reset sync tokens)
- `browser remove <acct/#>` — selectively shred all logins, cookies, tokens, and storage for a specific account/profile
- `browser` / `browser launch` — enforce browser anti-WebRTC leak & anti-infostealer policies or launch Mullvad Browser in isolated ephemeral mode
- `forensic-check` — inspect VSS snapshots, USN deletion journal, timeline, SRUM, and slack space
- `wipe-pca` — purge Windows 11 Program Compatibility Assistant launch dictionaries (`PcaAppLaunchDic.txt`, `PcaGeneralDb*.txt`) and enforce zero-byte lockdown
- `wipe-shellbags` — purge Explorer ShellBags (`BagMRU` & `Bags` folder navigation histories)
- `wipe-srum` — neutralize SRUM ESE database (`SRUDB.dat`) and lock Diagnostic Policy Service (`DPS`)
- `scrub-wifi` — wipe NetworkList saved Wi-Fi profiles and historical gateway BSSIDs (anti-WiGLE triangulation)
- `wipe-tokens` — neutralize Telegram Desktop (`tdata`), Discord, Signal, and Slack active session auth tokens
- `wipe-screenshots` — scrub Windows Snipping Tool (`ScreenSketch`) temporary buffers & Acropalypse recovery caches
- `wipe-reglogs` — flush active registry transaction journals (`.LOG1`, `.LOG2`) to disk and sanitize orphan containers
- `chameleon` — seed synthetic civilian activity, decoy documents & benign Recent links (defeats SANS "Too Clean Machine" / Evidence of Absence)
- `chameleon -purge` — purge synthetic camouflage documents and revert to zero-state
- `deadman` — arm USB Dead Man's Switch (monitors wrist-lanyard USB drive; triggers immediate panic/poweroff on physical pull)
- `wipe-deleted` — purge VSS shadows, reset USN deletion logs, zero SRUM/Search databases & re-trim SSD (`wipe-deleted -cipher` for DoD 3-pass zeroing)
- `wipe-logs` — purge all 400+ Windows event log channels (Security, System, App, ScriptBlock, WLAN)
- `scrub <path>` — strip image EXIF metadata, remove NTFS `Zone.Identifier` origin streams, and normalize file MACB timestamps
- `panic` — apex duress protocol: terminate sensitive processes, sever Wi-Fi, enforce Mullvad killswitch, flush routes/DNS/ARP, wipe traces & lock screen (`panic -poweroff` for emergency hard shutdown)
- `restore` — rollback system configuration from latest JSON snapshot in `backups/`

### Direct CLI Flags
```sh
powershell ./WinOpSec.ps1 -Audit
powershell ./WinOpSec.ps1 -Recon
powershell ./WinOpSec.ps1 -Mullvad
powershell ./WinOpSec.ps1 -Browser
powershell ./WinOpSec.ps1 -LaunchBrowser
powershell ./WinOpSec.ps1 -HardenAll
powershell ./WinOpSec.ps1 -WipeTraces
powershell ./WinOpSec.ps1 -PcaWipe
powershell ./WinOpSec.ps1 -ShellBags
powershell ./WinOpSec.ps1 -Srum
powershell ./WinOpSec.ps1 -ScrubWifi
powershell ./WinOpSec.ps1 -Scrub ./path/to/files
powershell ./WinOpSec.ps1 -SpoofMac
powershell ./WinOpSec.ps1 -ScanSecrets
powershell ./WinOpSec.ps1 -Panic
powershell ./WinOpSec.ps1 -Restore
powershell ./WinOpSec.ps1 -Help
```
