# winopsec v5.0 (Apex Edition)

Cross-platform operations security, Mullvad VPN partner integration, browser anti-leak/anti-infostealer shield, real-time public sentry & intrusion tripwire, kernel memory protection, honeytoken canary traps, and state-level anti-forensics utility.

## Supported Operating Systems

- **Tier 1 (Flagship / Fully Weaponized):** Windows 10 & Windows 11 (21H2, 22H2, 23H2, 24H2+, Windows Server — all editions, x64 & ARM64)
  - Full support for real-time public defensive sentry, deep low-level kernel memory guards, PCA/BAM/SRUM neutralizers, WFP Mullvad killswitch, LSASS RunAsPPL, ShellBags sanitization, and hardware GUID randomization.
- **Tier 2 (Experimental Stubs / Roadmap):** Linux & macOS
  - Basic cross-platform stubs (shell history shredder, basic network reconnaissance, journal vacuuming). Full feature parity in active development.

## Usage

### Interactive REPL
```sh
# Windows (Auto-elevates to Administrator via UAC)
.\run.bat

# or via PowerShell
powershell -NoProfile -ExecutionPolicy Bypass ./WinOpSec.ps1
```

Commands inside `winopsec` console (organized into 5 Operational Pillars):

### Guided 1-Click Scenarios
- `quick` / `wizard` / `mode` — launches the interactive guided scenario wizard:
  - `[1] Cafe / Public Wi-Fi Mode` — MAC spoof + Mullvad lock + Sentry with Auto-Panic
  - `[2] Complete Host Lockdown` — Kernel PPL + LSASS guard + disable telemetry & leaks
  - `[3] Secure Ephemeral Browsing` — Anti-WebRTC leak + ephemeral private browser session
  - `[4] Post-Session Trace Scrub & Camouflage` — Neutralize PCA/ShellBags + seed civilian noise
  - `[5] Full Security Posture Audit` — Comprehensive 53-point benchmark scan
- `hud` / `dash` — displays the real-time Tactical Cyber HUD: 8-vector sentry perimeter, live Mullvad tunnel encryption (Kyber-1024), killswitch status, DAITA, RAM metrics, canary tripwire state & overall posture score
- `intro` / `tour` — launches animated Apple-style onboarding boot sequence with human neural voice narration (`en-US-ChristopherNeural`), teaching the 6 cardinal OpSec rules and calling out script-kiddie blunders
- `test-voice` — instantaneous hardware audio diagnostic to verify speaker output and audio pipeline
- `guide <command>` — displays in-depth plain-language explanation of any feature (e.g. `guide sentry`, `guide chameleon`, `guide pca`, `guide canary`)

### Direct Pillar Commands
- `1` / `audit` — full posture check (telemetry, LSASS/NTLM shield, kernel memory guard, sensors, network leaks, Mullvad/VPN tunnel, browser OpSec, PCA/ShellBags traces, canary honeytoken traps, FDE)
- `2` / `telemetry` — disable OS telemetry, crash reporting, WDigest cleartext, anonymous SAM + enforce LSASS `RunAsPPL`, NTLMv2-only, `DisablePagingExecutive`, and destroy `hiberfil.sys`
- `3` / `anon` — VPN-compatible geolocation kill (kills `lfsvc` & cloud location provider while muting Windows 11 24H2 WLAN popups for Mullvad & Proton VPN), blocks Recall/Copilot AI, locks Webcam/Mic, and enables Wi-Fi MAC randomization
- `4` / `net` — disable LLMNR, mDNS (UDP 5353), NetBIOS, Teredo, WPAD, ICMP redirects + enforce SMB signing & outbound telemetry firewall blocks
- `5` / `harden-all` — apply all host, kernel, network, Mullvad & browser hardening modules with automatic JSON state snapshot
- `6` / `wipe` — zero-overwrite shell histories, UserAssist ROT13 execution logs, ComDlg32/RunMRU, JumpLists, NTFS `Zone.Identifier` streams, WER crash dumps, browser caches, clipboard, DNS/NetBIOS caches, and volatile RAM
- `wipe-ram` — flush process working sets via Win32 `psapi.dll!EmptyWorkingSet` and purge volatile DRAM pages against physical cold-boot extraction
- `7` / `secrets` — scan user directories for private keys, `.env`, `.git-credentials`, `.kube`, and API tokens
- `canary` — audit honeytoken decoy traps (`canary drop` to plant realistic bait files across Desktop, Documents, Downloads; `canary purge` to cleanly remove)
- `8` / `recon` — live VPN tunnel & DNS leak verification, exposed listening ports (`0.0.0.0`/`::`), and active external TCP sockets
- `9` / `mac` — on-demand hardware MAC address spoofer for active physical network interfaces (`mac reset` to restore factory MAC)
- `sentry` — real-time public sentry & 8-vector intrusion tripwire: continuous perimeter monitoring against ARP poisoning/MITM, SYN port scans, rogue DNS injection, microphone/webcam surveillance, unauthorized USB/BadUSB insertions, and honeytoken canary breaches
  - `sentry -autopanic` — arm sentry with automated countermeasure: automatically severs all network adapters and locks workstation upon detecting critical intrusion or physical USB tampering
  - `sentry status` — query instantaneous perimeter posture and baseline integrity
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
- `jitter <path>` — apply natural Gaussian timestamp jitter (business hours, uniform distribution) to defeat anti-timestomp heuristics
- `usb list` — inspect connected removable drives, storage sizes, and BitLocker encryption status
- `usb deploy [drive]` — clone standalone portable WinOpSec to USB with root `autorun.inf` malware immunization
- `usb shield on|off` — toggle Windows hardware USB storage write-protection (read-only port lock)
- `panic` — apex duress protocol: terminate sensitive processes, sever Wi-Fi, enforce Mullvad killswitch, flush routes/DNS/ARP, wipe traces & lock screen (`panic -poweroff` for emergency hard shutdown)
- `vanish` / `burn` — ghost self-destruct: DoD multi-pass cryptographic shredding of all WinOpSec modules, backups, and audio assets, detached folder eradication, SSD TRIM & hard poweroff
- `restore` — rollback system configuration from latest JSON snapshot in `backups/`

### Direct CLI Flags
```sh
powershell ./WinOpSec.ps1 -Hud
powershell ./WinOpSec.ps1 -Audit
powershell ./WinOpSec.ps1 -Sentry
powershell ./WinOpSec.ps1 -Sentry -AutoPanic
powershell ./WinOpSec.ps1 -Recon
powershell ./WinOpSec.ps1 -Mullvad
powershell ./WinOpSec.ps1 -Browser
powershell ./WinOpSec.ps1 -LaunchBrowser
powershell ./WinOpSec.ps1 -HardenAll
powershell ./WinOpSec.ps1 -WipeTraces
powershell ./WinOpSec.ps1 -WipeRam
powershell ./WinOpSec.ps1 -PcaWipe
powershell ./WinOpSec.ps1 -ShellBags
powershell ./WinOpSec.ps1 -Srum
powershell ./WinOpSec.ps1 -ScrubWifi
powershell ./WinOpSec.ps1 -Scrub ./path/to/files
powershell ./WinOpSec.ps1 -Jitter ./path/to/files
powershell ./WinOpSec.ps1 -SpoofMac
powershell ./WinOpSec.ps1 -ScanSecrets
powershell ./WinOpSec.ps1 -Panic
powershell ./WinOpSec.ps1 -Vanish
powershell ./WinOpSec.ps1 -Restore
powershell ./WinOpSec.ps1 -Intro
powershell ./WinOpSec.ps1 -TestVoice
powershell ./WinOpSec.ps1 -Help
```

## Forensic Integrity & Audio Architecture

All bundled neural audio clips in `assets/audio/` are forensically sanitized:
- **Zero Metadata:** Stripped of ID3v1, ID3v2, software encoder stamps, and author identifiers.
- **Normalized Timestamps:** Static timestamps (`2025-01-01 08:00:00 UTC`) across all files.
- **ADS Stripped:** Zero NTFS `Zone.Identifier` alternate data streams.
- **Graceful Fallback:** If audio assets are omitted or removed, WinOpSec dynamically falls back to the native Windows SAPI voice synthesizer without throwing errors.
