# WINOPSEC v5.0 APEX ARCHITECTURE BLUEPRINT
### Full-Spectrum Defensive OpSec, Tripwire Sentry & Anti-Forensic Execution Topology

---

## 1. High-Level System Architecture Diagram

```mermaid
flowchart TD
    subgraph OPERATOR["OPERATOR INTERACTION LAYER"]
        CLI["CLI Direct Flags (-Hud, -Sentry, -Panic, -Vanish)"]
        BAT["run.bat (Elevation Bootstrap & ExecutionPolicy Bypass)"]
        REPL["Interactive PowerShell REPL Console"]
        HUD["Tactical Cyber HUD (Real-Time Metrics & Action Menu)"]
        VOICE["Audio Synthesis Engine (edge-tts / SAPI Narrator)"]
    end

    subgraph ORCHESTRATION["CORE ORCHESTRATION ENGINE (WinOpSec.ps1)"]
        DISPATCH["Command Router & Regex Dispatcher"]
        STATE["Posture State Engine (JSON Snapshots & Rollback)"]
        DRVCTX["Drive Context Resolver (HOST C:\ vs USB AIR-GAPPED)"]
    end

    subgraph PILLARS["DEFENSIVE PILLARS & FUNCTIONAL MODULES"]
        subgraph P1["Layer 1: Host & Firmware"]
            TEL["Telemetry.psm1\n(DiagTrack, Egress Rules)"]
            LSASS["LSASS Guard\n(RunAsPPL, WDigest)"]
            DMA["Firmware Guard\n(UEFI WPBT, DMA Anti-PCILeech)"]
            HWID["HwIdOpSec.psm1\n(MachineGuid, SQM ID)"]
        end

        subgraph P2["Layer 2: Network & Anonymity"]
            NET["NetworkOpSec.psm1\n(LLMNR, mDNS, NetBIOS, WPAD)"]
            VPN["Mullvad Partner\n(Kyber-1024 PQC, DAITA, WFP)"]
            ANON["Anonymity.psm1\n(MAC Spoofing, Geolocation)"]
            EGRESS["EgressRecon.psm1\n(Socket Audit, Foreign IPs)"]
        end

        subgraph P3["Layer 3: Ephemeral & Browser"]
            BROWSER["BrowserOpSec.psm1\n(WebRTC Leak Shield)"]
            VAULT["Vault Protector\n(MasterKey DPAPI)"]
            SECRETS["SecretsScanner.psm1\n(Private Keys, .env, Seeds)"]
        end

        subgraph P4["Layer 4: Sentry & Perimeters"]
            SENTRY["SentryMonitor.psm1\n(ARP MITM, Port Scans, Mic/Cam)"]
            CANARY["CanaryTrap.psm1\n(Honeytokens, Manifest Baseline)"]
            BUSKILL["DeadManSwitch.psm1\n(USB Hardware Lanyard)"]
        end

        subgraph P5["Layer 5: Anti-Forensics & Stealth"]
            WIPE["AntiForensics.psm1\n(USN, RAM Trim, Prefetch, PCA)"]
            CHAM["Chameleon.psm1\n(Civilian Noise Decoys)"]
            JITTER["Timestamp Jitter\n(Gaussian Anti-Timestomp)"]
        end

        subgraph P6["Layer 6: USB Hardware & Ghost"]
            USB["UsbOpSec.psm1\n(Deployment, Autorun Lock)"]
            PORTLOCK["Port Protection\n(StorageDevicePolicies Read-Only)"]
            PANIC["Emergency Panic\n(Route Sever, Trace Wipe, Lock)"]
            VANISH["Ghost Vanish\n(DoD Shred, USN Wipe, SSD TRIM, Poweroff)"]
        end
    end

    BAT --> CLI
    CLI --> ORCHESTRATION
    REPL --> DISPATCH
    HUD --> DISPATCH
    DISPATCH --> PILLARS
    DRVCTX --> HUD
    DISPATCH --> VOICE
    STATE --> P1
    STATE --> P2
    STATE --> P3
```

---

## 2. Operational Dataflow & Signal Routing

```mermaid
sequenceDiagram
    autonumber
    actor User as Operator / Admin
    participant Console as WinOpSec REPL / HUD
    participant Sentry as Sentry Perimeter Watcher
    participant Kernel as Windows Kernel / Registry
    participant Mullvad as Mullvad WireGuard Tunnel
    participant Forensic as Anti-Forensic Engine

    User->>Console: Launch 'cafe' or 'sentry -autopanic'
    Console->>Kernel: Enforce MAC Randomization & Disable LLMNR/mDNS
    Console->>Mullvad: Lock Kyber-1024 PQC + Strict WFP Killswitch
    Console->>Sentry: Arm 8-Vector Tripwire (ARP, SYN, BadUSB, Canary)

    loop Background Sentry Perimeter
        Sentry->>Kernel: Check ARP Table & Listener Ports (445/135)
        Sentry->>Kernel: Monitor USB Insertion IDs (Hardware Tripwire)
        Sentry->>Kernel: Query Sensor Privacy Consent (Mic/Camera)
    end

    alt Malicious ARP Poisoning / Rogue Probe Detected
        Sentry-->>Console: SENTRY ALARM: Gateway Poisoned!
        Sentry->>Mullvad: Enforce Total Network Blackout (Block-All)
        Sentry->>Kernel: Purge ARP Cache & Sever Wi-Fi Connection
        Sentry->>Kernel: Lock Workstation (user32.dll LockWorkStation)
    end

    User->>Console: Execute 'vanish' / Emergency Burn
    Console->>User: Require Explicit Safety Passcode: 'NUKE'
    User->>Console: Operator types 'NUKE'
    Console->>Forensic: Cryptographically zero all WinOpSec modules & backups
    Console->>Kernel: Detach cleanup batch script to %TEMP%
    Console->>Kernel: Purge USN Deletion Journal & Send SSD TRIM
    Console->>Kernel: Emergency Hard Power-Off (shutdown.exe /s /f /t 0)
```

---

## 3. Defense-in-Depth Layer Breakdown

### Layer 1: Host Integrity & Kernel Shields
* **LSASS Process Light (RunAsPPL)**: Enforces `AuditLevel = 1` and `RunAsPPL = 1` under `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`. Blocks Mimikatz and LSASS memory carving even from elevated debuggers.
* **Kernel Paging Protection**: `DisablePagingExecutive = 1` prevents core kernel drivers and sensitive crypto keys from being written to the pagefile on disk.
* **Firmware Defense**: Disables Windows Platform Binary Table (`UEFI WPBT`) execution to neutralize persistent OEM firmware rootkits, and locks `External DMA Guard` against Thunderbolt/PCIe DMA attacks (e.g., PCILeech).

### Layer 2: Network & Anonymity Fabric
* **Protocol Leak Eradication**:
  * Multicast Name Resolution (LLMNR UDP 5355) &rarr; Disabled via policy.
  * Multicast DNS (mDNS UDP 5353) &rarr; Disabled across all network adapters.
  * NetBIOS over TCP/IP (NBT-NS) &rarr; Set to `NetbiosOptions = 2` across all interfaces.
  * WPAD (Web Proxy Auto-Discovery) &rarr; Overridden to static null proxy.
* **Mullvad Partner Ecosystem**: WireGuard configuration enforced with Kyber-1024 post-quantum key exchange, DAITA (Defense Against AI-guided Traffic Analysis) packet padding, and WFP strict outbound killswitch.

### Layer 3: Perimeter Tripwires & Active Deception
* **8-Vector Sentry Monitor**:
  1. *Gateway ARP Integrity*: Watches for duplicate MACs and gateway IP address transitions.
  2. *SYN Port Scan Guard*: Flags unsolicited connection attempts to ports 135 and 445.
  3. *BadUSB Tripwire*: Monitors device registration IDs for stealth HID keyboard emulation attacks.
  4. *Rogue DNS Watcher*: Alerts on unauthorized DHCP-driven DNS resolver drift.
  5. *Mic & Cam Trap*: Detects unauthorized background activation of audio/video capture devices.
  6. *Evil Twin AP Guard*: Detects Wi-Fi BSSID switching or rogue access point cloning.
  7. *Reverse Shell Trap*: Continuously inspects outbound connections originating from command shells (`cmd.exe`, `powershell.exe`).
  8. *Honeytoken Canary*: Drops realistic honeytokens (`passwords_2026.xlsx`, `crypto_wallet_seed.txt`) and tracks `LastAccessTime` divergence against a cryptographic baseline manifest.

### Layer 4: Anti-Forensics & Deception Camouflage
* **Windows 11 Hidden Execution Databases**:
  * Program Compatibility Assistant (PCA): Flushes `PcaAppLaunchDic.txt` and locks the file to 0 bytes (`attrib +r +s +h`).
  * Explorer ShellBags: Purges `BagMRU` and `Bags` keys across `HKCU` and `UsrClass.dat`.
  * Prefetch & BAM: Clears `*.pf` execution traces and resets Background Activity Moderator histories.
* **Civilian Noise Camouflage (`Chameleon`)**: Generates benign academic research papers, recipes, and travel documents with natural timestamps, defeating SANS "Too Clean Machine" anomaly heuristics during forensic inspection.

### Layer 5: USB-Driven Architecture & Ghost Protocol
* **Portable USB Deployment**: Clones the complete portable suite to a removable drive, configures a root launcher, and locks a dummy `autorun.inf` directory (`+s +h +r`) to immunize the drive against USB worms.
* **Hardware Port Protection**: Flips `StorageDevicePolicies\WriteProtect` to enforce read-only status on all connected USB ports, preventing data exfiltration or malware staging.
* **Ghost Self-Destruct (`vanish`)**: Multi-pass random overwrite of all files, detached folder obliteration, NTFS USN Journal wiping (`fsutil usn deletejournal /D`), and storage SSD TRIM optimization prior to immediate shutdown.
