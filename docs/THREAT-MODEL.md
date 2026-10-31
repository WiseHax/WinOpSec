# WinOpSec Threat Model

This document states, honestly, **who WinOpSec defends against, what it does, and
what it cannot do.** A security tool that overstates its protection is worse than
no tool, because it breeds false confidence. Read this before relying on anything
here operationally.

## Who this is for

- People on untrusted networks (public/café Wi-Fi, conferences, hotels).
- People who want to reduce their Windows host's telemetry, credential-theft, and
  forensic-artifact footprint.
- People who want an early-warning tripwire for local network and physical
  attacks against their machine.

WinOpSec is **defensive**. It changes the configuration of the host it runs on. It
does not attack other systems.

## Adversaries considered

| Adversary | What WinOpSec does about it | Honest limits |
|-----------|-----------------------------|---------------|
| **Same-LAN attacker** (ARP/MITM, rogue DNS, port scan, evil-twin AP) | `sentry` watches ARP baselines, DNS servers, inbound SYN probes, BSSID changes, and can auto-sever the network | Heuristic detection; a careful attacker can evade. Fails safe (alerts, does not silently trust). |
| **Infostealer / malware reading secrets** | Canary honeytokens trip on access; browser token/vault hardening; LSASS `RunAsPPL`, WDigest-off | Does not remove existing malware. PPL/credential guards need admin and a clean boot. |
| **Telemetry / tracking by the OS & apps** | Disables Windows telemetry, advertising ID, activity upload, Bing search, Recall/Copilot where policy allows | Microsoft can change/relocate these controls per build; always re-run `-Audit` to confirm. |
| **Forensic examiner with disk access** | Wipes PCA, ShellBags, SRUM, UserAssist, event logs, browser traces; chameleon decoys | **Not** a guarantee of unrecoverability. See non-goals. |
| **Physical snatch of an unlocked machine** | `deadman` USB tripwire, `panic`, `vanish` | Depends on the machine being configured and the trigger firing in time. |
| **Network traffic analysis / geolocation** | Mullvad killswitch, PQ tunnel, DAITA, MAC randomization, Wi-Fi profile scrub | Only as strong as Mullvad and WireGuard themselves; requires the Mullvad client. |

## Non-goals (what WinOpSec is NOT)

- **Not anti-virus / EDR.** It will not detect or remove a running implant.
- **Not a guarantee of forensic unrecoverability.** On SSDs, wear-levelling,
  controller remapping, and prior backups/VSS mean "wiped" data may persist.
  Overwrite passes target the logical file, not every physical NAND cell.
- **Not a defense against a kernel-level or hypervisor-level attacker** already
  present on the host. It assumes the OS kernel is trustworthy at run time.
- **Not a substitute for full-disk encryption.** Use BitLocker/FDE; WinOpSec only
  reports FDE status.
- **Not a legal shield.** Anti-forensic use may itself be evidence. Know your laws.

## Trust assumptions

- The OS and PowerShell runtime are not already compromised when WinOpSec runs.
- The operator runs it with the privilege the task needs (many guards require
  admin; unprivileged runs are clearly marked as partial).
- Mullvad, WireGuard, and the browsers' own policy engines behave as documented.

## Fail-safe posture

- Audits are **read-only**.
- Hardening writes are **verified by readback**; unverifiable changes are reported
  as failures, not successes.
- State is snapshotted to `backups/` before changes so `restore` can revert.
- Destructive actions (`wipe`, `panic`, `vanish`, `deadman`) are irreversible and
  guarded by confirmation; test them in a VM first.

## Reporting a gap

If WinOpSec reports a `PASS`/`HARDENED` that is not actually true on your system,
that is a security bug — see [SECURITY.md](../SECURITY.md).
