# Security Policy

WinOpSec is a **defensive** Windows operations-security toolkit. It changes
sensitive host state (registry policies, services, firewall rules, credential
protections) and includes irreversible actions (trace wiping, panic,
self-destruct). Treat bug reports here seriously.

## Scope

In scope:

- A hardening function that reports `PASS`/applied when the change was **not**
  actually made or verified.
- An audit check that reports a false `HARDENED`/`CLEAN` (false sense of safety).
- A destructive command (`wipe`, `panic`, `vanish`, `deadman`) that can fire
  without its confirmation guard, or that destroys more than documented.
- A privacy leak: machine identifiers, secrets, or user paths written into
  logs, the repository, or any outbound request.
- Command/code injection via user-supplied paths or arguments.

Out of scope:

- Features requiring Administrator that correctly report "requires admin" when
  run unprivileged.
- Detection heuristics (sentry) producing an occasional false positive, as long
  as they fail safe.

## Reporting

Please **do not** open a public issue for a vulnerability. Instead, use GitHub's
private **"Report a vulnerability"** advisory flow on this repository, or contact
the maintainer directly.

Include: affected file/function, PowerShell and Windows version, reproduction
steps, and the actual vs. expected behavior. A PoC that shows a false `PASS` or
an unguarded destructive path is ideal.

## Expectations

- Acknowledgement within a reasonable window.
- Coordinated disclosure: a fix lands before public details.
- Credit in the changelog unless you prefer to remain anonymous.

## Operational note for users

Always run `-Audit` to confirm state after hardening. Keep the JSON snapshots in
`backups/` so `restore` can roll changes back. Test `panic`/`vanish` behavior in
a VM before relying on them.
