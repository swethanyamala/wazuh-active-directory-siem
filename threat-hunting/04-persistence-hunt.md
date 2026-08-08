# Hunt: Persistence via New Scheduled Tasks & Privileged Group Changes

**Tactic:** Persistence (T1053.005 — Scheduled Task), Persistence/Privilege Escalation (T1098 — Account Manipulation, T1078.002 — Valid Accounts: Domain Accounts)

## Hypothesis

Once an attacker has a foothold (or has completed a DCSync/Kerberoasting compromise), the next logical step is establishing persistence so they don't lose access if their initial entry point is closed. Two of the most common, low-effort persistence mechanisms in an AD environment are creating a scheduled task that re-executes a payload, and adding an account (theirs, or a newly created one) to a privileged group so normal-looking authentication continues to grant elevated access.

## Hunt query (Wazuh Discover)

```
data.win.system.eventID:(4698 OR 4732 OR 4728 OR 4756)
```

| Event ID | Meaning |
|---|---|
| 4698 | A new scheduled task was created |
| 4732 | A member was added to a local security group |
| 4728 | A member was added to a global security group (e.g., Domain Admins) |
| 4756 | A member was added to a universal group |

## What to look for

- **Who made the change** — does this account normally perform administrative group/task changes, or is this out of pattern?
- **What group/task** — additions to Domain Admins, Enterprise Admins, or any group with replication rights (the same rights that make DCSync possible, per the Splunk repo's Stage 3 writeup) deserve immediate follow-up.
- **Timing relative to other alerts** — a group membership change shortly after a Kerberoasting or DCSync alert in this repo is a strong signal the attacker is consolidating access, not just triggering a one-off alert.
- **Scheduled task content** — for 4698, review the task's action (command/executable) for anything unexpected, especially tasks pointed at PowerShell, `cmd.exe`, or unfamiliar binaries.

## Why this is a hunt, not a rule

Admins legitimately create scheduled tasks and modify group membership constantly — the legitimate-use rate is too high for this to be a reliable always-on alert without heavy environment-specific tuning (expected admins, expected maintenance windows, expected groups). It's much better suited to a periodic review (e.g., daily/weekly) where a human applies context a static rule doesn't have.
