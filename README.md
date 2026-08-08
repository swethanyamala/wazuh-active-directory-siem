# Active Directory Attack Detection with Wazuh

Custom Wazuh detection rules for two of the most common post-compromise Active Directory attacks — **Kerberoasting** and **DCSync** deployed against a Windows Server domain controller and validated with live attack simulation.

## Why these two attacks

Both are *credential theft* techniques that abuse legitimate Active Directory/Kerberos behavior rather than exploiting a vulnerability, which is exactly why they're hard to prevent outright and have to be caught by detection engineering instead of a patch:

- **Kerberoasting (T1558.003):** any authenticated domain user can request a Kerberos service ticket for any SPN-registered account. If the ticket is encrypted with RC4, the attacker cracks the service account's password hash offline, with no further interaction with the domain needed.
- **DCSync (T1003.006):** an account holding (or that has escalated to) `Replicating Directory Changes` / `Replicating Directory Changes All` rights can impersonate a domain controller and pull every credential hash in the domain via the directory replication protocol — no code execution on a DC required, and it never touches `NTDS.dit` on disk.

## What's in this repo

| File | Purpose |
|---|---|
| [`rules/local_rules.xml`](./rules/local_rules.xml) | Wazuh custom detection rules for both attacks, plus false-positive suppression rules and a correlation rule for multi-SPN Kerberoast sweeps |
| [`docs/enable-auditing.md`](./docs/enable-auditing.md) | Windows audit policy + SACL configuration required before either rule can fire (the step most guides skip) |
| [`docs/attack-simulation-and-testing.md`](./docs/attack-simulation-and-testing.md) | How to actually trigger both attacks in a lab to validate detection, plus a false-positive check |
| [`docs/enable-fim.md`](./docs/enable-fim.md) | File Integrity Monitoring setup for AD persistence paths (SYSVOL/GPO, scheduled tasks, autostart registry keys) |
| [`rules/fim_rules.xml`](./rules/fim_rules.xml) | Custom FIM correlation rules tagging persistence-relevant path changes with MITRE IDs |
| `screenshots/` | Drop your alert screenshots here |
| [`threat-hunting/`](./threat-hunting/) | Proactive hunt queries covering Discovery, Golden Ticket indicators, PowerShell/LOLBins, and persistence — different MITRE tactics than the automated rules above, run manually rather than auto-alerted |

## Architecture

```
Domain Controller (Windows Server)
  └─ Wazuh agent → forwards Security eventchannel (4769, 4662)
       └─ Wazuh manager → local_rules.xml matches attack signatures
            └─ Alert (level 12–14) → Wazuh dashboard / indexer
```

## Deploy

1. Complete [`docs/enable-auditing.md`](./docs/enable-auditing.md) on the DC first — without the audit policy and SACL changes, the events these rules depend on are never generated.
2. Append the contents of [`rules/local_rules.xml`](./rules/local_rules.xml) to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh manager.
3. `systemctl restart wazuh-manager`
4. Validate the rule syntax loaded correctly: `/var/ossec/bin/wazuh-logtest`
5. Run the simulations in [`docs/attack-simulation-and-testing.md`](./docs/attack-simulation-and-testing.md) and confirm alerts fire.

## Detection logic summary

| Rule ID | Trigger | Level | MITRE |
|---|---|---|---|
| 110001 | Event 4662 with replication GUID (DCSync) | 12 | T1003.006 |
| 110002 | Suppress 110001 for legitimate machine accounts | 0 | — |
| 110010 | Event 4769 with RC4 ticket encryption (0x17) | 12 | T1558.003 |
| 110011 | Suppress 110010 for krbtgt/machine account targets | 0 | — |
| 110012 | Same account, 3+ distinct SPNs via RC4 within 5 min | 14 | T1558.003 |

## File Integrity Monitoring (Persistence Detection)

Beyond attack detection and hunting, this repo also configures Wazuh's FIM module to watch the specific files/registry keys an attacker touches when establishing persistence after a compromise (GPO tampering, scheduled tasks, autostart registry entries) — directly backing up the persistence hunt above with actual file-change evidence. See [`docs/enable-fim.md`](./docs/enable-fim.md) and [`rules/fim_rules.xml`](./rules/fim_rules.xml).

| Rule ID | Trigger | Level | MITRE |
|---|---|---|---|
| 110020 | Change in SYSVOL Group Policy Objects | 12 | T1484.001 |
| 110021 | Scheduled task file created/modified | 10 | T1053.005 |
| 110022 | Change in Run/RunOnce autostart registry keys | 12 | T1547.001 |

---

## Threat Hunting

Beyond the automated rules above, this repo also includes proactive hunt queries for attack techniques that are a poor fit for a static always-on rule (too event-sparse, too correlation-heavy, or too false-positive-prone without human review): [`/threat-hunting`](./threat-hunting/)

| Hunt | Tactic |
|---|---|
| [LDAP Recon via PowerShell](./threat-hunting/01-ldap-recon-hunt.md) | Discovery (T1087/T1069/T1482) — closes the exact gap documented in the Splunk repo |
| [Golden Ticket Indicators](./threat-hunting/02-golden-ticket-indicators.md) | Credential Access (T1558.001) |
| [Suspicious PowerShell / LOLBins](./threat-hunting/03-suspicious-powershell-lolbins.md) | Execution, Defense Evasion (T1059.001, T1027) |
| [Persistence: New Admins & Scheduled Tasks](./threat-hunting/04-persistence-hunt.md) | Persistence (T1053.005, T1098) |

---

## Part of a multi-platform detection story

This is the same Kerberoasting/DCSync detection logic already built in **Splunk** (SPL) — see [active-directory-attack-detection-lab](https://github.com/swethanyamala/active-directory-attack-detection-lab) — now rebuilt independently in **Wazuh**. Building the same detection twice on two different platforms is the point — it demonstrates the underlying attack logic and field-level reasoning transfers, not just familiarity with one product's query syntax.

Resume/interview framing: *"Built and validated Kerberoasting and DCSync detection rules across two independent SIEM platforms (Splunk and Wazuh), including audit policy prerequisites, false-positive tuning, and live attack simulation for validation."*

## Incident Response

For the "what to do when this fires" side — triage, containment, and recovery steps — see the playbooks already written for these same two attacks: [playbooks/02-kerberoasting-response.md](https://github.com/swethanyamala/active-directory-attack-detection-lab/blob/main/playbooks/02-kerberoasting-response.md) and [playbooks/03-dcsync-response.md](https://github.com/swethanyamala/active-directory-attack-detection-lab/blob/main/playbooks/03-dcsync-response.md). The response procedure doesn't change based on which SIEM caught the attack, so it isn't duplicated here.
