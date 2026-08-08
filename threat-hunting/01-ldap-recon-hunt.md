# Hunt: LDAP Reconnaissance via PowerShell

**Tactic:** Discovery — T1087 (Account Discovery), T1069 (Permission Groups Discovery), T1482 (Domain Trust Discovery)

## Hypothesis

In the companion Splunk lab ([active-directory-attack-detection-lab](https://github.com/swethanyamala/active-directory-attack-detection-lab)), I documented a real detection gap: native Windows Directory Service auditing (Event 4662) does not reliably fire when LDAP enumeration is performed via `[adsisearcher]`/`DirectorySearcher`, especially when run by a privileged account locally on the DC. If an attacker used this exact technique against a Wazuh-monitored environment, the automated 4662-based approach used for DCSync in this repo would not catch it either — the same underlying blind spot applies here.

This hunt closes that gap using a different data source: **PowerShell Script Block Logging (Event 4104)**, which records the actual command text run, regardless of whether the resulting LDAP read triggers a directory-auditing event.

## Prerequisite

Enable Script Block Logging via GPO: `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging` → Enabled. Confirm the Wazuh agent's `ossec.conf` is also reading the `Microsoft-Windows-PowerShell/Operational` eventchannel, not just `Security`.

## Hunt query (Wazuh Discover)

```
data.win.system.eventID:4104 AND data.win.eventdata.scriptBlockText:(*adsisearcher* OR *DirectorySearcher* OR *DirectoryEntry* OR *servicePrincipalName*)
```

## What to look for

- **Who ran it** — is this a known admin/inventory account and host, or something unexpected?
- **What was queried** — general enumeration (`objectClass=user`) is lower concern; SPN-specific enumeration (`servicePrincipalName=*`) is a direct Kerberoasting precursor and higher concern.
- **What happened next** — check for Kerberoasting rule `110010`/`110012` or DCSync rule `110001` firing from the same account/host shortly after. A recon hit followed by one of those is a near-certain real incident, not a benign finding.

## Baseline first

Before treating any hit as suspicious, run this hunt once against a normal week of traffic to identify your legitimate noise (backup tools, inventory scripts, helpdesk tooling) so you're not chasing known-good activity every time.
