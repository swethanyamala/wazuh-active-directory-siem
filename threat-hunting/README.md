# Threat Hunting

The rules in [`../rules/local_rules.xml`](../rules/local_rules.xml) are **automated detections** — they fire on their own when a known pattern occurs. Threat hunting is different: it's a human-driven, proactive search for signs of compromise that don't have (or can't reliably have) an automated rule watching for them, based on a hypothesis about what an attacker might have done.

Each hunt below targets a different MITRE ATT&CK tactic than the automated rules already cover (Credential Access via Kerberoasting/DCSync), so this folder adds genuinely new coverage rather than repeating the same two attacks a third time.

## Hunts in this folder

| # | Hunt | Tactic | Why it's a hunt, not a rule |
|---|---|---|---|
| 1 | [LDAP Recon via PowerShell](01-ldap-recon-hunt.md) | Discovery (T1087/T1069/T1482) | Closes the exact detection gap documented in the companion Splunk repo — 4662 auditing doesn't reliably catch privileged local LDAP reads, so this hunts via PowerShell Script Block Logging instead |
| 2 | [Golden Ticket Indicators](02-golden-ticket-indicators.md) | Credential Access (T1558.001) | Requires correlating two event types over time (4768 vs 4769) — not a simple single-event match a static rule handles well |
| 3 | [Suspicious PowerShell / LOLBins](03-suspicious-powershell-lolbins.md) | Execution, Defense Evasion (T1059.001, T1027) | Keyword-based hunting is inherently fuzzy (attackers rename/obfuscate) so it's run as an analyst review, not an auto-fire alert |
| 4 | [Persistence: New Admins & Scheduled Tasks](04-persistence-hunt.md) | Persistence (T1053.005, T1098) | High legitimate-use rate (admins do this too) makes this better suited to periodic review than an always-on alert |

## How to run these

All queries are written for the Wazuh dashboard's **Discover** search bar (KQL/Lucene-style query syntax against the `wazuh-alerts-*` index pattern). Paste the query string into Discover, set your time range, and review results manually — these are investigative starting points, not pass/fail alerts.
