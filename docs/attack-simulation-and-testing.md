# Attack Simulation & Testing

How to trigger the detections in `../rules/local_rules.xml` for real, so your screenshots show actual alerts rather than just config screens.

Run these from a compromised/attacker Windows host that's domain-joined (not the DC itself), using a domain user account — Kerberoasting in particular doesn't require any elevated privilege, just a valid domain logon.

## Setup needed

- A service account in AD with a registered SPN (the Kerberoasting target). Create one if you don't have one:
  ```powershell
  setspn -A http/testsvc.wazuhtest.com svc-test
  ```
- [Mimikatz](https://github.com/ParrotSec/mimikatz) on the attacker host, for the DCSync simulation.
- A domain account with **Replicating Directory Changes** and **Replicating Directory Changes All** rights, for the DCSync simulation (in a real attack this would be a privilege-escalated account; in a lab you can grant it directly to your test account to demonstrate the detection).

## Simulate Kerberoasting

From the attacker host, PowerShell (no admin rights needed):

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "http/testsvc.wazuhtest.com"
```

This requests a TGS for the SPN-registered account. Repeat against 2–3 different SPNs within a few minutes to also trigger the higher-confidence correlation rule (110012) if you've registered multiple SPNs.

Expected result: rule `110010` (and `110012` if multiple SPNs) fires in the Wazuh dashboard within moments, showing `TicketEncryptionType: 0x17`.

## Simulate DCSync

From the attacker host, run Mimikatz as the privileged test account:

```
mimikatz # lsadump::dcsync /domain:wazuhtest.com /user:krbtgt
```

Expected result: rule `110001` fires, showing the replication GUID matched in `win.eventdata.properties`, with `SubjectUserName` set to your test account (not a machine account, so it isn't suppressed by rule `110002`).

## Confirming in the Wazuh dashboard

1. **Security events > Threat hunting** (or **Modules > Security Events** depending on your Wazuh version) → filter by `rule.id: 110001` or `110010` or `110012`.
2. Confirm the alert level (12 or 14), MITRE ATT&CK tag (T1003.006 / T1558.003), and the raw decoded fields.
3. Screenshot: the alert list, one expanded alert showing full decoded event data, and the MITRE ATT&CK tab if your dashboard version surfaces it.

## False-positive check (do this — it's a good writeup point)

Before calling the rule "done," generate legitimate traffic and confirm it does NOT fire:

- Normal domain user logons and file share access → should not trigger either rule.
- Real DC-to-DC replication traffic → should be suppressed by rule `110002` (machine account exclusion).
- If you have Entra Connect / any directory sync service running, confirm its normal replication activity doesn't false-positive; add its account to the exclusion list in `local_rules.xml` if it does.

Documenting one true positive AND one confirmed-true-negative (legitimate traffic that correctly did not alert) is more convincing in a portfolio than the alert screenshot alone — it shows you tuned the rule instead of just copying one from a blog.

## Sources used to build these rules

- [Wazuh: How to detect Active Directory attacks with Wazuh, Part 1](https://wazuh.com/blog/how-to-detect-active-directory-attacks-with-wazuh-part-1-of-2/) — base rule structure and simulation steps this lab adapts from.
