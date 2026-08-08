# File Integrity Monitoring (FIM) for AD Persistence Detection

Wazuh's built-in FIM module (`syscheck`) can watch specific files, directories, and registry keys for changes and alert on them. This repo uses it to catch a category of activity the Kerberoasting/DCSync rules and the threat-hunting queries don't cover directly: an attacker (or a newly-compromised account) **establishing persistence** by tampering with Group Policy, dropping a scheduled task, or planting an autostart registry entry.

This directly backs up [`threat-hunting/04-persistence-hunt.md`](../threat-hunting/04-persistence-hunt.md) — that hunt looks for the *event log evidence* of persistence (4698, 4728, 4732, 4756); FIM independently confirms the *actual file/registry change* itself, which is harder for an attacker to fully hide.

## What this monitors and why

| Path | Why it matters |
|---|---|
| `C:\Windows\SYSVOL\<domain>\Policies` | Group Policy Objects live here. Tampering with a GPO (T1484.001) is a powerful, domain-wide persistence and privilege-escalation technique — a malicious GPO can push a scheduled task or script to every machine in an OU. |
| `C:\Windows\System32\Tasks` | Scheduled task definitions are stored as files here. FIM catches the file drop directly, independent of whether Event 4698 was logged/forwarded correctly. |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `...\RunOnce` | Classic autostart persistence locations (T1547.001) — a value added here runs automatically at every logon. |

## Agent configuration

Add to the `<syscheck>` block in `ossec.conf` on the domain controller's Wazuh agent:

```xml
<syscheck>
  <directories check_all="yes" realtime="yes" report_changes="yes">C:\Windows\SYSVOL\domain\Policies</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">C:\Windows\System32\Tasks</directories>

  <windows_registry arch="both">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</windows_registry>
  <windows_registry arch="both">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
</syscheck>
```

Restart the agent after editing (`Restart-Service -Name wazuh` / `WazuhSvc`).

> `realtime="yes"` gives near-instant alerts on Windows rather than waiting for the default scheduled scan interval — worth the small extra overhead for these specific high-value paths. `report_changes="yes"` has Wazuh store a diff of what actually changed, which is what makes the alert useful for triage instead of just "something changed here."

## Custom rules

See [`../rules/fim_rules.xml`](../rules/fim_rules.xml) — tags changes to these specific paths with a higher severity and the relevant MITRE technique, instead of leaving them at Wazuh's generic default FIM alert level. Append its contents to `local_rules.xml` the same way as the Kerberoasting/DCSync rules.

## Validating

1. Make a small test change — e.g., link a test GPO to an OU, or add a harmless test scheduled task (`schtasks /create /tn TestTask /tr notepad.exe /sc once /st 00:00`).
2. Confirm the corresponding FIM alert appears in the Wazuh dashboard within moments (with `realtime="yes"`) or after the next scan cycle.
3. Confirm the custom rule (not just Wazuh's generic FIM rule) fired — check the rule ID and MITRE tag in the alert.
4. Clean up your test artifacts (remove the test task/GPO link) once confirmed.

## Known limitation

FIM on `SYSVOL` in particular can be noisy in an environment with active, legitimate GPO management — expect to tune the rule (e.g., exclude specific known-good GPO GUIDs, or specific admin accounts) after observing real baseline traffic, the same way the Kerberoasting/DCSync rules were tuned against false positives.
