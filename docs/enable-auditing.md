# Prerequisite: Enable Windows Auditing on the Domain Controller

The Wazuh rules in [`../rules/local_rules.xml`](../rules/local_rules.xml) match against Windows Security event IDs 4769 (Kerberos TGS request) and 4662 (Directory Service Access). Neither is logged by default — you must enable the right audit policy and, for 4662, a SACL on the domain object. If you skip this, the rules will deploy cleanly and simply never fire, with no error to tell you why.

## 1. Confirm the Wazuh agent is reading the Security eventchannel

On the DC, check `C:\Program Files (x86)\ossec-agent\ossec.conf` for:

```xml
<ossec_config>
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

If it's missing, add it and restart the agent (`Restart-Service -Name wazuh` or `WazuhSvc` depending on version).

## 2. Enable audit policy (for Event 4769 — Kerberoasting)

On the DC, via Group Policy (or `secpol.msc` for a quick lab test):

`Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Account Logon > Audit Kerberos Service Ticket Operations` → set to **Success**.

Or via command line (run as Administrator on the DC):

```powershell
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
```

Verify:

```powershell
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```

## 3. Enable audit policy + SACL (for Event 4662 — DCSync)

**3a. Audit policy:**

```powershell
auditpol /set /subcategory:"Directory Service Access" /success:enable
```

**3b. SACL on the domain object** — this is the step people miss. Audit policy alone isn't enough for 4662; you also need a System Access Control List entry on the domain partition itself, telling AD which access attempts to log.

1. Open **Active Directory Users and Computers** → View → **Advanced Features**.
2. Right-click the domain root (e.g., `wazuhtest.com`) → **Properties** → **Security** tab → **Advanced** → **Auditing** tab → **Add**.
3. Principal: **Everyone**. Type: **Success**. Applies to: **This object and all descendant objects**.
4. Permissions: at minimum check **Replicating Directory Changes** and **Replicating Directory Changes All** (these correspond to the two GUIDs the Wazuh rule matches on).
5. OK through all dialogs.

Without step 3b, DCSync attempts will not generate 4662 events at all, regardless of the audit policy setting in step 3a.

## 4. Verify events are reaching Wazuh

After enabling auditing, generate a baseline event (e.g., have any domain user browse a share or authenticate to any SPN-registered service) and check on the Wazuh manager:

```bash
tail -f /var/ossec/logs/alerts/alerts.log | grep -E "4769|4662"
```

Or use the built-in rule tester against a sample log line:

```bash
/var/ossec/bin/wazuh-logtest
```

If you see decoded `win.system.eventID` fields populate, the pipeline is working and the custom rules can be layered on top.
